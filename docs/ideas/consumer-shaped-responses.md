# Consumer-Shaped MCP Responses via a Shared Config DSL

## Problem Statement
How might we let an MCP client declare what kind of consumer it is — token-sensitive LLM
or byte/parse-sensitive programmatic tool — and receive a payload shaped for it, configured
per-endpoint on HTTP and per-flag on STDIO, without forking tool schemas or the Deluge
connection?

## Recommended Direction
Treat the URL path + query string as a single canonical config DSL parsed by ONE function,
producing an in-process `ResponseConfig`. Thread that config into the existing per-session
`DelugeServer` factory (`src/main.rs:412`). Response shaping is a pure transform on the JSON
`Value` the tools already produce, applied before serialization (`src/tools/mod.rs:324, 488,
508`) — so it needs neither a subprocess nor a second Deluge connection; the single shared
`api` handle (`src/main.rs:408`) is reused unchanged.

```
HTTP:  /mcp/json?shape=minified,sparse&ids=short      (parsed in middleware)
STDIO: --response-config 'json?shape=minified,sparse&ids=short'   (same string, same parser)
```

One grammar, one parser, one set of tests, two call sites. Adding a future format (`toon`,
`xml`) lights up on both transports at once.

Reframe: the selector is not "pick an encoding" — it is **"declare your consumer type and
get a payload shaped for you."** Because LLM-oriented shaping (sparse, short ids) is a mild
*loss* for programmatic consumers (they must merge defaults / resolve ids), all such shaping
is strictly **opt-in, never default**. The endpoint encodes consumer intent.

### Axes (query parameters)
```
format:  json            (only value in v1; the segment reserves the namespace)
shape:   pretty (default, = today's behavior) | minified ; sparse (defaults block + omit)
ids:     full (default) | short                (selects an IdStrategy — see below)
fields:  <csv projection>                       (later)
```

## ID Strategy Seam (designed-for, not built)
A torrent id's representation is a pluggable `IdStrategy` selected by the `ids=` axis. v1
ships `full` only. The trait has four responsibilities so future schemes stay additive
rather than cross-cutting across the 21 tools:

```
encode(full_hash) -> token            (output rendering)
decode(token)     -> full | NotFound | Ambiguous | Expired
                     PERMISSIVE: the full hash is ALWAYS accepted, whatever the active
                     strategy. Token shapes are distinguishable (integer vs 12-hex vs
                     40/64-hex), so one decode sniffs and accepts all forms at once.
describe()        -> schema fragment  teaches the LLM the id's rules AND that short/
                     ephemeral ids are TRANSIENT interaction tokens — persist the full
                     hash as the durable cross-system key, never a short/ephemeral id.
resolve_ids tool  -> batch bidirectional translation between any form and the full hash;
                     serves as the external-index bridge AND the Expired recovery path.
```

**Why resolve_ids is a public contract, not an internal convenience:** torrents don't live
in isolation. The full info hash is the join key the outside world uses — Deluge, MAM,
Sonarr/Radarr, a user's catalog. Any abbreviation is local to this server's bubble, so any
client bridging to an external index needs reliable two-way translation. This is true for
the stateless `Prefix` strategy too, not just `Ephemeral`.

**Output rule:** output may abbreviate, but full hashes are NOT emitted inline by default —
they are recovered on demand via `resolve_ids` for the subset a client actually
cross-references. Emitting full hashes for every row would defeat the token savings.

### Strategies (variants behind the one trait)
| Strategy | encode | decode | ~tokens (1,541-torrent case) | state |
|---|---|---|---|---|
| `Full` (today, v1) | identity | identity | ~34.8k | none |
| `Prefix(12)` | truncate to 12 hex | hashset lookup; ambiguity error | ~8k | refreshable cache |
| `Ephemeral(u16)` | incrementing seq # on first sighting | array index -> hash; `Expired` on evict | ~3-4k | per-session map + counter, TTL/LRU eviction |

`Ephemeral` is the biggest token lever (a 1-5 digit int is ~1 token vs ~7 for a 12-hex
prefix) but the only stateful/expiring one — hence the `describe()`/recovery machinery. The
cache for `Prefix`/`Ephemeral` stays fresh via the Deluge `TorrentAddedEvent`/
`TorrentRemovedEvent` push events (reusing the subscription mechanism the plugin watcher
already uses), not polling.

## Key Assumptions to Validate
- [ ] `ResponseConfig` can be threaded into the per-session factory and read by tool
      handlers (in-process; no rmcp transport surgery, no subprocess).
- [ ] One parser cleanly serves both the HTTP path+query and the STDIO `--response-config`
      string — single grammar, shared tests.
- [ ] Per-session tool *metadata* can be rendered dynamically (not just static `#[tool]`
      macro output) so `describe()` fragments reach the schema — the plugin-gating +
      `tools/list_changed` machinery is precedent; confirm the schema-build hook exists.
- [ ] 12-char fixed prefix is collision-safe at scale (issue #9: 6 chars unique at 1,541).
- [ ] Sparse stays strictly opt-in so programmatic consumers keep complete, stable payloads.

## MVP Scope
IN:  Shared config parser; `ResponseConfig` threaded into the session factory; `shape=
     minified` and `shape=sparse` on the read path (HTTP + STDIO); the `IdStrategy` trait
     with `Full` as the only impl, with the existing tools' id handling routed through it;
     docs + parser/output tests.
OUT: `ids=short` (increment 2 — touches write contract), `Ephemeral`, `resolve_ids`,
     `toon`/`xml`, `fields=` projection, per-call overrides, any subprocess/multi-instance,
     path-as-backend-selector.

## Not Doing (and Why)
- **Subprocess / process boundary per config** — can't share the Deluge connection
  (`src/main.rs:408`), adds lifecycle/IPC/crash cost, and buys no isolation that output-
  shaping needs. Config is data, not a process. (Reconsider only if a path ever selects a
  *different Deluge backend or credentials* — a deliberate, separate decision.)
- **Pre-mounted services per combo / matrix-URI `;` params** — unnecessary once config is an
  in-process object; query string avoids the semicolon/proxy/Axum-matcher hazards.
- **`ids=short` in v1** — only lever that changes the write contract (every hash-accepting
  tool must resolve prefixes); ship after read-path shaping with ambiguity tests.
- **Minimal-unique (Git-style) prefixes** — adaptive length makes a prefix go ambiguous as
  torrents are added; a fixed 12-char prefix removes recomputation and output-stability
  headaches.
- **Inline full hashes alongside short ids** — defeats the token win; recover on demand via
  `resolve_ids` instead.
- **TOON / XML / TSV / columnar / per-call format params** — deferred; no consumer parses
  them today, each is real parser + escaping + test cost, and the `json` segment reserves
  the namespace so adding them later is not a breaking URL change.

## Open Questions
- **Does `ids=short`/`Ephemeral` pay for itself?** Abbreviation's net token win depends on
  the scan-to-cross-reference ratio: wins big for scan-many/act-few libraries, erodes if a
  workload cross-references nearly everything it lists. The reusable hash-resolution layer
  may justify the seam regardless of the token math.
- **Decode placement** — explicit `cfg.ids.decode(token)?` at the top of each hash-accepting
  tool (greppable, no magic; leaning this way) vs a typed `TorrentId` newtype resolved during
  arg deserialization (prettier, but serde can't easily see per-session runtime state).
- **Ephemeral id map scope** — per-session (dies with the connection; cleanest "invalidates
  eventually", no cross-client collisions; leaning this way) vs server-global (shareable, but
  contention + confusion). Deferred, but `decode` must be able to return `Expired` and the
  error must carry actionable "re-fetch via list_torrents" guidance so adding it later is not
  a breaking change.
- **Default whitespace for plain `/mcp`** — stay `pretty` (backward-compatible) or flip to
  `minified` per issue #9 ("pretty buys a model nothing")?
