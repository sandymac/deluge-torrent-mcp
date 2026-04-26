# MCP Tool Interface Guidelines

These guidelines govern how tool definitions are written in `mod.rs`. Every doc comment and
field description is serialized into JSON Schema and injected into the LLM's context on every
request — token cost is real and cumulative.

## Tool Macro Attributes

Every `#[tool]` must have:
- `title` — human-readable display name in Title Case (e.g. `"Add Torrent"`)
- `annotations(...)` — behavioral hints for MCP clients

### Annotation defaults and when to override

| Hint | Default | Override when |
|---|---|---|
| `read_only_hint` | `false` | Tool only reads state, never writes |
| `destructive_hint` | `true` | Tool modifies but does not destroy (set `false`) |
| `idempotent_hint` | `false` | Repeated calls with same args have no extra effect (set `true`) |
| `open_world_hint` | `true` | Tool only talks to the local Deluge daemon (set `false`) |

**Do not** repeat idempotency or safety information in the tool description if it is already
expressed by an annotation. For example, don't write "Safe to call on an already-paused
torrent (idempotent)" when `idempotent_hint = true` is set.

## Tool Descriptions (doc comments on `async fn`)

- One to two sentences. State what the tool does and any non-obvious behavior.
- Mention async behavior with `ASYNC:` prefix when the operation completes in the background.
- Mention prerequisites with `PREREQUISITE:` when another tool must be called first.
- Do **not** include:
  - "Returns nothing on success" — implied
  - Unit conversion hints (e.g. "divide by 1073741824 for GiB") — LLMs know this
  - "Use -1 for unlimited" — belongs in the param struct description, not the tool description
  - Restatements of what annotations already express (idempotency, destructiveness)
  - Suggestions like "use before X to verify Y" — implied by the tool name

## Parameter Structs

- Put shared context at the **struct level** via a `///` doc comment on the struct itself.
  schemars maps this to the object's `description` in JSON Schema.
  Example: speed units, mutual-exclusion rules, defaults that apply to all fields.
- Field descriptions should be **one line**. They explain what the field does, not how to use
  the whole tool.
- Do **not** repeat struct-level context in each field.
- Use **enums** for string parameters with a fixed set of valid values (e.g. `TorrentState`).
  This generates a JSON Schema `enum` constraint, removing the need to list values in prose
  and giving the LLM a machine-readable constraint.

## Wire Shape Robustness

An upstream tool-call serializer between the LLM and the MCP server has been observed
silently coercing scalar string values that pattern-match as hex/numeric into integers —
e.g. `info_hash: "d31ebfafb0efc9a47dfb8bbd1560c90cfdc10fdb"` arrived at the server as the
integer `310947815609010` (decimal digits stripped, alpha chars dropped). The integer is
on the wire before the server sees it, so no schema-side change (regex pattern, inline
type, `$ref` removal) can recover the original string. The historical `deluge_rename_folder`
hit this exact bug.

**Rule:** for any string parameter whose value can pattern-match as a number — torrent
info_hashes, file hashes, content hashes, all-digit IDs — use a length-1 `Vec` instead of
a scalar `String`:

```rust
#[derive(Deserialize, schemars::JsonSchema)]
struct MyToolParams {
    /// Exactly one info_hash to operate on.
    #[schemars(length(min = 1, max = 1))]
    info_hashes: Vec<InfoHash>,
    // ...
}
```

In the tool body, validate the length and unwrap:

```rust
Self::validate_info_hashes(&p.info_hashes)?;
if p.info_hashes.len() != 1 {
    return Err("my_tool operates on a single torrent. Provide exactly one info_hash.".to_string());
}
let hash = p.info_hashes.into_iter().next().unwrap();
```

The JSON array context locks the element type as string and survives the round trip. Scalar
strings whose values are obviously non-numeric (paths, names, free-form text) are unaffected
and stay as `String`.

For tools that genuinely operate on a batch (e.g. `deluge_pause_torrent`), use `Vec<InfoHash>`
without the length constraint — same shape, same robustness.

## What Goes Where

| Information | Where to put it |
|---|---|
| What the tool does | Tool `///` doc comment |
| Shared parameter context (units, rules) | Struct `///` doc comment |
| Per-field semantics | Field `///` doc comment (one line) |
| Valid string values | Rust enum (not field description prose) |
| Behavioral hints | `annotations(...)` on `#[tool]` |
| Display name | `title = "..."` on `#[tool]` |

## Disabled-by-Default Tools

Tools that modify the filesystem or delete data are disabled by default via `tool_gate()`.
Disabled tools are **hidden from `tools/list`** — they consume no LLM context tokens when
not in use. The `tool_gate()` call is defense-in-depth only.

When writing descriptions for gateable tools, do not mention `--enable-tool` flags — the LLM
will never see the tool unless it is already enabled.
