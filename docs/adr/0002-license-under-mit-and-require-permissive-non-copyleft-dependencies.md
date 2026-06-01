# 2. License under MIT and require permissive, non-copyleft dependencies

Date: 2026-03-24

## Status

Accepted

## Context

The project needs a license for its own source and a policy for the licenses of
the third-party code compiled into the distributed binary. A copyleft
dependency (GPL and similar) would impose its terms on the whole binary, which
is incompatible with shipping under a permissive license.

## Decision

License the project under the **MIT** license. Any dependency compiled into or
distributed with the binary must be under a **permissive, MIT-compatible**
license (MIT, Apache-2.0, BSD, ISC, Zlib, …). **Copyleft** licenses (GPL, LGPL,
AGPL, MPL, and similar) are not permitted, and a copyleft crate is disqualified
regardless of technical fit.

## Consequences

- Downstream users can redistribute and embed the binary under permissive terms.
- Adding a dependency requires a license check, not just a technical one.
- Third-party obligations are surfaced through a generated `THIRD_PARTY_LICENSES`
  manifest so attributions stay current as dependencies change.
