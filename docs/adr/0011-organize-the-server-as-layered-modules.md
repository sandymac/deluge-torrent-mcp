# 11. Organize the server as layered modules

Date: 2026-05-31

## Status

Accepted

## Context

As the tool count grew, structure eroded. Tool bodies built raw RPC
method/argument pairs inline, scattering Deluge's wire shapes across the tool,
resource, probe, and connection-test paths. Tool-gating state was spread across
several hand-maintained parallel lists with no link to the macros that actually
register the tools, so the lists could drift silently. The tool module had grown
into a single multi-thousand-line file.

## Decision

Separate the server into layers with clear ownership:

- A typed **domain layer** wrapping the RPC client, exposing one method per
  Deluge call so every wire shape lives in one auditable place and the tool layer
  passes only primitives.
- A single **tool-visibility component** that owns all gating state and answers
  visibility questions, instead of threading many handles through free functions.
- A single **tool registry** as the source of truth for tool metadata (default
  state, plugin gating), checked against the registered tools so a mismatch fails
  the build rather than silently breaking gating.
- Cohesive submodules (parameters, handlers, validation, errors, value shaping,
  event handling) in place of one god-module.

## Consequences

- Wire shapes and gating rules are centralized and hard to desynchronize;
  forgetting to register a tool in either place is a compile error.
- Modules stay small and single-purpose, easing review and change.
- There are more files and a layer of indirection between a tool and the raw RPC
  call, which is the deliberate trade for the above.
