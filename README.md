# mde

`mde` is the Layer 5 protocol and local tool broker for the Siliconcordat stack. It lets any coding agent read, trace, edit, verify, and commit code through exact syntax spans instead of fragile text diffs.

Any tool or model that speaks JSON-RPC over stdio (Model Context Protocol, or MCP) can connect to `mde`. Humans stay in control of approvals, tests, and Git history.

## What `mde` solves

Standard MCP servers dump large tool lists and prose rules into prompts on every turn. They do not block an agent from editing an unread file, changing a test file to make a check pass, or breaking syntax inside macros.

`mde` fixes those failure modes in software instead of prompt rules:

- **Read before write:** Every edit requires a short-lived `read_token` minted when the file was read at its exact current SHA-256 digest.
- **Byte-exact syntax edits:** Tree-sitter parses Rust, Python, C, and TypeScript into concrete syntax trees (CSTs). Edits splice raw byte ranges so untouched comments, blank lines, and directives stay byte-identical.
- **Hard refusals on unsafe syntax:** Edits inside Tree-sitter `ERROR` or `MISSING` nodes, or inside C preprocessor and Rust macro regions, are rejected before writing a byte.
- **Protected test locks:** Paths marked as tests or anchors cannot be edited during normal code changes.
- **Zone classification:** Each located span carries a syntactic zone tag (`prose`, `code`, `formal_proof`, `ui_module`, or `condensed_json`) compiled from `schemas/zone-manifest.v0.1.json` so the Layer 4 harness (`exo`) and Layer 2 model runtime (`weft`) can pick the right checks and adapter scales.
- **Native prose and safety guard:** `mde guard` checks markdown and text for em dashes, clause semicolons, duplicate references, long paragraphs, AI-tell phrases, outcome forecasts, leaked secrets, local home paths, and call-policy violations with zero Python dependencies.
- **Verifier code audit:** `mde guard --code-audit` flags bare Python `assert` statements (stripped under `python3 -O`), bare `except:` or silent swallow clauses, and duplicate JSON object keys.
- **Plane 1 integrity and vendoring seams:** `mde integrity` writes and verifies path-confined `SHA256SUMS` and `MANIFEST.sha256` manifests. `mde seam-verify` validates `vendor/splices/<name>/splice.json` manifests for donor SHA pinning, slice hashes, One-Way Visibility, Zero Lockfile Mutation, and Clean Ejection.
- **Plain Git output:** Verified changes project to normal minimal Git commits. Any engineer can edit files with a plain text editor and commit with standard `git`.

## Stack position

`mde` sits at Layer 5 of the Siliconcordat stack (formerly named `mep` for Plane 1 text integrity and expanded to cover structural editing and vendor-namespaced weight-slot metadata):

| Layer | Repo | Role |
| --- | --- | --- |
| L5 | `siliconcordat/mde` | Improved MCP broker, CST splicer, Plane 1 lineage, W-MCP `_meta` contract |
| L4 | `siliconcordat/exo` | Agent harness, exact-byte human approval gate, memory, zone router |
| L3 | `siliconcordat/warp` | OS runtime, sandboxes, load-time model gate (`warp-modeld`) |
| L2 | `siliconcordat/weft` | Deterministic weight compiler, certificates, multi-adapter artifacts |
| L1 | `siliconcordat/loom` | Hardware research and architecture theory |

## Repository layout

- `PROTOCOL.md`: Complete L5 wire protocol, 5-verb contract, JSON schemas, call guard rules, Plane 1 lineage, and vendor-namespaced weight-slot `_meta`.
- `PLAN.md`: Implementation milestones, conformance gates, and explicit deferrals.
- `schemas/zone-manifest.v0.1.json`: Canonical SHA-256 Vertical Zone Manifest mapping languages and CST nodes to zones, protection flags, and default Layer 2 scale hints.
- `docs/BENCHMARKS.md`: Reproducible latency measurements and real-corpus conformance pass rates.
- `docs/contextual-compute.md`: Proposed note. A closed tool is absent from the session offer. The zone manifest is unchanged.
- `Cargo.toml`, `src/`, `tests/`, `examples/`: Rust `mde` CLI binary, stdio JSON-RPC MCP server, Tree-sitter CST engine, native guard, and automated conformance tests.

## Quickstart

```sh
cargo test
cargo run -- locate src/cst.rs
cargo run -- guard README.md PROTOCOL.md PLAN.md
cargo run -- guard --code-audit schemas/
cargo run -- zone-manifest --verify schemas/zone-manifest.v0.1.json
cargo run -- integrity --verify
cargo run -- seam-verify
cargo run -- mcp
```

## License

Code is licensed under the Apache License, Version 2.0 (`LICENSE`). Documentation is licensed under CC BY 4.0.
