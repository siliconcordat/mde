# MDE Protocol Specification (L5 Improved MCP, v0.1)

This specification defines the Layer 5 interface shared by coding agents, harnesses, and operating system tools in the Siliconcordat stack. Every operation runs over standard MCP JSON-RPC 2.0 (`stdio` or local CLI) with zero changes to core MCP framing.

## 1. Design boundaries

Four rules govern the protocol:

1. **Human authority stays external.** Protocol calls and adapter metadata never grant approval, merge rights, or spend permission.
2. **Mechanical locks replace prompt reminders.** Unread writes, broken syntax edits, protected oracle edits, and leaked secrets fail closed in code.
3. **No premature standards proposal.** All MDE extensions live strictly inside vendor-namespaced `_meta` (`gg.siliconcordat/mde`) until external users exercise them.
4. **Plain text remains authoritative.** Source files stay ordinary UTF-8 files in Git. Any human can bypass `mde`, commit with plain `git`, and let `mde` re-index on the next call.

## 2. Profile A: Five-verb CST broker

Every agent (hosted or local) can speak Profile A. Both the CLI (`mde <verb>`) and stdio MCP (`tools/call`) expose the exact same JSON inputs and outputs.

| Verb | Purpose | Mechanical guard |
| --- | --- | --- |
| `splice_locate` | Parse a file with Tree-sitter CST, list symbols with raw byte spans, tag syntactic zones, and mint session `read_token` values | Read-only. Detects `ERROR`, `MISSING`, and macro-opaque byte spans. |
| `splice_trace` | Scan workspace references, map affected anchors, list unresolved dynamic call sites, classify risk triggers, and mint `read_token` values | Read-only. Unresolved dynamic calls widen test scope instead of shrinking it. |
| `splice_patch` | Apply byte-range CST edits in an isolated scratch copy and emit a content-addressed Splice Packet | Requires valid `read_token` matching live disk SHA-256. Refuses `ERROR`, macro-opaque spans, and protected oracle paths. |
| `splice_verify` | Apply a Splice Packet inside an isolated Git worktree, run Tier 0 compiler and Tier 1/2 anchors, check oracle integrity, and emit an Evidence Bundle | Fails closed if protected oracle files change. Scans logs for secrets and byte caps. |
| `splice_project` | Materialize a verified Splice Packet and Evidence Bundle into a standard minimal Git commit | Verifies exact `packet_id` and `result_tree`. High-risk changes hard-block without an exact diff SHA-256 approval token. |

### 2.1 Read-before-write lock

When `splice_locate` or `splice_trace` reads a file, the broker computes:

```text
read_token = SHA256(session_nonce || ":" || repo_rel_path || ":" || blob_sha256 || ":" || start_byte || ":" || end_byte)
```

`splice_patch` checks every requested edit against active tokens held by the broker. If the file changed on disk, the span exceeds the read range, or no token exists, the call fails with `ERR_READ_REQUIRED` and writes zero bytes.

### 2.2 Syntax and macro refusal rules

- **Broken syntax (Gate G1.3):** If the target byte span intersects or sits inside any Tree-sitter `ERROR` or `MISSING` node, `splice_patch` returns `ERR_SYNTAX_ERROR_REGION` along with the minimal damaged byte span.
- **Macro-opaque regions (Gate G1.4):** If the target span intersects a C preprocessor directive (`preproc_if`, `preproc_ifdef`, `preproc_def`, `preproc_function_def`, `preproc_elif`, `preproc_else`) or a Rust macro definition or invocation (`macro_definition`, `macro_invocation`, `attribute_item` containing proc-macro attributes when configured), `splice_patch` returns `ERR_MACRO_OPAQUE`.
- **Zero-byte identity (Gates G1.1 and G1.2):** `splice_patch` never pretty-prints an AST. It constructs output by concatenating raw slices `orig[..start] + replacement + orig[end..]`, re-parses the patched bytes to confirm zero newly introduced `ERROR` or `MISSING` nodes, and rejects edits that alter bytes outside the declared target and import spans.

### 2.3 Deterministic call-policy guard (safeagents pattern)

Before executing any tool call, the broker evaluates a deterministic policy check against `.mde/policy.json`:

1. Confine every path inside the repository root (rejects `..` traversal, absolute paths outside the root, and symlink escapes).
2. Block writes to `protected_oracle_paths` (such as `tests/`, `anchors/`, or `.mde/anchors.json`) unless an explicit separate `anchor_spec_change` capability is invoked and marked `high_risk`.
3. Classify `risk_triggers` (`auth`, `public_api`, `schema`, `infra`, `anchors`) from touched paths and exported symbols. Any trigger promotes `risk_class` to `high_risk`.
4. Enforce hard per-packet caps (`max_evals` keyed per `SplicePacket` `packet_id` in `.mde/session_tokens.json` and `.mde/packets/<packet_id>.evals.json`, failing closed with `ERR_TOKEN_STORE` on missing, corrupt, or digest-mismatched token stores once budget state exists, along with `max_wall_sec` and `max_trace_bytes`) and secret regex scanning on all captured stdout, stderr, and packet metadata (rejecting private keys, tokens, and local home-directory paths).

### 2.4 Syntactic zone classifier (L5 to L4/L2 bridge)

`splice_locate` and `splice_trace` assign a deterministic zone tag to every file and CST byte span using the precedence and rules published in `schemas/zone-manifest.v0.1.json` (`formal_proof` > `condensed_json` > `ui_module` > `code` > `prose`):

| Zone | Detection rule | Consumer role in L4 `exo` and L2 `weft` |
| --- | --- | --- |
| `prose` | Markdown, plain text, doc comments, and string documentation blocks | Runs `mde guard` prose checks and enables `corpus` writing priors |
| `code` | Standard implementation nodes in Rust, Python, C, and TypeScript | Runs compiler and unit anchors with neutral code priors |
| `formal_proof` | Lean files (`.lean`), proof blocks, theorem/lemma/tactic spans, or formal spec markers | Disables style rewrites, protects axioms/SHAs, and raises `formal-verification` adapter scale |
| `ui_module` | CSS, HTML, JSX/TSX, Svelte, SVG, and tagged UI component spans | Routes design checks, respects `data-eido-skip`, and enables `weft-eido` design priors |
| `condensed_json` | JSON, JSONL, TOML, and YAML configuration and schema files | Protects exact keys and digests with all style adapters at `0.0` |

Each located node returns `zone` and `span_bytes` inside `_meta["gg.siliconcordat/mde"]`. Higher layers never guess content zones from fragile regexes over raw prompts.

### 2.5 Native prose, code, and safety guard (`mde guard` / `mde_guard`)

`mde` embeds a zero-dependency deterministic guard callable via CLI (`mde guard`), MCP (`mde_guard`), and automatically during `splice_verify` on patched `prose` files. It checks em dashes, clause-stitching semicolons, duplicate GitHub/URL references, paragraphs over 420 characters, banned AI-tell openers, outcome forecasts, secret/local-path leaks, and call-policy rules.

With `--code-audit` (or `code_audit: true` over MCP), it also uses Tree-sitter Python CST and a strict streaming JSON parser to flag bare Python `assert` statements, bare `except:` or silent swallow blocks, and duplicate JSON object keys at any nesting depth.

## 3. Canonical JSON schemas (v0.1)

All packets and bundles serialize as canonical UTF-8 JSON with sorted keys and content-addressed SHA-256 digests (`sha256:<64-hex>`).

### 3.1 Splice Packet (`splice-packet/v0.1`)

```json
{
  "schema": "splice-packet/v0.1",
  "packet_id": "sha256:<digest of canonical body excluding packet_id>",
  "capability_id": "mde.broker.policy_guard",
  "base_commit": "<40-hex git commit or empty if unborn>",
  "base_tree": "<40-hex git tree or workspace digest>",
  "lane": "build",
  "risk_class": "routine",
  "risk_triggers": [],
  "parent_packets": [],
  "read_proofs": [
    {
      "path": "src/policy.rs",
      "blob_sha256": "sha256:...",
      "cst_root_sha256": "sha256:...",
      "read_token": "..."
    }
  ],
  "edits": [
    {
      "path": "src/policy.rs",
      "language": "rust",
      "anchor_node_kind": "function_item",
      "anchor_symbol": "validate_path",
      "zone": "code",
      "start_byte": 120,
      "end_byte": 410,
      "expected_old_sha256": "sha256:...",
      "replacement_utf8": "pub fn validate_path(...) { ... }"
    }
  ],
  "seam_contract": {
    "exported_symbols_touched": ["validate_path"],
    "calls_added": [],
    "unresolved_dynamic_sites": [],
    "declared_effects": ["pure"]
  },
  "generation_provenance": {
    "actor": "local-cli",
    "mode": "targeted",
    "model_id": "none",
    "prompt_sha256": null,
    "tool_trace_sha256": null,
    "budget_used": {"tokens": 0, "evals": 1, "wall_sec": 0}
  },
  "git_projection": {
    "commit_subject": "policy: confine relative paths",
    "summary_lines": ["Rejects parent traversal outside repository root."],
    "expected_result_tree": "<sha256 or git tree>"
  }
}
```

### 3.2 Evidence Bundle (`evidence-bundle/v0.1`)

```json
{
  "schema": "evidence-bundle/v0.1",
  "bundle_id": "sha256:<digest of canonical body excluding bundle_id>",
  "packet_id": "sha256:...",
  "base_tree": "<sha256 or git tree>",
  "result_tree": "<sha256 or git tree>",
  "toolchain_digest": {
    "os": "macos",
    "arch": "aarch64",
    "mde_version": "0.1.0"
  },
  "oracle_integrity": {
    "protected_paths_pre_sha256": "sha256:...",
    "protected_paths_post_sha256": "sha256:...",
    "tamper_free": true
  },
  "tier0_compiler": {
    "zone": "A",
    "cmd": ["cargo", "check"],
    "exit_code": 0,
    "duration_ms": 810,
    "diagnostics_sha256": "sha256:...",
    "passed": true
  },
  "anchors": [
    {
      "anchor_id": "unit_policy",
      "tier": 1,
      "visibility": "visible",
      "zone": "A",
      "cmd": ["cargo", "test", "policy"],
      "exit_code": 0,
      "passed": true,
      "duration_ms": 220,
      "stdout_sha256": "sha256:...",
      "stderr_sha256": "sha256:...",
      "cassette_sha256": null
    }
  ],
  "summary": {
    "tier0_pass": true,
    "tier1_passed": 1,
    "tier1_total": 1,
    "tier2_passed": 1,
    "tier2_total": 1,
    "lexicase_grade": "canonical",
    "widened_for_unresolved_sites": []
  },
  "secret_scan": {
    "passed": true,
    "max_trace_bytes": 1048576,
    "actual_trace_bytes": 1024
  },
  "human_approval": {
    "required": false,
    "approved_diff_sha256": null
  }
}
```

Any 1-byte change to `base_tree`, `result_tree`, or protected oracle files invalidates the bundle.

## 4. Sibling seam: cross-repo capability vendoring (`vendor/splices/`)

Intra-repo CST editing (Section 2) is separate from cross-repo capability vendoring. When a host repository imports a self-contained slice from an upstream donor repository, it follows the vendoring seam checked by `mde seam-verify` (and MCP `mde_seam_verify`):

- Store the vendored slice under `vendor/splices/<capability_name>/` with a `splice.json` manifest recording donor URI, pinned hex commit SHA, license, seam exports, optional `slice_hashes`, and optional `host_lockfile_hashes`.
- Enforce four invariants mechanically: donor commit pinning, One-Way Visibility (core code never imports `vendor/splices/`), Zero Lockfile Mutation, and Clean Ejection (deleting the slice directory breaks zero core files or build manifests).

## 5. Plane 1 integrity and causal lineage (formerly MEP, now MDE)

MDE carries forward the Plane 1 text integrity model previously named MEP (name change only, concepts unchanged), implemented natively via `mde integrity --write` / `--verify` (and MCP `mde_integrity`):

- **Authoritative text layout:** Human-authored principles, operating procedures, skills, and design docs live in plain versioned files covered by sorted, path-confined `SHA256SUMS` or `MANIFEST.sha256` manifests.
- **Path confinement:** Verification fails closed on absolute paths, `..` traversal, escaping symlinks, malformed lines, duplicates, missing files, modified files, and unlisted extra files.
- **Causal lineage and zero hidden authority:** Revisions point to parent digests. Contested heads escalate to the owner. Reading a Plane 1 document supplies pinned context only and never grants execution, merge, or spend permission.

## 6. Profile B: W-MCP weight-slot lifecycle (vendor-namespaced `_meta`)

Profile B applies only to self-hosted open-weights runtimes where the owner controls load-time checks. Closed-weight APIs ignore Profile B and use Profile A plus Plane 1 text retrieval.

All Profile B fields live under `_meta["gg.siliconcordat/mde"]`:

- `checkpoint_fingerprint`: 4-layer checkpoint identity (`layout_sha256`, tensor bytes fingerprint, config/tokenizer/template digests, Plane 1 lineage digests) plus a 5th serving-flag digest.
- `slot_manifest_digest`: Content hash of active adapter IDs, scales, and `FixedRadixCertificate` witnesses.
- `zone_hint`: Syntactic zone (`prose`, `code`, `formal_proof`, `ui_module`) emitted by `splice_locate` and `splice_trace` for L4 dynamic scale routing.
- `rollback_state`: Boolean kill-switch indicator (`active` or `bypassed_to_w0`) requiring immediate KV and hybrid recurrent-state flush on deactivation.
