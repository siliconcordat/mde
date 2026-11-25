use mde::broker::{Broker, LocateRequest, PatchEditInput, PatchRequest, ProjectRequest, VerifyRequest};
use mde::guard::audit_json_duplicate_keys;
use mde::policy::PolicyConfig;
use mde::seam::verify_seam_manifest;
use mde::types::sha256_prefixed;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn init_git_repo(root: &Path) {
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .expect("git command failed");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["init"]);
    run(&["config", "user.email", "mde-test@example.invalid"]);
    run(&["config", "user.name", "MDE Test"]);
    run(&["add", "-A"]);
    run(&["commit", "-m", "init"]);
}

#[test]
fn bug1_seam_non_utf8_and_unreadable_file_fails_closed() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let slice_dir = root.join("vendor/splices/demo");
    fs::create_dir_all(&slice_dir).unwrap();

    // Non-UTF-8 bytes in declared seam file, with matching slice_hashes so only export check decides.
    let raw_non_utf8: &[u8] = &[0xff, 0xfe, 0x00, 0x80, b'x'];
    let seam_path = slice_dir.join("seam.rs");
    fs::write(&seam_path, raw_non_utf8).unwrap();
    let digest = sha256_prefixed(raw_non_utf8);

    let manifest = json!({
        "splice_version": "1",
        "capability": "demo_cap",
        "donor": {
            "uri": "https://example.invalid/donor",
            "commit": "0123456789abcdef0123456789abcdef01234567",
            "license": "MIT"
        },
        "seam": {
            "path": "vendor/splices/demo/seam.rs",
            "exports": ["must_exist_symbol"]
        },
        "slice_hashes": {
            "vendor/splices/demo/seam.rs": digest
        },
        "host_lockfile_hashes": {}
    });
    fs::write(
        slice_dir.join("splice.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let rep = verify_seam_manifest(root, "vendor/splices/demo/splice.json").unwrap();
    assert!(
        !rep.ok,
        "non-UTF-8 seam file must NOT pass seam export verification"
    );
    assert!(
        rep.failures.iter().any(|f| f.invariant == "seam_exports"),
        "expected seam_exports failure on unreadable/non-UTF-8 seam file, got: {:?}",
        rep.failures
    );
}

#[cfg(unix)]
#[test]
fn bug2_workspace_tree_digest_fails_closed_on_unreadable_file_or_dir() {
    // Only enforceable when not running as root (root bypasses 0o000 mode bits).
    let uid_out = Command::new("id").arg("-u").output().unwrap();
    if String::from_utf8_lossy(&uid_out.stdout).trim() == "0" {
        eprintln!("SKIPPED bug2 DAC permission subtest: uid == 0 bypasses mode bits");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("src")).unwrap();
    let src_rs = "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n";
    fs::write(root.join("src/lib.rs"), src_rs).unwrap();

    let locked_file = root.join("src/unreadable.txt");
    fs::write(&locked_file, "secret contents\n").unwrap();

    let mut broker = Broker::open(root, false).unwrap();
    let loc = broker
        .splice_locate(LocateRequest {
            path: "src/lib.rs".into(),
            capability_id: Some("cap_io".into()),
        })
        .unwrap();
    let sym = loc.symbols.iter().find(|s| s.symbol == "add").unwrap();
    let old_span = &src_rs.as_bytes()[sym.start_byte..sym.end_byte];
    let old_sha = sha256_prefixed(old_span);

    // Make sibling workspace file unreadable before splice_patch computes workspace_tree_digest.
    fs::set_permissions(&locked_file, fs::Permissions::from_mode(0o000)).unwrap();
    let patch_res = broker.splice_patch(PatchRequest {
        capability_id: "cap_io".into(),
        read_tokens: vec![sym.read_token.clone()],
        edits: vec![PatchEditInput {
            path: "src/lib.rs".into(),
            start_byte: sym.start_byte,
            end_byte: sym.end_byte,
            expected_old_sha256: old_sha.clone(),
            replacement_utf8: "pub fn add(a: i32, b: i32) -> i32 {\n    a + b + 0\n}".into(),
            anchor_symbol: Some("add".into()),
            anchor_node_kind: Some(sym.kind.clone()),
        }],
        lane: None,
        seam_contract: None,
        commit_subject: None,
        summary_lines: vec![],
        allow_oracle_write: false,
        actor: None,
        mode: None,
        model_id: None,
    });
    fs::set_permissions(&locked_file, fs::Permissions::from_mode(0o644)).unwrap();

    let err = patch_res.expect_err("unreadable workspace file must fail closed with ERR_IO");
    assert_eq!(err.code, "ERR_IO");

    // Also verify unreadable subdirectory fails closed instead of swallowing collect_workspace_files.
    let locked_dir = root.join("src/locked_sub");
    fs::create_dir_all(&locked_dir).unwrap();
    fs::write(locked_dir.join("inner.rs"), "pub fn z() {}\n").unwrap();
    fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o000)).unwrap();
    let dir_res = broker.splice_patch(PatchRequest {
        capability_id: "cap_io".into(),
        read_tokens: vec![sym.read_token.clone()],
        edits: vec![PatchEditInput {
            path: "src/lib.rs".into(),
            start_byte: sym.start_byte,
            end_byte: sym.end_byte,
            expected_old_sha256: old_sha,
            replacement_utf8: "pub fn add(a: i32, b: i32) -> i32 {\n    a + b + 0\n}".into(),
            anchor_symbol: Some("add".into()),
            anchor_node_kind: Some(sym.kind.clone()),
        }],
        lane: None,
        seam_contract: None,
        commit_subject: None,
        summary_lines: vec![],
        allow_oracle_write: false,
        actor: None,
        mode: None,
        model_id: None,
    });
    fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let dir_err = dir_res.expect_err("unreadable workspace dir must fail closed with ERR_IO");
    assert_eq!(dir_err.code, "ERR_IO");
}

#[test]
fn bug3_high_risk_refusal_cleanly_restores_working_tree() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("auth")).unwrap();
    let orig = "pub fn check(v: i32) -> bool {\n    v > 0\n}\n";
    fs::write(root.join("auth/check.rs"), orig).unwrap();
    init_git_repo(root);

    let mut broker = Broker::open(root, false).unwrap();
    let loc = broker
        .splice_locate(LocateRequest {
            path: "auth/check.rs".into(),
            capability_id: Some("auth_tweak".into()),
        })
        .unwrap();
    let sym = loc.symbols.iter().find(|s| s.symbol == "check").unwrap();
    let old_sha = sha256_prefixed(&orig.as_bytes()[sym.start_byte..sym.end_byte]);

    let pkt = broker
        .splice_patch(PatchRequest {
            capability_id: "auth_tweak".into(),
            read_tokens: vec![sym.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "auth/check.rs".into(),
                start_byte: sym.start_byte,
                end_byte: sym.end_byte,
                expected_old_sha256: old_sha,
                replacement_utf8: "pub fn check(v: i32) -> bool {\n    v >= 1\n}".into(),
                anchor_symbol: Some("check".into()),
                anchor_node_kind: Some(sym.kind.clone()),
            }],
            lane: None,
            seam_contract: None,
            commit_subject: None,
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();

    let bundle = broker
        .splice_verify(VerifyRequest {
            packet_id: pkt.packet_id.clone(),
            eval_count: None,
        })
        .unwrap();

    let err = broker
        .splice_project(ProjectRequest {
            packet_id: pkt.packet_id,
            bundle_id: bundle.bundle_id,
            approve_diff_sha256: None,
        })
        .unwrap_err();
    assert_eq!(err.code, "ERR_APPROVAL_REQUIRED");
    assert_eq!(fs::read_to_string(root.join("auth/check.rs")).unwrap(), orig);
}

#[test]
fn bug4_broker_owned_eval_count_blocks_caller_spoofing_and_persists() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join(".mde")).unwrap();
    let src_rs = "pub fn f(x: i32) -> i32 {\n    x + 1\n}\n";
    fs::write(root.join("src/lib.rs"), src_rs).unwrap();
    let policy = PolicyConfig {
        max_evals: 2,
        ..Default::default()
    };
    fs::write(
        root.join(".mde/policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
    init_git_repo(root);

    let mut broker = Broker::open(root, true).unwrap();
    let loc = broker
        .splice_locate(LocateRequest {
            path: "src/lib.rs".into(),
            capability_id: Some("cap_budget".into()),
        })
        .unwrap();
    let sym = loc.symbols.iter().find(|s| s.symbol == "f").unwrap();
    let old_sha = sha256_prefixed(&src_rs.as_bytes()[sym.start_byte..sym.end_byte]);
    let pkt = broker
        .splice_patch(PatchRequest {
            capability_id: "cap_budget".into(),
            read_tokens: vec![sym.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/lib.rs".into(),
                start_byte: sym.start_byte,
                end_byte: sym.end_byte,
                expected_old_sha256: old_sha,
                replacement_utf8: "pub fn f(x: i32) -> i32 {\n    x + 2\n}".into(),
                anchor_symbol: Some("f".into()),
                anchor_node_kind: Some(sym.kind.clone()),
            }],
            lane: None,
            seam_contract: None,
            commit_subject: None,
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();

    // Eval 1 (caller sends None) -> OK
    broker
        .splice_verify(VerifyRequest {
            packet_id: pkt.packet_id.clone(),
            eval_count: None,
        })
        .unwrap();
    // Eval 2 (caller tries to spoof 0) -> OK (broker count reaches 2 == max_evals)
    broker
        .splice_verify(VerifyRequest {
            packet_id: pkt.packet_id.clone(),
            eval_count: Some(0),
        })
        .unwrap();
    // Eval 3 (caller tries to spoof 1) -> MUST fail closed with ERR_BUDGET_EXCEEDED!
    let err3 = broker
        .splice_verify(VerifyRequest {
            packet_id: pkt.packet_id.clone(),
            eval_count: Some(1),
        })
        .unwrap_err();
    assert_eq!(err3.code, "ERR_BUDGET_EXCEEDED");

    // Reopening persisted broker must NOT reset evals_used!
    let reopened = Broker::open(root, true).unwrap();
    let err4 = reopened
        .splice_verify(VerifyRequest {
            packet_id: pkt.packet_id,
            eval_count: Some(1),
        })
        .unwrap_err();
    assert_eq!(err4.code, "ERR_BUDGET_EXCEEDED");
}

#[test]
fn bug5_json_dup_parser_enforces_max_depth_128() {
    // Valid depth 64 with duplicate key still detected.
    let mut dup64 = String::new();
    for _ in 0..63 {
        dup64.push_str("{\"a\":");
    }
    dup64.push_str("{\"k\":1,\"k\":2}");
    for _ in 0..63 {
        dup64.push('}');
    }
    let mut f_dup = Vec::new();
    audit_json_duplicate_keys("dup64.json", &dup64, &mut f_dup);
    assert_eq!(f_dup.len(), 1);
    assert_eq!(f_dup[0].rule, "duplicate_json_key");

    // Valid nesting exactly at depth 128 passes cleanly.
    let ok128 = format!("{}{}", "[".repeat(128), "]".repeat(128));
    let mut f_ok = Vec::new();
    audit_json_duplicate_keys("ok128.json", &ok128, &mut f_ok);
    assert!(f_ok.is_empty(), "depth 128 should pass, got: {:?}", f_ok);

    // Nesting at depth 129, 200, and 50_000 (arrays and objects) must fail closed without SIGSEGV.
    for depth in [129usize, 200usize, 50_000usize] {
        let deep_arr = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let mut findings = Vec::new();
        audit_json_duplicate_keys("deep_arr.json", &deep_arr, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "invalid_json" && f.message.contains("depth")),
            "array depth {depth} must be rejected by JsonDupParser with depth finding"
        );
    }
    let deep_obj = format!("{}0{}", "{\"a\":".repeat(10_000), "}".repeat(10_000));
    let mut obj_findings = Vec::new();
    audit_json_duplicate_keys("deep_obj.json", &deep_obj, &mut obj_findings);
    assert!(
        obj_findings
            .iter()
            .any(|f| f.rule == "invalid_json" && f.message.contains("depth")),
        "object depth 10000 must be rejected cleanly"
    );
}

#[test]
fn bug6_session_tokens_json_keys_are_deterministically_sorted() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("src")).unwrap();

    let mut broker = Broker::open(root, true).unwrap();
    for idx in 0..12 {
        let rel = format!("src/mod_{idx}.rs");
        let body = format!("pub fn fn_{idx}_a() -> i32 {{ {idx} }}\npub fn fn_{idx}_b() -> i32 {{ {} }}\n", idx + 1);
        fs::write(root.join(&rel), body).unwrap();
        broker
            .splice_locate(LocateRequest {
                path: rel,
                capability_id: Some("cap_det".into()),
            })
            .unwrap();
    }

    let raw = fs::read_to_string(root.join(".mde/session_tokens.json")).unwrap();
    // Extract token keys directly in serialized file order (lines matching `    "sha256:...": {`).
    let keys: Vec<String> = raw
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("\"sha256:") && trimmed.ends_with("\": {") {
                Some(
                    trimmed
                        .trim_start_matches('"')
                        .trim_end_matches("\": {")
                        .to_string(),
                )
            } else {
                None
            }
        })
        .collect();
    assert!(
        keys.len() >= 24,
        "expected >= 24 minted tokens, found {}",
        keys.len()
    );
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(
        keys, sorted,
        ".mde/session_tokens.json token keys must be canonically sorted (BTreeMap)"
    );
}

#[cfg(unix)]
#[test]
fn bug2b_stat_failure_in_0444_dir_and_injective_tree_digest() {
    // 1. Injective tree digest (control c2b): runs even as root!
    let tmp_a = TempDir::new().unwrap();
    let root_a = tmp_a.path();
    fs::create_dir_all(root_a.join("src")).unwrap();
    fs::write(root_a.join("src/lib.rs"), "pub fn f() -> i32 { 1 }\n").unwrap();
    fs::write(root_a.join("x"), b"1").unwrap();
    fs::write(root_a.join("y"), b"2").unwrap();

    let mut broker_a = Broker::open(root_a, false).unwrap();
    let loc_a = broker_a
        .splice_locate(LocateRequest {
            path: "src/lib.rs".into(),
            capability_id: Some("cap_inj".into()),
        })
        .unwrap();
    let sym_a = loc_a.symbols.iter().find(|s| s.symbol == "f").unwrap();
    let pkt_a = broker_a
        .splice_patch(PatchRequest {
            capability_id: "cap_inj".into(),
            read_tokens: vec![sym_a.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/lib.rs".into(),
                start_byte: sym_a.start_byte,
                end_byte: sym_a.end_byte,
                expected_old_sha256: sha256_prefixed(
                    &b"pub fn f() -> i32 { 1 }\n"[sym_a.start_byte..sym_a.end_byte],
                ),
                replacement_utf8: "pub fn f() -> i32 { 2 }".into(),
                anchor_symbol: Some("f".into()),
                anchor_node_kind: Some(sym_a.kind.clone()),
            }],
            lane: None,
            seam_contract: None,
            commit_subject: None,
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();

    let tmp_b = TempDir::new().unwrap();
    let root_b = tmp_b.path();
    fs::create_dir_all(root_b.join("src")).unwrap();
    fs::write(root_b.join("src/lib.rs"), "pub fn f() -> i32 { 1 }\n").unwrap();
    let forged_name = format!("x\t{}\ny", sha256_prefixed(b"1"));
    fs::write(root_b.join(&forged_name), b"2").unwrap();

    let mut broker_b = Broker::open(root_b, false).unwrap();
    let loc_b = broker_b
        .splice_locate(LocateRequest {
            path: "src/lib.rs".into(),
            capability_id: Some("cap_inj".into()),
        })
        .unwrap();
    let sym_b = loc_b.symbols.iter().find(|s| s.symbol == "f").unwrap();
    let pkt_b = broker_b
        .splice_patch(PatchRequest {
            capability_id: "cap_inj".into(),
            read_tokens: vec![sym_b.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/lib.rs".into(),
                start_byte: sym_b.start_byte,
                end_byte: sym_b.end_byte,
                expected_old_sha256: sha256_prefixed(
                    &b"pub fn f() -> i32 { 1 }\n"[sym_b.start_byte..sym_b.end_byte],
                ),
                replacement_utf8: "pub fn f() -> i32 { 2 }".into(),
                anchor_symbol: Some("f".into()),
                anchor_node_kind: Some(sym_b.kind.clone()),
            }],
            lane: None,
            seam_contract: None,
            commit_subject: None,
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();

    assert_ne!(
        pkt_a.base_tree, pkt_b.base_tree,
        "tab/newline filename framing collision (c2b) must be impossible"
    );
    assert_ne!(
        pkt_a.git_projection.expected_result_tree,
        pkt_b.git_projection.expected_result_tree,
        "expected_result_tree framing collision (c2b) must be impossible"
    );

    // 2. Mode 0o444 readable-but-unsearchable directory (control c2a): requires non-root DAC.
    let uid_out = Command::new("id").arg("-u").output().unwrap();
    if String::from_utf8_lossy(&uid_out.stdout).trim() == "0" {
        eprintln!("SKIPPED bug2b 0444 dir subtest: uid == 0 bypasses DAC search bits");
        return;
    }
    let data_dir = root_a.join("data");
    fs::create_dir_all(&data_dir).unwrap();
    fs::write(data_dir.join("secret.txt"), b"AAAA").unwrap();
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o444)).unwrap();

    let res_0444 = broker_a.splice_patch(PatchRequest {
        capability_id: "cap_inj".into(),
        read_tokens: vec![sym_a.read_token.clone()],
        edits: vec![PatchEditInput {
            path: "src/lib.rs".into(),
            start_byte: sym_a.start_byte,
            end_byte: sym_a.end_byte,
            expected_old_sha256: sha256_prefixed(
                &b"pub fn f() -> i32 { 1 }\n"[sym_a.start_byte..sym_a.end_byte],
            ),
            replacement_utf8: "pub fn f() -> i32 { 2 }".into(),
            anchor_symbol: Some("f".into()),
            anchor_node_kind: Some(sym_a.kind.clone()),
        }],
        lane: None,
        seam_contract: None,
        commit_subject: None,
        summary_lines: vec![],
        allow_oracle_write: false,
        actor: None,
        mode: None,
        model_id: None,
    });
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let err = res_0444.expect_err("0444 directory stat failure must fail closed with ERR_IO");
    assert_eq!(err.code, "ERR_IO");
}

#[cfg(unix)]
#[test]
fn bug3b_partial_write_and_failed_commit_rollback_worktree_and_index_and_ignore_ext_diff() {
    // Part A (control c3b + L5): runs even under uid 0!
    // Pre-commit hook aborts `git commit`: rollback must restore BOTH worktree AND staged index,
    // and `diff.external` must be ignored during `git_diff_paths` (`--no-ext-diff`).
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("src")).unwrap();
    let orig_lib = "pub fn calc(x: i32) -> i32 {\n    x + 1\n}\n";
    fs::write(root.join("src/lib.rs"), orig_lib).unwrap();
    init_git_repo(root);

    // Configure an external diff driver that would fail or corrupt diff output if invoked.
    let ext_out = Command::new("git")
        .current_dir(root)
        .args(["config", "diff.external", "false"])
        .output()
        .unwrap();
    assert!(ext_out.status.success());

    // Install a pre-commit hook that rejects commits.
    let hooks_dir = root.join(".git/hooks");
    fs::create_dir_all(&hooks_dir).unwrap();
    let hook_path = hooks_dir.join("pre-commit");
    fs::write(&hook_path, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).unwrap();

    let mut broker = Broker::open(root, false).unwrap();
    let loc = broker
        .splice_locate(LocateRequest {
            path: "src/lib.rs".into(),
            capability_id: Some("cap_c3b".into()),
        })
        .unwrap();
    let sym = loc.symbols.iter().find(|s| s.symbol == "calc").unwrap();
    let pkt = broker
        .splice_patch(PatchRequest {
            capability_id: "cap_c3b".into(),
            read_tokens: vec![sym.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/lib.rs".into(),
                start_byte: sym.start_byte,
                end_byte: sym.end_byte,
                expected_old_sha256: sha256_prefixed(
                    &orig_lib.as_bytes()[sym.start_byte..sym.end_byte],
                ),
                replacement_utf8: "pub fn calc(x: i32) -> i32 {\n    x + 10\n}".into(),
                anchor_symbol: Some("calc".into()),
                anchor_node_kind: Some(sym.kind.clone()),
            }],
            lane: None,
            seam_contract: None,
            commit_subject: None,
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();
    let bundle = broker
        .splice_verify(VerifyRequest {
            packet_id: pkt.packet_id.clone(),
            eval_count: None,
        })
        .unwrap();

    let proj_err = broker
        .splice_project(ProjectRequest {
            packet_id: pkt.packet_id.clone(),
            bundle_id: bundle.bundle_id.clone(),
            approve_diff_sha256: None,
        })
        .expect_err("pre-commit hook exit 1 must abort splice_project");
    assert_eq!(proj_err.code, "ERR_GIT");
    assert_eq!(
        fs::read_to_string(root.join("src/lib.rs")).unwrap(),
        orig_lib,
        "working tree must be restored after failed git commit"
    );
    let cached = Command::new("git")
        .current_dir(root)
        .args(["diff", "--cached", "--name-only"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&cached.stdout).trim(),
        "",
        "git index must be unstaged on rollback (control c3b)"
    );

    // Part B (controls c3_rollback & c3a): require non-root DAC mode 0o444 enforcement.
    let uid_out = Command::new("id").arg("-u").output().unwrap();
    if String::from_utf8_lossy(&uid_out.stdout).trim() == "0" {
        eprintln!("SKIPPED bug3b 0444 rollback subtests: uid == 0 bypasses 0o444 permissions");
        return;
    }

    // Control c3_rollback: pre-commit hook chmods patched `src/lib.rs` to 0444 then exits 1,
    // forcing rollback write failure during `splice_project` -> must surface `ERR_ROLLBACK_FAILED`.
    fs::write(&hook_path, "#!/bin/sh\nchmod 0444 src/lib.rs\nexit 1\n").unwrap();
    fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).unwrap();
    let rb_err = broker
        .splice_project(ProjectRequest {
            packet_id: pkt.packet_id,
            bundle_id: bundle.bundle_id,
            approve_diff_sha256: None,
        })
        .expect_err("read-only patched file during rollback must surface ERR_ROLLBACK_FAILED");
    fs::set_permissions(root.join("src/lib.rs"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(root.join("src/lib.rs"), orig_lib).unwrap();
    assert_eq!(rb_err.code, "ERR_ROLLBACK_FAILED");
    assert_eq!(
        rb_err.detail.as_ref().unwrap()["failed_paths"],
        json!(["src/lib.rs"])
    );

    // Control c3a: high-risk multi-file packet editing auth/a.rs and auth/b.rs where auth/b.rs
    // is made 0444 before project -> project returns ERR_IO and auth/a.rs is rolled back cleanly!
    let tmp2 = TempDir::new().unwrap();
    let root2 = tmp2.path();
    fs::create_dir_all(root2.join("auth")).unwrap();
    let orig_a = "pub fn auth_a(v: i32) -> bool {\n    v > 0\n}\n";
    let orig_b = "pub fn auth_b(v: i32) -> bool {\n    v > 1\n}\n";
    fs::write(root2.join("auth/a.rs"), orig_a).unwrap();
    fs::write(root2.join("auth/b.rs"), orig_b).unwrap();
    init_git_repo(root2);

    let mut broker2 = Broker::open(root2, false).unwrap();
    let loc2a = broker2
        .splice_locate(LocateRequest {
            path: "auth/a.rs".into(),
            capability_id: Some("auth_multi".into()),
        })
        .unwrap();
    let loc2b = broker2
        .splice_locate(LocateRequest {
            path: "auth/b.rs".into(),
            capability_id: Some("auth_multi".into()),
        })
        .unwrap();
    let sym2a = loc2a.symbols.iter().find(|s| s.symbol == "auth_a").unwrap();
    let sym2b = loc2b.symbols.iter().find(|s| s.symbol == "auth_b").unwrap();

    let pkt2 = broker2
        .splice_patch(PatchRequest {
            capability_id: "auth_multi".into(),
            read_tokens: vec![sym2a.read_token.clone(), sym2b.read_token.clone()],
            edits: vec![
                PatchEditInput {
                    path: "auth/a.rs".into(),
                    start_byte: sym2a.start_byte,
                    end_byte: sym2a.end_byte,
                    expected_old_sha256: sha256_prefixed(
                        &orig_a.as_bytes()[sym2a.start_byte..sym2a.end_byte],
                    ),
                    replacement_utf8: "pub fn auth_a(v: i32) -> bool {\n    v >= 10\n}".into(),
                    anchor_symbol: Some("auth_a".into()),
                    anchor_node_kind: Some(sym2a.kind.clone()),
                },
                PatchEditInput {
                    path: "auth/b.rs".into(),
                    start_byte: sym2b.start_byte,
                    end_byte: sym2b.end_byte,
                    expected_old_sha256: sha256_prefixed(
                        &orig_b.as_bytes()[sym2b.start_byte..sym2b.end_byte],
                    ),
                    replacement_utf8: "pub fn auth_b(v: i32) -> bool {\n    v >= 20\n}".into(),
                    anchor_symbol: Some("auth_b".into()),
                    anchor_node_kind: Some(sym2b.kind.clone()),
                },
            ],
            lane: None,
            seam_contract: None,
            commit_subject: None,
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();
    let bundle2 = broker2
        .splice_verify(VerifyRequest {
            packet_id: pkt2.packet_id.clone(),
            eval_count: None,
        })
        .unwrap();

    fs::set_permissions(root2.join("auth/b.rs"), fs::Permissions::from_mode(0o444)).unwrap();
    let c3a_err = broker2
        .splice_project(ProjectRequest {
            packet_id: pkt2.packet_id,
            bundle_id: bundle2.bundle_id,
            approve_diff_sha256: None,
        })
        .expect_err("0444 auth/b.rs must fail splice_project");
    fs::set_permissions(root2.join("auth/b.rs"), fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(c3a_err.code, "ERR_IO");
    assert_eq!(
        fs::read_to_string(root2.join("auth/a.rs")).unwrap(),
        orig_a,
        "auth/a.rs must be rolled back when sibling auth/b.rs write fails (control c3a)"
    );
    assert_eq!(
        fs::read_to_string(root2.join("auth/b.rs")).unwrap(),
        orig_b
    );
}

#[test]
fn bug4b_eval_budget_is_scoped_per_packet_and_token_store_tamper_fails_closed() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join(".mde")).unwrap();
    let src_rs = "pub fn f(x: i32) -> i32 {\n    x + 1\n}\n";
    fs::write(root.join("src/lib.rs"), src_rs).unwrap();
    let policy = PolicyConfig {
        max_evals: 2,
        ..Default::default()
    };
    fs::write(
        root.join(".mde/policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
    init_git_repo(root);

    let mut broker = Broker::open(root, true).unwrap();
    let loc = broker
        .splice_locate(LocateRequest {
            path: "src/lib.rs".into(),
            capability_id: Some("cap_scope".into()),
        })
        .unwrap();
    let sym = loc.symbols.iter().find(|s| s.symbol == "f").unwrap();
    let old_sha = sha256_prefixed(&src_rs.as_bytes()[sym.start_byte..sym.end_byte]);

    // Packet A (Task A)
    let pkt_a = broker
        .splice_patch(PatchRequest {
            capability_id: "cap_task_a".into(),
            read_tokens: vec![sym.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/lib.rs".into(),
                start_byte: sym.start_byte,
                end_byte: sym.end_byte,
                expected_old_sha256: old_sha.clone(),
                replacement_utf8: "pub fn f(x: i32) -> i32 {\n    x + 2\n}".into(),
                anchor_symbol: Some("f".into()),
                anchor_node_kind: Some(sym.kind.clone()),
            }],
            lane: None,
            seam_contract: None,
            commit_subject: None,
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();

    // Packet B (Task B — distinct packet_id!)
    let pkt_b = broker
        .splice_patch(PatchRequest {
            capability_id: "cap_task_b".into(),
            read_tokens: vec![sym.read_token.clone()],
            edits: vec![PatchEditInput {
                path: "src/lib.rs".into(),
                start_byte: sym.start_byte,
                end_byte: sym.end_byte,
                expected_old_sha256: old_sha,
                replacement_utf8: "pub fn f(x: i32) -> i32 {\n    x + 3\n}".into(),
                anchor_symbol: Some("f".into()),
                anchor_node_kind: Some(sym.kind.clone()),
            }],
            lane: None,
            seam_contract: None,
            commit_subject: None,
            summary_lines: vec![],
            allow_oracle_write: false,
            actor: None,
            mode: None,
            model_id: None,
        })
        .unwrap();
    assert_ne!(pkt_a.packet_id, pkt_b.packet_id);

    // Exhaust Task A's budget (2/2) across reopened persisted CLI-like brokers (control c4e).
    for _ in 0..2 {
        let b = Broker::open(root, true).unwrap();
        b.splice_verify(VerifyRequest {
            packet_id: pkt_a.packet_id.clone(),
            eval_count: None,
        })
        .unwrap();
    }
    let b_exhausted = Broker::open(root, true).unwrap();
    let err_a = b_exhausted
        .splice_verify(VerifyRequest {
            packet_id: pkt_a.packet_id.clone(),
            eval_count: None,
        })
        .unwrap_err();
    assert_eq!(err_a.code, "ERR_BUDGET_EXCEEDED");

    // Control c4e: Task B's first verify MUST succeed (per-packet budget, not repo-global lockout!).
    let b_fresh_task = Broker::open(root, true).unwrap();
    b_fresh_task
        .splice_verify(VerifyRequest {
            packet_id: pkt_b.packet_id.clone(),
            eval_count: None,
        })
        .expect("Task B must not be locked out by Task A exhausting max_evals (control c4e)");
    assert_eq!(b_fresh_task.packet_evals_used(&pkt_a.packet_id), 2);
    assert_eq!(b_fresh_task.packet_evals_used(&pkt_b.packet_id), 1);

    // Snapshot valid session_tokens.json so we can test c4a, c4b, and c4c independently.
    let tok_path = root.join(".mde/session_tokens.json");
    let valid_tokens_json = fs::read_to_string(&tok_path).unwrap();

    // Control c4a: deleting .mde/session_tokens.json after budget state exists MUST fail closed!
    fs::remove_file(&tok_path).unwrap();
    let err_c4a = match Broker::open(root, true) {
        Ok(_) => panic!("deleted session_tokens.json must fail closed (c4a)"),
        Err(e) => e,
    };
    assert_eq!(err_c4a.code, "ERR_TOKEN_STORE");

    // Control c4b: corrupting .mde/session_tokens.json with invalid JSON MUST fail closed!
    fs::write(&tok_path, "not json").unwrap();
    let err_c4b = match Broker::open(root, true) {
        Ok(_) => panic!("corrupt session_tokens.json must fail closed (c4b)"),
        Err(e) => e,
    };
    assert_eq!(err_c4b.code, "ERR_TOKEN_STORE");

    // Control c4c: editing packet eval count downward in .mde/session_tokens.json MUST fail closed!
    let edited = valid_tokens_json.replace(": 2", ": 0");
    assert_ne!(edited, valid_tokens_json);
    fs::write(&tok_path, edited).unwrap();
    let err_c4c = match Broker::open(root, true) {
        Ok(_) => panic!("tampered evals_by_packet in session_tokens.json must fail closed (c4c)"),
        Err(e) => e,
    };
    assert_eq!(err_c4c.code, "ERR_TOKEN_STORE");

    // Restoring intact session_tokens.json reopens cleanly with Task A still at 2/2 exhausted.
    fs::write(&tok_path, valid_tokens_json).unwrap();
    let restored = Broker::open(root, true).unwrap();
    assert_eq!(
        restored
            .splice_verify(VerifyRequest {
                packet_id: pkt_a.packet_id,
                eval_count: None,
            })
            .unwrap_err()
            .code,
        "ERR_BUDGET_EXCEEDED"
    );
}
