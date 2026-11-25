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
