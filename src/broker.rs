use crate::cst::{analyze_file, apply_byte_span_edits, detect_language};
use crate::guard::{
    audit_code_sources, check_sources, evaluate_call_policy, CallPolicyRequest, GuardOptions,
    GuardReport,
};
use crate::integrity::{verify_manifest, write_manifest, DEFAULT_MANIFEST_NAME};
use crate::policy::{
    classify_risk, confine_path, is_protected_oracle_path, scan_secrets_and_paths,
    validate_call_policy, AnchorSpec, PolicyConfig,
};
use crate::seam::{verify_all_seams, verify_seam_manifest};
use crate::types::{
    canonical_json_sha256, sha256_prefixed, AnchorResult, BudgetUsed, CommandResult, CstEdit,
    EvidenceBundle, EvidenceSummary, GenerationProvenance, GitProjectionSpec, HumanApproval, Lane,
    LocateResult, LocatedSymbol, MdeError, MdeMetaPayload, MdeResult, OracleIntegrity,
    ProjectResult, ReadProof, ReferenceHit, RiskClass, SeamContract, SplicePacket,
    ToolchainDigest, TraceResult, Zone, EVIDENCE_BUNDLE_SCHEMA, MDE_META_NAMESPACE, MDE_VERSION,
    SPLICE_PACKET_SCHEMA,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub path: String,
    pub blob_sha256: String,
    pub cst_root_sha256: String,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TokenStore {
    session_nonce: String,
    tokens: BTreeMap<String, TokenRecord>,
    #[serde(default)]
    evals_used: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocateRequest {
    pub path: String,
    #[serde(default)]
    pub capability_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TraceRequest {
    pub path: String,
    #[serde(default)]
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatchEditInput {
    pub path: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub expected_old_sha256: String,
    pub replacement_utf8: String,
    #[serde(default)]
    pub anchor_symbol: Option<String>,
    #[serde(default)]
    pub anchor_node_kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatchRequest {
    pub capability_id: String,
    pub read_tokens: Vec<String>,
    pub edits: Vec<PatchEditInput>,
    #[serde(default)]
    pub lane: Option<Lane>,
    #[serde(default)]
    pub seam_contract: Option<SeamContract>,
    #[serde(default)]
    pub commit_subject: Option<String>,
    #[serde(default)]
    pub summary_lines: Vec<String>,
    #[serde(default)]
    pub allow_oracle_write: bool,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifyRequest {
    pub packet_id: String,
    #[serde(default)]
    pub eval_count: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProjectRequest {
    pub packet_id: String,
    pub bundle_id: String,
    #[serde(default)]
    pub approve_diff_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GuardRequest {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub check_dupes: Option<bool>,
    #[serde(default)]
    pub check_mentions: bool,
    #[serde(default)]
    pub code_audit: bool,
    #[serde(default)]
    pub call_policy: Option<CallPolicyRequest>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IntegrityRequest {
    /// Mode: "verify" (default) or "write"
    #[serde(default = "default_verify_mode")]
    pub mode: String,
    #[serde(default)]
    pub manifest: Option<String>,
    #[serde(default = "default_strict_true")]
    pub strict_unlisted: bool,
}

fn default_verify_mode() -> String {
    "verify".to_string()
}

fn default_strict_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeamVerifyRequest {
    /// Optional single manifest path (vendor/splices/<name>/splice.json); if omitted, scans all.
    #[serde(default)]
    pub manifest_path: Option<String>,
}

pub struct Broker {
    repo_root: PathBuf,
    tokens: TokenStore,
    persist_tokens: bool,
    evals_used: AtomicU64,
}

impl Broker {
    pub fn open(repo_root: impl AsRef<Path>, persist_tokens: bool) -> MdeResult<Self> {
        let root = fs::canonicalize(repo_root.as_ref()).map_err(|e| {
            MdeError::new(
                "ERR_REPO_ROOT",
                format!("cannot open repository root: {e}"),
            )
        })?;
        let tokens = if persist_tokens {
            load_token_store(&root).unwrap_or_else(new_token_store)
        } else {
            new_token_store()
        };
        let evals_used = AtomicU64::new(tokens.evals_used);
        Ok(Self {
            repo_root: root,
            tokens,
            persist_tokens,
            evals_used,
        })
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn evals_used(&self) -> u64 {
        self.evals_used.load(Ordering::SeqCst)
    }

    fn save_tokens(&self) -> MdeResult<()> {
        if !self.persist_tokens {
            return Ok(());
        }
        let mde_dir = self.repo_root.join(".mde");
        fs::create_dir_all(&mde_dir).map_err(|e| {
            MdeError::new("ERR_IO", format!("failed to create .mde dir: {e}"))
        })?;
        let path = mde_dir.join("session_tokens.json");
        let snapshot = TokenStore {
            session_nonce: self.tokens.session_nonce.clone(),
            tokens: self.tokens.tokens.clone(),
            evals_used: self.evals_used.load(Ordering::SeqCst),
        };
        let data = serde_json::to_vec_pretty(&snapshot)
            .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("token serialize: {e}")))?;
        fs::write(path, data)
            .map_err(|e| MdeError::new("ERR_IO", format!("failed to write token store: {e}")))
    }

    fn mint_token(
        &mut self,
        rel_path: &str,
        blob_sha256: &str,
        cst_root_sha256: &str,
        start_byte: usize,
        end_byte: usize,
    ) -> String {
        let material = format!(
            "{}:{}:{}:{}:{}",
            self.tokens.session_nonce, rel_path, blob_sha256, start_byte, end_byte
        );
        let token = sha256_prefixed(material.as_bytes());
        self.tokens.tokens.insert(
            token.clone(),
            TokenRecord {
                path: rel_path.to_string(),
                blob_sha256: blob_sha256.to_string(),
                cst_root_sha256: cst_root_sha256.to_string(),
                start_byte,
                end_byte,
            },
        );
        token
    }

    pub fn splice_locate(&mut self, req: LocateRequest) -> MdeResult<LocateResult> {
        let policy = PolicyConfig::load(&self.repo_root)?;
        let (rel_path, abs_path) = confine_path(&self.repo_root, &req.path)?;
        validate_call_policy("splice_locate", std::slice::from_ref(&rel_path), 1, false, &policy)?;

        let bytes = fs::read(&abs_path).map_err(|e| {
            MdeError::new("ERR_IO", format!("failed to read {rel_path}: {e}"))
        })?;
        let blob_sha256 = sha256_prefixed(&bytes);
        let parsed = analyze_file(&rel_path, &bytes)?;

        let file_read_token = self.mint_token(
            &rel_path,
            &blob_sha256,
            &parsed.cst_root_sha256,
            0,
            bytes.len(),
        );

        let mut symbols = Vec::with_capacity(parsed.symbols.len());
        for sym in parsed.symbols {
            let tok = self.mint_token(
                &rel_path,
                &blob_sha256,
                &parsed.cst_root_sha256,
                sym.start_byte,
                sym.end_byte,
            );
            symbols.push(LocatedSymbol {
                symbol: sym.symbol,
                kind: sym.kind,
                zone: sym.zone,
                start_byte: sym.start_byte,
                end_byte: sym.end_byte,
                start_line: sym.start_line,
                end_line: sym.end_line,
                span_sha256: sym.span_sha256,
                read_token: tok,
            });
        }
        self.save_tokens()?;

        let mut meta = BTreeMap::new();
        meta.insert(
            MDE_META_NAMESPACE.to_string(),
            MdeMetaPayload {
                zone_hint: parsed.dominant_zone,
                dominant_zone: parsed.dominant_zone,
                zone_bytes: parsed.zone_bytes,
                checkpoint_fingerprint: None,
                slot_manifest_digest: None,
                rollback_state: "bypassed_to_w0".to_string(),
            },
        );

        Ok(LocateResult {
            path: rel_path,
            language: parsed.language,
            blob_sha256,
            cst_root_sha256: parsed.cst_root_sha256,
            total_bytes: bytes.len(),
            file_read_token,
            dominant_zone: parsed.dominant_zone,
            symbols,
            error_spans: parsed.error_spans,
            macro_opaque_spans: parsed.macro_opaque_spans,
            meta,
        })
    }

    pub fn splice_trace(&mut self, req: TraceRequest) -> MdeResult<TraceResult> {
        let policy = PolicyConfig::load(&self.repo_root)?;
        let (rel_path, abs_path) = confine_path(&self.repo_root, &req.path)?;
        validate_call_policy("splice_trace", std::slice::from_ref(&rel_path), 1, false, &policy)?;

        let bytes = fs::read(&abs_path).map_err(|e| {
            MdeError::new("ERR_IO", format!("failed to read {rel_path}: {e}"))
        })?;
        let blob_sha256 = sha256_prefixed(&bytes);
        let parsed = analyze_file(&rel_path, &bytes)?;
        let file_read_token = self.mint_token(
            &rel_path,
            &blob_sha256,
            &parsed.cst_root_sha256,
            0,
            bytes.len(),
        );
        self.save_tokens()?;

        let mut references = Vec::new();
        let mut dynamic_sites = parsed.dynamic_sites;
        let all_files = collect_workspace_files(&self.repo_root)?;

        if let Some(ref sym) = req.symbol {
            for f in &all_files {
                if let Ok(content) = fs::read(self.repo_root.join(f)) {
                    let text = String::from_utf8_lossy(&content);
                    for (idx, line) in text.lines().enumerate() {
                        if line.contains(sym.as_str()) {
                            references.push(ReferenceHit {
                                path: f.clone(),
                                line: idx + 1,
                                snippet: line.trim().chars().take(100).collect(),
                            });
                        }
                    }
                }
            }
        }

        // Also scan directly referenced files for dynamic call sites.
        let mut scanned_paths = vec![rel_path.clone()];
        for hit in &references {
            if !scanned_paths.contains(&hit.path) {
                scanned_paths.push(hit.path.clone());
                if let Ok(other_bytes) = fs::read(self.repo_root.join(&hit.path)) {
                    if let Ok(other_parsed) = analyze_file(&hit.path, &other_bytes) {
                        dynamic_sites.extend(other_parsed.dynamic_sites);
                    }
                }
            }
        }

        let mut mapped_anchors = Vec::new();
        let mut widened_anchors = Vec::new();
        for anchor in &policy.anchors {
            let matches_path = anchor.path_prefixes.is_empty()
                || anchor
                    .path_prefixes
                    .iter()
                    .any(|p| rel_path.starts_with(p));
            if matches_path {
                mapped_anchors.push(anchor.anchor_id.clone());
            } else if !dynamic_sites.is_empty() {
                // Gate G2.2: unresolved dynamic sites widen anchor execution.
                widened_anchors.push(anchor.anchor_id.clone());
            }
        }

        let sym_vec: Vec<String> = req.symbol.clone().into_iter().collect();
        let (risk_class, risk_triggers) =
            classify_risk(std::slice::from_ref(&rel_path), &sym_vec, "", &policy);

        let mut meta = BTreeMap::new();
        meta.insert(
            MDE_META_NAMESPACE.to_string(),
            MdeMetaPayload {
                zone_hint: parsed.dominant_zone,
                dominant_zone: parsed.dominant_zone,
                zone_bytes: parsed.zone_bytes,
                checkpoint_fingerprint: None,
                slot_manifest_digest: None,
                rollback_state: "bypassed_to_w0".to_string(),
            },
        );

        Ok(TraceResult {
            path: rel_path,
            symbol: req.symbol,
            blob_sha256,
            file_read_token,
            dominant_zone: parsed.dominant_zone,
            references,
            mapped_anchors,
            widened_anchors,
            unresolved_dynamic_sites: dynamic_sites,
            risk_class,
            risk_triggers,
            meta,
        })
    }

    pub fn splice_patch(&mut self, req: PatchRequest) -> MdeResult<SplicePacket> {
        let policy = PolicyConfig::load(&self.repo_root)?;
        if req.edits.is_empty() {
            return Err(MdeError::new("ERR_EMPTY_EDITS", "splice_patch requires at least one edit"));
        }

        // Normalize and confine every edited path first.
        let mut normalized_paths = Vec::new();
        for edit in &req.edits {
            let (norm, _) = confine_path(&self.repo_root, &edit.path)?;
            if !normalized_paths.contains(&norm) {
                normalized_paths.push(norm);
            }
        }

        let allow_oracle = req.allow_oracle_write && req.capability_id == "anchor_spec_change";
        validate_call_policy("splice_patch", &normalized_paths, 1, allow_oracle, &policy)?;

        // Group edits by normalized path.
        let mut edits_by_path: BTreeMap<String, Vec<PatchEditInput>> = BTreeMap::new();
        for edit in req.edits {
            let (norm, _) = confine_path(&self.repo_root, &edit.path)?;
            edits_by_path.entry(norm).or_default().push(edit);
        }

        let mut read_proofs = Vec::new();
        let mut final_edits = Vec::new();
        let mut staged_outputs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut all_dynamic_sites = Vec::new();
        let mut exported_syms = Vec::new();

        for (norm_path, file_edits) in &edits_by_path {
            let abs_path = self.repo_root.join(norm_path);
            let original = fs::read(&abs_path).map_err(|e| {
                MdeError::new("ERR_IO", format!("failed to read {norm_path}: {e}"))
            })?;
            let live_blob_sha = sha256_prefixed(&original);
            let parsed = analyze_file(norm_path, &original)?;

            // Enforce read-before-write pokayoke lock for every edit on this file.
            let mut verified_token: Option<(String, TokenRecord)> = None;
            for edit in file_edits {
                let matching = req.read_tokens.iter().find_map(|tok| {
                    self.tokens.tokens.get(tok).and_then(|rec| {
                        if rec.path == *norm_path
                            && rec.blob_sha256 == live_blob_sha
                            && rec.start_byte <= edit.start_byte
                            && rec.end_byte >= edit.end_byte
                        {
                            Some((tok.clone(), rec.clone()))
                        } else {
                            None
                        }
                    })
                });
                match matching {
                    Some(found) => {
                        verified_token = Some(found);
                    }
                    None => {
                        return Err(MdeError::with_detail(
                            "ERR_READ_REQUIRED",
                            format!(
                                "missing or stale read_token for {norm_path} ({}..{}); run splice_locate first",
                                edit.start_byte, edit.end_byte
                            ),
                            json!({
                                "path": norm_path,
                                "live_blob_sha256": live_blob_sha,
                                "start_byte": edit.start_byte,
                                "end_byte": edit.end_byte
                            }),
                        ));
                    }
                }
            }

            if let Some((tok, rec)) = verified_token {
                read_proofs.push(ReadProof {
                    path: norm_path.clone(),
                    blob_sha256: rec.blob_sha256,
                    cst_root_sha256: rec.cst_root_sha256,
                    read_token: tok,
                });
            }

            // Fail closed on secrets or local home paths inside replacement text (Gate G6.4).
            for edit in file_edits {
                let scan = scan_secrets_and_paths(
                    edit.replacement_utf8.as_bytes(),
                    policy.max_trace_bytes,
                );
                if !scan.passed {
                    return Err(MdeError::with_detail(
                        "ERR_SECRET_OR_PATH_LEAK",
                        format!("replacement text failed secret/path scan: {:?}", scan.findings),
                        json!({"findings": scan.findings}),
                    ));
                }
            }

            let lang = detect_language(norm_path);
            let mut cst_edits = Vec::with_capacity(file_edits.len());
            for edit in file_edits {
                let matched_sym = parsed
                    .symbols
                    .iter()
                    .find(|s| s.start_byte <= edit.start_byte && s.end_byte >= edit.end_byte);
                let zone = matched_sym
                    .map(|s| s.zone)
                    .unwrap_or(parsed.dominant_zone);
                let sym_name = edit
                    .anchor_symbol
                    .clone()
                    .or_else(|| matched_sym.map(|s| s.symbol.clone()))
                    .unwrap_or_else(|| "span".to_string());
                let node_kind = edit
                    .anchor_node_kind
                    .clone()
                    .or_else(|| matched_sym.map(|s| s.kind.clone()))
                    .unwrap_or_else(|| "byte_span".to_string());
                if !exported_syms.contains(&sym_name) {
                    exported_syms.push(sym_name.clone());
                }
                cst_edits.push(CstEdit {
                    path: norm_path.clone(),
                    language: lang,
                    anchor_node_kind: node_kind,
                    anchor_symbol: sym_name,
                    zone,
                    start_byte: edit.start_byte,
                    end_byte: edit.end_byte,
                    expected_old_sha256: edit.expected_old_sha256.clone(),
                    replacement_utf8: edit.replacement_utf8.clone(),
                });
            }

            // Apply raw byte edits in memory (checks G1.1, G1.2, G1.3, G1.4, and post-parse).
            let patched = apply_byte_span_edits(norm_path, &original, &cst_edits)?;
            for site in &parsed.dynamic_sites {
                all_dynamic_sites.push(format!("{}:{} {}", site.path, site.line, site.kind));
            }
            staged_outputs.insert(norm_path.clone(), patched);
            final_edits.extend(cst_edits);
        }

        let base_commit = git_rev_parse(&self.repo_root, "HEAD").unwrap_or_default();
        let base_tree = match git_rev_parse(&self.repo_root, "HEAD^{tree}") {
            Some(tree) => tree,
            None => workspace_tree_digest(&self.repo_root, &BTreeMap::new())?,
        };
        let expected_result_tree = workspace_tree_digest(&self.repo_root, &staged_outputs)?;

        let seam_contract = req.seam_contract.unwrap_or(SeamContract {
            exported_symbols_touched: exported_syms.clone(),
            calls_added: Vec::new(),
            unresolved_dynamic_sites: all_dynamic_sites,
            declared_effects: vec!["unspecified".to_string()],
        });

        let (risk_class, risk_triggers) = classify_risk(
            &normalized_paths,
            &seam_contract.exported_symbols_touched,
            &req.capability_id,
            &policy,
        );

        let mut packet = SplicePacket {
            schema: SPLICE_PACKET_SCHEMA.to_string(),
            packet_id: String::new(),
            capability_id: req.capability_id,
            base_commit,
            base_tree,
            lane: req.lane.unwrap_or(Lane::Build),
            risk_class,
            risk_triggers,
            parent_packets: Vec::new(),
            read_proofs,
            edits: final_edits,
            seam_contract,
            generation_provenance: GenerationProvenance {
                actor: req.actor.unwrap_or_else(|| "local-cli".to_string()),
                mode: req.mode.unwrap_or_else(|| "targeted".to_string()),
                model_id: req.model_id.unwrap_or_else(|| "none".to_string()),
                prompt_sha256: None,
                tool_trace_sha256: None,
                budget_used: BudgetUsed {
                    tokens: 0,
                    evals: 1,
                    wall_sec: 0,
                },
            },
            git_projection: GitProjectionSpec {
                commit_subject: req
                    .commit_subject
                    .unwrap_or_else(|| "splice: apply verified CST edit".to_string()),
                summary_lines: req.summary_lines,
                expected_result_tree,
            },
        };

        packet.packet_id = canonical_json_sha256(&packet, Some("packet_id"))?;
        self.persist_packet(&packet)?;
        Ok(packet)
    }

    pub fn splice_verify(&self, req: VerifyRequest) -> MdeResult<EvidenceBundle> {
        let policy = PolicyConfig::load(&self.repo_root)?;
        let packet = self.load_packet(&req.packet_id)?;
        let touched_paths: Vec<String> = packet.edits.iter().map(|e| e.path.clone()).collect();
        // Track evaluations on the broker so callers cannot spoof eval_count downward to bypass
        // max_evals, while still honoring any higher caller-supplied floor for compatibility.
        let next_eval = self.evals_used.load(Ordering::SeqCst).saturating_add(1);
        let effective_eval = next_eval.max(req.eval_count.unwrap_or(0));
        validate_call_policy(
            "splice_verify",
            &touched_paths,
            effective_eval,
            false,
            &policy,
        )?;
        self.evals_used.store(next_eval, Ordering::SeqCst);
        self.save_tokens()?;

        // Prepare isolated disposable workspace (git worktree when HEAD exists, else copy).
        let scratch = create_isolated_workspace(&self.repo_root, &packet.base_commit)?;
        let verify_res = self.run_verification_in_workspace(&scratch.path, &packet, &policy);
        cleanup_isolated_workspace(&self.repo_root, &scratch);
        let bundle = verify_res?;
        self.persist_bundle(&bundle)?;
        Ok(bundle)
    }

    fn run_verification_in_workspace(
        &self,
        work_dir: &Path,
        packet: &SplicePacket,
        policy: &PolicyConfig,
    ) -> MdeResult<EvidenceBundle> {
        let pre_oracle_sha = hash_protected_oracles(work_dir, policy)?;

        // Apply packet edits cleanly inside isolated workspace.
        let mut by_path: BTreeMap<String, Vec<CstEdit>> = BTreeMap::new();
        for edit in &packet.edits {
            by_path.entry(edit.path.clone()).or_default().push(edit.clone());
        }
        let mut patched_map = BTreeMap::new();
        for (rel_path, edits) in &by_path {
            let abs = work_dir.join(rel_path);
            let orig = fs::read(&abs).map_err(|e| {
                MdeError::new("ERR_IO", format!("verify read failed for {rel_path}: {e}"))
            })?;
            let updated = apply_byte_span_edits(rel_path, &orig, edits)?;
            fs::write(&abs, &updated).map_err(|e| {
                MdeError::new("ERR_IO", format!("verify write failed for {rel_path}: {e}"))
            })?;
            patched_map.insert(rel_path.clone(), updated);
        }

        let mut trace_bytes = Vec::new();

        // Tier 0 compiler / syntax gate.
        let tier0 = if let Some(ref cmd) = policy.tier0_cmd {
            let (res, raw_out) = run_command_checked(work_dir, cmd)?;
            trace_bytes.extend_from_slice(&raw_out);
            res
        } else {
            // Built-in CST parse verification across all patched files.
            let t0 = Instant::now();
            let mut ok = true;
            let mut diag = Vec::new();
            for (rel_path, bytes) in &patched_map {
                let parsed = analyze_file(rel_path, bytes)?;
                if !parsed.error_spans.is_empty() {
                    ok = false;
                    diag.extend_from_slice(
                        format!("{rel_path}: {} syntax error(s)\n", parsed.error_spans.len())
                            .as_bytes(),
                    );
                }
            }
            trace_bytes.extend_from_slice(&diag);
            CommandResult {
                zone: "A".to_string(),
                cmd: vec!["mde-cst-check".to_string()],
                exit_code: if ok { 0 } else { 1 },
                duration_ms: t0.elapsed().as_millis() as u64,
                diagnostics_sha256: sha256_prefixed(&diag),
                passed: ok,
            }
        };

        // Select anchors: mapped by path prefix, widened if unresolved dynamic sites exist (G2.2).
        let mut selected: Vec<&AnchorSpec> = Vec::new();
        let mut widened_reasons: Vec<String> = Vec::new();
        let has_dynamic = !packet.seam_contract.unresolved_dynamic_sites.is_empty();
        for anchor in &policy.anchors {
            let matches_path = anchor.path_prefixes.is_empty()
                || packet.edits.iter().any(|e| {
                    anchor
                        .path_prefixes
                        .iter()
                        .any(|p| e.path.starts_with(p))
                });
            if matches_path {
                selected.push(anchor);
            } else if has_dynamic {
                selected.push(anchor);
                widened_reasons.push(anchor.anchor_id.clone());
            }
        }

        let mut anchor_results = Vec::new();
        let mut tier1_passed = 0usize;
        let mut tier1_total = 0usize;
        let mut tier2_passed = 0usize;
        let mut tier2_total = 0usize;
        let mut any_anchor_failed = false;

        for anchor in selected {
            if anchor.zone == "B" && anchor.cassette_sha256.is_none() {
                return Err(MdeError::new(
                    "ERR_ZONE_B_NO_CASSETTE",
                    format!(
                        "Zone B anchor {} requires immutable cassette_sha256",
                        anchor.anchor_id
                    ),
                ));
            }
            let (stdout, stderr, exit_code, duration_ms) = run_raw_command(work_dir, &anchor.cmd)?;
            trace_bytes.extend_from_slice(&stdout);
            trace_bytes.extend_from_slice(&stderr);
            let passed = exit_code == 0;
            if !passed {
                any_anchor_failed = true;
            }
            if anchor.tier == 1 {
                tier1_total += 1;
                if passed {
                    tier1_passed += 1;
                }
            } else {
                tier2_total += 1;
                if passed {
                    tier2_passed += 1;
                }
            }
            anchor_results.push(AnchorResult {
                anchor_id: anchor.anchor_id.clone(),
                tier: anchor.tier,
                visibility: anchor.visibility.clone(),
                zone: anchor.zone.clone(),
                cmd: anchor.cmd.clone(),
                exit_code,
                passed,
                duration_ms,
                stdout_sha256: sha256_prefixed(&stdout),
                stderr_sha256: sha256_prefixed(&stderr),
                cassette_sha256: anchor.cassette_sha256.clone(),
            });
        }

        // Automatic native prose + safety guard on patched Zone::Prose files when enabled.
        if policy.enforce_prose_guard {
            let prose_opts = GuardOptions {
                check_prose: true,
                check_dupes: true,
                check_secrets: true,
                check_mentions: false,
                max_paragraph_chars: crate::guard::DEFAULT_MAX_PARAGRAPH_CHARS,
                max_trace_bytes: policy.max_trace_bytes,
                extra_forbidden_patterns: policy.extra_forbidden_patterns.clone(),
            };
            for (rel_path, bytes) in &patched_map {
                let parsed = analyze_file(rel_path, bytes)?;
                if parsed.dominant_zone == Zone::Prose {
                    let t0 = Instant::now();
                    let text = String::from_utf8_lossy(bytes);
                    let rep = check_sources(&[(rel_path.as_str(), text.as_ref())], &prose_opts);
                    let rep_json = serde_json::to_vec(&rep).unwrap_or_default();
                    tier1_total += 1;
                    if rep.passed {
                        tier1_passed += 1;
                    } else {
                        any_anchor_failed = true;
                    }
                    anchor_results.push(AnchorResult {
                        anchor_id: format!("mde_prose_guard:{rel_path}"),
                        tier: 1,
                        visibility: "visible".to_string(),
                        zone: "A".to_string(),
                        cmd: vec!["mde".to_string(), "guard".to_string(), rel_path.clone()],
                        exit_code: if rep.passed { 0 } else { 1 },
                        passed: rep.passed,
                        duration_ms: t0.elapsed().as_millis() as u64,
                        stdout_sha256: sha256_prefixed(&rep_json),
                        stderr_sha256: sha256_prefixed(b""),
                        cassette_sha256: None,
                    });
                }
            }
        }

        // Gate G3.4: verify protected oracle files were untouched during verification.
        let post_oracle_sha = hash_protected_oracles(work_dir, policy)?;
        let tamper_free = pre_oracle_sha == post_oracle_sha;

        // Gate G6.4: scan captured traces for secrets, local paths, and size cap.
        let secret_scan = scan_secrets_and_paths(&trace_bytes, policy.max_trace_bytes);
        if !secret_scan.passed {
            return Err(MdeError::with_detail(
                "ERR_SECRET_OR_PATH_LEAK",
                format!(
                    "verification trace failed secret/path/size scan: {:?}",
                    secret_scan.findings
                ),
                json!({"secret_scan": secret_scan}),
            ));
        }

        let lexicase_grade = if !tier0.passed || !tamper_free {
            "rejected".to_string()
        } else if !any_anchor_failed && tier1_passed == tier1_total && tier2_passed == tier2_total {
            "canonical".to_string()
        } else if tier2_passed == tier2_total && tier1_total >= 4 && tier1_passed + 1 >= tier1_total
        {
            "stepping_stone".to_string()
        } else {
            "rejected".to_string()
        };

        let result_tree = workspace_tree_digest(work_dir, &BTreeMap::new())?;
        let requires_approval = packet.risk_class == RiskClass::HighRisk;

        let mut bundle = EvidenceBundle {
            schema: EVIDENCE_BUNDLE_SCHEMA.to_string(),
            bundle_id: String::new(),
            packet_id: packet.packet_id.clone(),
            base_tree: packet.base_tree.clone(),
            result_tree,
            toolchain_digest: ToolchainDigest {
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                mde_version: MDE_VERSION.to_string(),
            },
            oracle_integrity: OracleIntegrity {
                protected_paths_pre_sha256: pre_oracle_sha,
                protected_paths_post_sha256: post_oracle_sha,
                tamper_free,
            },
            tier0_compiler: tier0,
            anchors: anchor_results,
            summary: EvidenceSummary {
                tier0_pass: true, // overwritten below
                tier1_passed,
                tier1_total,
                tier2_passed,
                tier2_total,
                lexicase_grade,
                widened_for_unresolved_sites: widened_reasons,
            },
            secret_scan,
            human_approval: HumanApproval {
                required: requires_approval,
                approved_diff_sha256: None,
            },
        };
        bundle.summary.tier0_pass = bundle.tier0_compiler.passed;
        bundle.bundle_id = canonical_json_sha256(&bundle, Some("bundle_id"))?;
        Ok(bundle)
    }

    pub fn splice_project(&self, req: ProjectRequest) -> MdeResult<ProjectResult> {
        let policy = PolicyConfig::load(&self.repo_root)?;
        let packet = self.load_packet(&req.packet_id)?;
        let bundle = self.load_bundle(&req.bundle_id)?;

        let touched_paths: Vec<String> = packet.edits.iter().map(|e| e.path.clone()).collect();
        validate_call_policy("splice_project", &touched_paths, 1, false, &policy)?;

        if bundle.packet_id != packet.packet_id || bundle.base_tree != packet.base_tree {
            return Err(MdeError::new(
                "ERR_BUNDLE_MISMATCH",
                "evidence bundle packet_id or base_tree does not match splice packet",
            ));
        }

        // Enforce live tree and commit freshness before projecting.
        let current_head = git_rev_parse(&self.repo_root, "HEAD").unwrap_or_default();
        let current_base_tree = match git_rev_parse(&self.repo_root, "HEAD^{tree}") {
            Some(tree) => tree,
            None => workspace_tree_digest(&self.repo_root, &BTreeMap::new())?,
        };
        if (!packet.base_commit.is_empty() && current_head != packet.base_commit)
            || current_base_tree != packet.base_tree
        {
            return Err(MdeError::with_detail(
                "ERR_STALE_BASE_TREE",
                "repository HEAD or base tree changed since packet was created",
                json!({
                    "expected_base_commit": packet.base_commit,
                    "actual_head": current_head,
                    "expected_base_tree": packet.base_tree,
                    "actual_base_tree": current_base_tree
                }),
            ));
        }

        if !bundle.summary.tier0_pass
            || !bundle.oracle_integrity.tamper_free
            || !bundle.secret_scan.passed
            || bundle.summary.lexicase_grade != "canonical"
        {
            return Err(MdeError::with_detail(
                "ERR_VERIFY_FAILED",
                "cannot project unverified or non-canonical bundle",
                json!({
                    "tier0_pass": bundle.summary.tier0_pass,
                    "tamper_free": bundle.oracle_integrity.tamper_free,
                    "secret_scan_passed": bundle.secret_scan.passed,
                    "grade": bundle.summary.lexicase_grade
                }),
            ));
        }

        // Compute patched outputs against live working tree without writing yet.
        let mut by_path: BTreeMap<String, Vec<CstEdit>> = BTreeMap::new();
        for edit in &packet.edits {
            by_path.entry(edit.path.clone()).or_default().push(edit.clone());
        }
        let mut originals: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut patched_files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (rel_path, edits) in &by_path {
            let abs = self.repo_root.join(rel_path);
            let orig = fs::read(&abs).map_err(|e| {
                MdeError::new("ERR_IO", format!("project read failed for {rel_path}: {e}"))
            })?;
            let updated = apply_byte_span_edits(rel_path, &orig, edits)?;
            originals.insert(rel_path.clone(), orig);
            patched_files.insert(rel_path.clone(), updated);
        }

        // Verify live patched workspace tree matches both bundle.result_tree and expected_result_tree.
        let actual_result_tree = workspace_tree_digest(&self.repo_root, &patched_files)?;
        if actual_result_tree != bundle.result_tree
            || actual_result_tree != packet.git_projection.expected_result_tree
        {
            return Err(MdeError::with_detail(
                "ERR_RESULT_TREE_MISMATCH",
                "patched workspace tree does not match verified bundle result_tree",
                json!({
                    "actual_result_tree": actual_result_tree,
                    "bundle_result_tree": bundle.result_tree,
                    "expected_result_tree": packet.git_projection.expected_result_tree
                }),
            ));
        }

        // Compute exact unified diff digest by staging in a scratch worktree or computing diff.
        // Write patched bytes temporarily, inspect `git diff -- <files>`, and roll back if blocked.
        let touched_vec: Vec<String> = patched_files.keys().cloned().collect();
        for (rel_path, bytes) in &patched_files {
            fs::write(self.repo_root.join(rel_path), bytes).map_err(|e| {
                MdeError::new("ERR_IO", format!("failed writing {rel_path}: {e}"))
            })?;
        }

        let diff_bytes = git_diff_paths(&self.repo_root, &touched_vec)?;
        let diff_sha256 = sha256_prefixed(&diff_bytes);

        // Gate G7.3: hard-block high-risk commits unless exact diff SHA-256 was approved.
        if packet.risk_class == RiskClass::HighRisk {
            let approved = req
                .approve_diff_sha256
                .as_deref()
                .map(|a| a == diff_sha256)
                .unwrap_or(false);
            if !approved {
                // Roll back working tree before returning refusal; fail explicitly if restore fails.
                self.rollback_originals(&originals, "ERR_APPROVAL_REQUIRED")?;
                return Err(MdeError::with_detail(
                    "ERR_APPROVAL_REQUIRED",
                    "high-risk splice requires exact diff SHA-256 human approval",
                    json!({
                        "risk_triggers": packet.risk_triggers,
                        "required_diff_sha256": diff_sha256
                    }),
                ));
            }
        }

        // Stage ONLY touched files and create a clean Git commit (Gate G4.1, zero Co-authored-by).
        let mut add_cmd = Command::new("git");
        add_cmd.current_dir(&self.repo_root).arg("add").arg("--");
        for f in &touched_vec {
            add_cmd.arg(f);
        }
        let add_out = add_cmd
            .output()
            .map_err(|e| MdeError::new("ERR_GIT", format!("git add failed: {e}")))?;
        if !add_out.status.success() {
            self.rollback_originals(&originals, "ERR_GIT")?;
            return Err(MdeError::new(
                "ERR_GIT",
                format!(
                    "git add failed: {}",
                    String::from_utf8_lossy(&add_out.stderr)
                ),
            ));
        }

        let mut msg = String::new();
        msg.push_str(&packet.git_projection.commit_subject);
        msg.push_str("\n\n");
        if packet.git_projection.summary_lines.is_empty() {
            msg.push_str(&format!("Capability: {}\n", packet.capability_id));
        } else {
            for line in &packet.git_projection.summary_lines {
                msg.push_str(line);
                msg.push('\n');
            }
        }
        msg.push_str(&format!(
            "\nSplice-Packet: {}\nSplice-Bundle: {}\n",
            packet.packet_id, bundle.bundle_id
        ));

        let commit_out = Command::new("git")
            .current_dir(&self.repo_root)
            .args(["commit", "-m", &msg])
            .output()
            .map_err(|e| MdeError::new("ERR_GIT", format!("git commit failed: {e}")))?;
        if !commit_out.status.success() {
            self.rollback_originals(&originals, "ERR_GIT")?;
            return Err(MdeError::new(
                "ERR_GIT",
                format!(
                    "git commit failed: {}",
                    String::from_utf8_lossy(&commit_out.stderr)
                ),
            ));
        }

        let commit_sha = git_rev_parse(&self.repo_root, "HEAD").unwrap_or_default();
        Ok(ProjectResult {
            packet_id: packet.packet_id,
            bundle_id: bundle.bundle_id,
            commit_sha,
            diff_sha256,
            touched_files: touched_vec,
        })
    }

    pub fn mde_guard(&self, req: GuardRequest) -> MdeResult<serde_json::Value> {
        let policy = PolicyConfig::load(&self.repo_root)?;
        if let Some(cp_req) = req.call_policy {
            let report = evaluate_call_policy(&self.repo_root, &cp_req, &policy);
            return serde_json::to_value(report)
                .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("{e}")));
        }

        if req.code_audit {
            if req.paths.is_empty() {
                return Err(MdeError::new(
                    "ERR_INVALID_ARGS",
                    "mde_guard with code_audit=true requires paths",
                ));
            }
            let mut loaded: Vec<(String, String)> = Vec::with_capacity(req.paths.len());
            for p in &req.paths {
                let (norm, abs) = confine_path(&self.repo_root, p)?;
                let raw_text = fs::read_to_string(&abs).map_err(|e| {
                    MdeError::new("ERR_IO", format!("code-audit failed to read {norm}: {e}"))
                })?;
                loaded.push((norm, raw_text));
            }
            let refs: Vec<(&str, &str)> = loaded
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let report = audit_code_sources(&refs)?;
            return serde_json::to_value(report)
                .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("{e}")));
        }

        let opts = GuardOptions {
            check_prose: true,
            check_dupes: req.check_dupes.unwrap_or(true),
            check_secrets: true,
            check_mentions: req.check_mentions,
            max_paragraph_chars: crate::guard::DEFAULT_MAX_PARAGRAPH_CHARS,
            max_trace_bytes: policy.max_trace_bytes,
            extra_forbidden_patterns: policy.extra_forbidden_patterns.clone(),
        };

        let report: GuardReport = if let Some(ref text) = req.text {
            check_sources(&[("<text>", text.as_str())], &opts)
        } else if !req.paths.is_empty() {
            let mut loaded: Vec<(String, String)> = Vec::with_capacity(req.paths.len());
            for p in &req.paths {
                let (norm, abs) = confine_path(&self.repo_root, p)?;
                let raw_text = fs::read_to_string(&abs).map_err(|e| {
                    MdeError::new("ERR_IO", format!("guard failed to read {norm}: {e}"))
                })?;
                loaded.push((norm, raw_text));
            }
            let refs: Vec<(&str, &str)> = loaded
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            check_sources(&refs, &opts)
        } else {
            return Err(MdeError::new(
                "ERR_INVALID_ARGS",
                "mde_guard requires paths, text, or call_policy",
            ));
        };

        serde_json::to_value(report).map_err(|e| MdeError::new("ERR_SERIALIZE", format!("{e}")))
    }

    pub fn mde_integrity(&self, req: IntegrityRequest) -> MdeResult<serde_json::Value> {
        let policy = PolicyConfig::load(&self.repo_root)?;
        validate_call_policy("mde_integrity", &[], 1, false, &policy)?;
        let manifest_name = req
            .manifest
            .as_deref()
            .unwrap_or(DEFAULT_MANIFEST_NAME);
        match req.mode.as_str() {
            "write" => {
                let res = write_manifest(&self.repo_root, manifest_name)?;
                serde_json::to_value(res)
                    .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("{e}")))
            }
            "verify" => {
                let rep = verify_manifest(&self.repo_root, manifest_name, req.strict_unlisted)?;
                serde_json::to_value(rep)
                    .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("{e}")))
            }
            other => Err(MdeError::new(
                "ERR_INVALID_ARGS",
                format!("mde_integrity mode must be 'verify' or 'write' (got '{other}')"),
            )),
        }
    }

    pub fn mde_seam_verify(&self, req: SeamVerifyRequest) -> MdeResult<serde_json::Value> {
        let policy = PolicyConfig::load(&self.repo_root)?;
        validate_call_policy("mde_seam_verify", &[], 1, false, &policy)?;
        if let Some(ref manifest_path) = req.manifest_path {
            let rep = verify_seam_manifest(&self.repo_root, manifest_path)?;
            serde_json::to_value(rep)
                .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("{e}")))
        } else {
            let suite = verify_all_seams(&self.repo_root)?;
            serde_json::to_value(suite)
                .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("{e}")))
        }
    }

    fn persist_packet(&self, packet: &SplicePacket) -> MdeResult<()> {
        let dir = self.repo_root.join(".mde/packets");
        fs::create_dir_all(&dir)
            .map_err(|e| MdeError::new("ERR_IO", format!("mkdir packets failed: {e}")))?;
        let fname = format!("{}.json", packet.packet_id.replace(':', "_"));
        let data = serde_json::to_vec_pretty(packet)
            .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("packet json: {e}")))?;
        fs::write(dir.join(fname), data)
            .map_err(|e| MdeError::new("ERR_IO", format!("write packet failed: {e}")))
    }

    pub fn load_packet(&self, packet_id: &str) -> MdeResult<SplicePacket> {
        validate_digest_id(packet_id, "packet_id")?;
        let fname = format!("{}.json", packet_id.replace(':', "_"));
        let path = self.repo_root.join(".mde/packets").join(fname);
        let raw_text = fs::read_to_string(&path).map_err(|e| {
            MdeError::new("ERR_PACKET_NOT_FOUND", format!("packet {packet_id}: {e}"))
        })?;
        let packet: SplicePacket = serde_json::from_str(&raw_text)
            .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("corrupt packet: {e}")))?;
        let computed = canonical_json_sha256(&packet, Some("packet_id"))?;
        if computed != packet_id || packet.packet_id != packet_id {
            return Err(MdeError::with_detail(
                "ERR_TAMPERED_PACKET",
                "packet JSON digest does not match packet_id",
                json!({"expected": packet_id, "computed": computed}),
            ));
        }
        Ok(packet)
    }

    fn persist_bundle(&self, bundle: &EvidenceBundle) -> MdeResult<()> {
        let dir = self.repo_root.join(".mde/bundles");
        fs::create_dir_all(&dir)
            .map_err(|e| MdeError::new("ERR_IO", format!("mkdir bundles failed: {e}")))?;
        let fname = format!("{}.json", bundle.bundle_id.replace(':', "_"));
        let data = serde_json::to_vec_pretty(bundle)
            .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("bundle json: {e}")))?;
        fs::write(dir.join(fname), data)
            .map_err(|e| MdeError::new("ERR_IO", format!("write bundle failed: {e}")))
    }

    pub fn load_bundle(&self, bundle_id: &str) -> MdeResult<EvidenceBundle> {
        validate_digest_id(bundle_id, "bundle_id")?;
        let fname = format!("{}.json", bundle_id.replace(':', "_"));
        let path = self.repo_root.join(".mde/bundles").join(fname);
        let raw_text = fs::read_to_string(&path).map_err(|e| {
            MdeError::new("ERR_BUNDLE_NOT_FOUND", format!("bundle {bundle_id}: {e}"))
        })?;
        let bundle: EvidenceBundle = serde_json::from_str(&raw_text)
            .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("corrupt bundle: {e}")))?;
        let computed = canonical_json_sha256(&bundle, Some("bundle_id"))?;
        if computed != bundle_id || bundle.bundle_id != bundle_id {
            return Err(MdeError::with_detail(
                "ERR_TAMPERED_BUNDLE",
                "bundle JSON digest does not match bundle_id",
                json!({"expected": bundle_id, "computed": computed}),
            ));
        }
        Ok(bundle)
    }

    fn rollback_originals(
        &self,
        originals: &BTreeMap<String, Vec<u8>>,
        cause_code: &str,
    ) -> MdeResult<()> {
        let mut failed_paths = Vec::new();
        let mut errors = Vec::new();
        for (rel_path, orig) in originals {
            if let Err(err) = fs::write(self.repo_root.join(rel_path), orig) {
                failed_paths.push(rel_path.clone());
                errors.push(format!("{rel_path}: {err}"));
            }
        }
        if !failed_paths.is_empty() {
            return Err(MdeError::with_detail(
                "ERR_ROLLBACK_FAILED",
                format!(
                    "failed to roll back working tree after {cause_code}: {}",
                    errors.join("; ")
                ),
                json!({
                    "cause": cause_code,
                    "failed_paths": failed_paths,
                    "errors": errors
                }),
            ));
        }
        Ok(())
    }
}

fn validate_digest_id(id: &str, field: &str) -> MdeResult<()> {
    let Some(hex_part) = id.strip_prefix("sha256:") else {
        return Err(MdeError::new(
            "ERR_INVALID_DIGEST_ID",
            format!("{field} must have format sha256:<64 lowercase hex chars>"),
        ));
    };
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(MdeError::new(
            "ERR_INVALID_DIGEST_ID",
            format!("{field} contains invalid digest characters or length"),
        ));
    }
    Ok(())
}

fn new_token_store() -> TokenStore {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let nonce = sha256_prefixed(format!("mde-session-{pid}-{nanos}").as_bytes());
    TokenStore {
        session_nonce: nonce,
        tokens: BTreeMap::new(),
        evals_used: 0,
    }
}

fn load_token_store(repo_root: &Path) -> Option<TokenStore> {
    let path = repo_root.join(".mde/session_tokens.json");
    let raw_text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw_text).ok()
}

fn git_rev_parse(repo_root: &Path, rev: &str) -> Option<String> {
    let out = Command::new("git")
        .current_dir(repo_root)
        .args(["rev-parse", rev])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn git_diff_paths(repo_root: &Path, paths: &[String]) -> MdeResult<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root).args(["diff", "--"]);
    for p in paths {
        cmd.arg(p);
    }
    let out = cmd
        .output()
        .map_err(|e| MdeError::new("ERR_GIT", format!("git diff failed: {e}")))?;
    if !out.status.success() {
        return Err(MdeError::new(
            "ERR_GIT",
            format!("git diff error: {}", String::from_utf8_lossy(&out.stderr)),
        ));
    }
    Ok(out.stdout)
}

fn collect_workspace_files(root: &Path) -> MdeResult<Vec<String>> {
    let mut out = Vec::new();
    walk_dir_rel(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk_dir_rel(root: &Path, dir: &Path, out: &mut Vec<String>) -> MdeResult<()> {
    let entries = fs::read_dir(dir)
        .map_err(|e| MdeError::new("ERR_IO", format!("read_dir failed: {e}")))?;
    for entry_res in entries {
        let entry = entry_res
            .map_err(|e| MdeError::new("ERR_IO", format!("read_dir entry failed: {e}")))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if matches!(
            name.as_str(),
            ".git" | ".mde" | "target" | "node_modules" | ".venv" | "__pycache__"
        ) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            walk_dir_rel(root, &path, out)?;
        } else if path.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(())
}

fn workspace_tree_digest(root: &Path, overrides: &BTreeMap<String, Vec<u8>>) -> MdeResult<String> {
    let mut files = collect_workspace_files(root)?;
    for k in overrides.keys() {
        if !files.contains(k) {
            files.push(k.clone());
        }
    }
    files.sort();
    let mut manifest = Vec::new();
    for f in files {
        let h = if let Some(b) = overrides.get(&f) {
            sha256_prefixed(b)
        } else {
            let b = fs::read(root.join(&f)).map_err(|e| {
                MdeError::new("ERR_IO", format!("workspace digest read failed for {f}: {e}"))
            })?;
            sha256_prefixed(&b)
        };
        manifest.extend_from_slice(format!("{f}\t{h}\n").as_bytes());
    }
    Ok(sha256_prefixed(&manifest))
}

fn hash_protected_oracles(work_dir: &Path, policy: &PolicyConfig) -> MdeResult<String> {
    let mut targets: Vec<String> = collect_workspace_files(work_dir)?
        .into_iter()
        .filter(|f| is_protected_oracle_path(f, policy))
        .collect();

    // Explicitly include configured protected paths even under `.mde/` (which walk_dir_rel skips).
    for spec in &policy.protected_oracle_paths {
        if spec.ends_with('/') {
            let dir = work_dir.join(spec.trim_end_matches('/'));
            if dir.is_dir() {
                let mut nested = Vec::new();
                collect_all_files_in_dir(work_dir, &dir, &mut nested)?;
                for f in nested {
                    if !targets.contains(&f) {
                        targets.push(f);
                    }
                }
            }
        } else if !targets.contains(spec) {
            targets.push(spec.clone());
        }
    }
    targets.sort();

    let mut manifest = Vec::new();
    for f in targets {
        let abs = work_dir.join(&f);
        if abs.is_file() {
            let bytes = fs::read(&abs).map_err(|e| {
                MdeError::new("ERR_IO", format!("oracle read failed for {f}: {e}"))
            })?;
            manifest.extend_from_slice(format!("{f}\t{}\n", sha256_prefixed(&bytes)).as_bytes());
        } else {
            manifest.extend_from_slice(format!("{f}\tABSENT\n").as_bytes());
        }
    }
    Ok(sha256_prefixed(&manifest))
}

fn collect_all_files_in_dir(root: &Path, dir: &Path, out: &mut Vec<String>) -> MdeResult<()> {
    let entries = fs::read_dir(dir)
        .map_err(|e| MdeError::new("ERR_IO", format!("read_dir failed: {e}")))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_all_files_in_dir(root, &path, out)?;
        } else if path.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(())
}

struct IsolatedWorkspace {
    path: PathBuf,
    is_worktree: bool,
}

fn create_isolated_workspace(repo_root: &Path, base_commit: &str) -> MdeResult<IsolatedWorkspace> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let wt_parent = repo_root.join(".mde/worktrees");
    fs::create_dir_all(&wt_parent)
        .map_err(|e| MdeError::new("ERR_IO", format!("mkdir worktrees failed: {e}")))?;
    let wt_path = wt_parent.join(format!("verify-{}-{}", std::process::id(), nanos));

    if !base_commit.is_empty() && repo_root.join(".git").exists() {
        let out = Command::new("git")
            .current_dir(repo_root)
            .args([
                "worktree",
                "add",
                "--detach",
                wt_path.to_string_lossy().as_ref(),
                base_commit,
            ])
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                return Ok(IsolatedWorkspace {
                    path: wt_path,
                    is_worktree: true,
                });
            }
        }
    }

    // Fallback: isolated plain directory copy (for non-git or unborn-HEAD workspaces).
    fs::create_dir_all(&wt_path)
        .map_err(|e| MdeError::new("ERR_IO", format!("mkdir scratch copy failed: {e}")))?;
    for rel in collect_workspace_files(repo_root)? {
        let dest = wt_path.join(&rel);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)
                .map_err(|e| MdeError::new("ERR_IO", format!("mkdir parent failed: {e}")))?;
        }
        fs::copy(repo_root.join(&rel), &dest)
            .map_err(|e| MdeError::new("ERR_IO", format!("copy {rel} failed: {e}")))?;
    }
    Ok(IsolatedWorkspace {
        path: wt_path,
        is_worktree: false,
    })
}

fn cleanup_isolated_workspace(repo_root: &Path, ws: &IsolatedWorkspace) {
    if ws.is_worktree {
        let _ = Command::new("git")
            .current_dir(repo_root)
            .args([
                "worktree",
                "remove",
                "--force",
                ws.path.to_string_lossy().as_ref(),
            ])
            .output();
    }
    let _ = fs::remove_dir_all(&ws.path);
}

fn run_raw_command(work_dir: &Path, cmd: &[String]) -> MdeResult<(Vec<u8>, Vec<u8>, i32, u64)> {
    if cmd.is_empty() {
        return Err(MdeError::new("ERR_EMPTY_CMD", "command array is empty"));
    }
    let t0 = Instant::now();
    let out = Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(work_dir)
        .output()
        .map_err(|e| MdeError::new("ERR_EXEC", format!("failed to run {}: {e}", cmd[0])))?;
    let code = out.status.code().unwrap_or(-1);
    Ok((out.stdout, out.stderr, code, t0.elapsed().as_millis() as u64))
}

fn run_command_checked(work_dir: &Path, cmd: &[String]) -> MdeResult<(CommandResult, Vec<u8>)> {
    let (stdout, stderr, exit_code, duration_ms) = run_raw_command(work_dir, cmd)?;
    let mut combined = Vec::with_capacity(stdout.len() + stderr.len());
    combined.extend_from_slice(&stdout);
    combined.extend_from_slice(&stderr);
    let diag_sha = sha256_prefixed(&combined);
    let res = CommandResult {
        zone: "A".to_string(),
        cmd: cmd.to_vec(),
        exit_code,
        duration_ms,
        diagnostics_sha256: diag_sha,
        passed: exit_code == 0,
    };
    Ok((res, combined))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    #[test]
    fn rollback_originals_surfaces_err_rollback_failed_and_restores_writable_siblings() {
        let uid_out = Command::new("id").arg("-u").output().unwrap();
        if String::from_utf8_lossy(&uid_out.stdout).trim() == "0" {
            return;
        }
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("auth")).unwrap();
        let locked = root.join("auth/locked.rs");
        let sibling = root.join("auth/sibling.rs");
        fs::write(&locked, b"modified_locked").unwrap();
        fs::write(&sibling, b"modified_sibling").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o444)).unwrap();

        let broker = Broker::open(root, false).unwrap();
        let mut originals = BTreeMap::new();
        originals.insert("auth/locked.rs".to_string(), b"orig_locked".to_vec());
        originals.insert("auth/sibling.rs".to_string(), b"orig_sibling".to_vec());

        let res = broker.rollback_originals(&originals, "ERR_APPROVAL_REQUIRED");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();

        let err = res.expect_err("read-only target must surface ERR_ROLLBACK_FAILED");
        assert_eq!(err.code, "ERR_ROLLBACK_FAILED");
        let detail = err.detail.as_ref().expect("expected rollback detail");
        assert_eq!(detail["cause"], "ERR_APPROVAL_REQUIRED");
        assert_eq!(detail["failed_paths"], json!(["auth/locked.rs"]));
        // Writable sibling was still restored cleanly.
        assert_eq!(fs::read(&sibling).unwrap(), b"orig_sibling");
    }
}
