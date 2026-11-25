use crate::policy::confine_path;
use crate::types::{sha256_prefixed, MdeError, MdeResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const LOCKFILE_NAMES: &[&str] = &[
    "Cargo.lock",
    "uv.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
];

const CORE_SKIP_DIRS: &[&str] = &[
    ".git",
    ".mde",
    "target",
    "node_modules",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "tests",
    "vendor",
];

#[derive(Debug, Clone, Deserialize)]
pub struct DonorSpec {
    pub uri: String,
    pub commit: String,
    pub license: String,
    #[serde(default)]
    pub entry_symbols: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeamSpec {
    pub path: String,
    #[serde(default)]
    pub exports: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerificationSpec {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub max_host_files_touched: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpliceManifest {
    pub splice_version: String,
    pub capability: String,
    pub donor: DonorSpec,
    #[serde(default)]
    pub severance_map: BTreeMap<String, String>,
    pub seam: SeamSpec,
    #[serde(default)]
    pub verification: Option<VerificationSpec>,
    /// Optional explicit SHA-256 digests (`"<rel_path>": "<64-hex>"` or `"sha256:<64-hex>"`)
    /// for vendored slice files under `vendor/splices/<name>/`.
    #[serde(default)]
    pub slice_hashes: BTreeMap<String, String>,
    /// Optional lockfile digests pinned before vendoring to assert Zero Lockfile Mutation.
    #[serde(default)]
    pub host_lockfile_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamCheckFailure {
    pub invariant: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamReport {
    pub manifest_path: String,
    pub slice_name: String,
    pub capability: String,
    pub donor_commit: String,
    pub seam_path: String,
    pub slice_files_checked: usize,
    pub slice_tree_sha256: String,
    pub one_way_visibility_ok: bool,
    pub zero_lockfile_mutation_ok: bool,
    pub clean_ejection_ok: bool,
    pub ok: bool,
    pub failures: Vec<SeamCheckFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamSuiteReport {
    pub ok: bool,
    pub slices_verified: usize,
    pub reports: Vec<SeamReport>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn is_valid_commit_sha(commit: &str) -> bool {
    (7..=64).contains(&commit.len())
        && commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Verify a single `vendor/splices/<name>/splice.json` manifest against Splicer Protocol v0.1.0:
/// donor commit pinning, vendored slice SHA-256 verification, seam export presence,
/// One-Way Visibility, Zero Lockfile Mutation, and Clean Ejection.
pub fn verify_seam_manifest(repo_root: &Path, manifest_rel: &str) -> MdeResult<SeamReport> {
    let canon_root = fs::canonicalize(repo_root).map_err(|e| {
        MdeError::new("ERR_REPO_ROOT", format!("cannot canonicalize repo root: {e}"))
    })?;
    let (norm_manifest, abs_manifest) = confine_path(&canon_root, manifest_rel)?;

    let Some(rest) = norm_manifest.strip_prefix("vendor/splices/") else {
        return Err(MdeError::new(
            "ERR_INVALID_SEAM_PATH",
            format!("manifest must live under vendor/splices/<name>/splice.json: {norm_manifest}"),
        ));
    };
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1] != "splice.json" {
        return Err(MdeError::new(
            "ERR_INVALID_SEAM_PATH",
            format!("manifest must match vendor/splices/<name>/splice.json: {norm_manifest}"),
        ));
    }
    let slice_name = parts[0].to_string();
    let slice_prefix = format!("vendor/splices/{slice_name}/");

    let raw_text = fs::read_to_string(&abs_manifest).map_err(|e| {
        MdeError::new("ERR_IO", format!("failed to read {norm_manifest}: {e}"))
    })?;
    let manifest: SpliceManifest = serde_json::from_str(&raw_text).map_err(|e| {
        MdeError::new("ERR_SERIALIZE", format!("invalid splice.json {norm_manifest}: {e}"))
    })?;

    let mut failures: Vec<SeamCheckFailure> = Vec::new();

    // 1. Donor pinning checks.
    if manifest.splice_version.trim().is_empty() {
        failures.push(SeamCheckFailure {
            invariant: "manifest_schema".into(),
            detail: "splice_version is empty".into(),
        });
    }
    if manifest.capability.trim().is_empty() {
        failures.push(SeamCheckFailure {
            invariant: "manifest_schema".into(),
            detail: "capability is empty".into(),
        });
    }
    if manifest.donor.uri.trim().is_empty() {
        failures.push(SeamCheckFailure {
            invariant: "donor_pinning".into(),
            detail: "donor.uri is empty".into(),
        });
    }
    if !is_valid_commit_sha(&manifest.donor.commit) {
        failures.push(SeamCheckFailure {
            invariant: "donor_pinning".into(),
            detail: format!(
                "donor.commit must be a lowercase hex commit SHA (got '{}')",
                manifest.donor.commit
            ),
        });
    }
    if manifest.donor.license.trim().is_empty() {
        failures.push(SeamCheckFailure {
            invariant: "donor_pinning".into(),
            detail: "donor.license is empty".into(),
        });
    }

    // 2. Seam file containment and export verification.
    let seam_norm = match confine_path(&canon_root, &manifest.seam.path) {
        Ok((norm, abs)) => {
            if !norm.starts_with(&slice_prefix) {
                failures.push(SeamCheckFailure {
                    invariant: "seam_containment".into(),
                    detail: format!("seam.path '{norm}' escapes {slice_prefix}"),
                });
            } else if !abs.is_file() {
                failures.push(SeamCheckFailure {
                    invariant: "seam_containment".into(),
                    detail: format!("seam.path '{norm}' does not exist"),
                });
            } else {
                match fs::read_to_string(&abs) {
                    Ok(seam_src) => {
                        for sym in &manifest.seam.exports {
                            if !seam_src.contains(sym.as_str()) {
                                failures.push(SeamCheckFailure {
                                    invariant: "seam_exports".into(),
                                    detail: format!(
                                        "declared export '{sym}' not found in {norm}"
                                    ),
                                });
                            }
                        }
                    }
                    Err(err) => {
                        failures.push(SeamCheckFailure {
                            invariant: "seam_exports".into(),
                            detail: format!("failed to read seam file {norm} as UTF-8: {err}"),
                        });
                    }
                }
            }
            norm
        }
        Err(err) => {
            failures.push(SeamCheckFailure {
                invariant: "seam_containment".into(),
                detail: format!("invalid seam.path '{}': {}", manifest.seam.path, err.code),
            });
            manifest.seam.path.clone()
        }
    };

    // 3. Vendored slice files hashing & explicit slice_hashes verification.
    let slice_dir = canon_root.join("vendor/splices").join(&slice_name);
    let mut slice_files = Vec::new();
    let mut visited_dirs = BTreeSet::new();
    collect_files_under(&canon_root, &slice_dir, &mut visited_dirs, &mut slice_files)?;
    slice_files.sort();

    let mut tree_manifest = Vec::new();
    let mut lockfile_inside_slice = false;
    for rel in &slice_files {
        let (_, abs) = confine_path(&canon_root, rel)?;
        let bytes = fs::read(&abs)
            .map_err(|e| MdeError::new("ERR_IO", format!("read slice file {rel}: {e}")))?;
        let hex_digest = sha256_hex(&bytes);
        tree_manifest.extend_from_slice(format!("{rel}\t{hex_digest}\n").as_bytes());

        if let Some(fname) = Path::new(rel).file_name().and_then(|s| s.to_str()) {
            if LOCKFILE_NAMES.contains(&fname) {
                lockfile_inside_slice = true;
                failures.push(SeamCheckFailure {
                    invariant: "zero_lockfile_mutation".into(),
                    detail: format!("vendored slice must not ship lockfile: {rel}"),
                });
            }
        }
    }
    let slice_tree_sha256 = sha256_prefixed(&tree_manifest);

    for (rel, expected_raw) in &manifest.slice_hashes {
        let expected_hex = expected_raw
            .strip_prefix("sha256:")
            .unwrap_or(expected_raw.as_str());
        match confine_path(&canon_root, rel) {
            Ok((norm, abs)) => {
                if !norm.starts_with(&slice_prefix) {
                    failures.push(SeamCheckFailure {
                        invariant: "slice_hash".into(),
                        detail: format!("slice_hashes entry '{norm}' escapes {slice_prefix}"),
                    });
                    continue;
                }
                if !abs.is_file() {
                    failures.push(SeamCheckFailure {
                        invariant: "slice_hash".into(),
                        detail: format!("slice_hashes entry missing: {norm}"),
                    });
                    continue;
                }
                let bytes = fs::read(&abs)
                    .map_err(|e| MdeError::new("ERR_IO", format!("read {norm}: {e}")))?;
                let actual = sha256_hex(&bytes);
                if actual != expected_hex {
                    failures.push(SeamCheckFailure {
                        invariant: "slice_hash".into(),
                        detail: format!(
                            "hash mismatch on {norm}: expected {expected_hex}, got {actual}"
                        ),
                    });
                }
            }
            Err(err) => {
                failures.push(SeamCheckFailure {
                    invariant: "slice_hash".into(),
                    detail: format!("unconfined slice_hashes path '{rel}': {}", err.code),
                });
            }
        }
    }

    // 4. Zero Lockfile Mutation check on pinned host lockfiles.
    let mut zero_lockfile_mutation_ok = !lockfile_inside_slice;
    for (lock_rel, expected_raw) in &manifest.host_lockfile_hashes {
        let expected_hex = expected_raw
            .strip_prefix("sha256:")
            .unwrap_or(expected_raw.as_str());
        match confine_path(&canon_root, lock_rel) {
            Ok((norm, abs)) => {
                if !abs.is_file() {
                    zero_lockfile_mutation_ok = false;
                    failures.push(SeamCheckFailure {
                        invariant: "zero_lockfile_mutation".into(),
                        detail: format!("pinned host lockfile missing: {norm}"),
                    });
                } else {
                    let bytes = fs::read(&abs)
                        .map_err(|e| MdeError::new("ERR_IO", format!("read {norm}: {e}")))?;
                    let actual = sha256_hex(&bytes);
                    if actual != expected_hex {
                        zero_lockfile_mutation_ok = false;
                        failures.push(SeamCheckFailure {
                            invariant: "zero_lockfile_mutation".into(),
                            detail: format!("host lockfile mutated: {norm}"),
                        });
                    }
                }
            }
            Err(err) => {
                zero_lockfile_mutation_ok = false;
                failures.push(SeamCheckFailure {
                    invariant: "zero_lockfile_mutation".into(),
                    detail: format!("unconfined lockfile path '{lock_rel}': {}", err.code),
                });
            }
        }
    }

    // 5. One-Way Visibility & Clean Ejection: core code and build manifests outside
    //    vendor/splices/ must not import or depend directly on vendor/splices/<name>.
    let mut one_way_visibility_ok = true;
    let mut clean_ejection_ok = true;

    let core_files = collect_core_files(&canon_root)?;
    let slash_needle = format!("vendor/splices/{slice_name}");
    let dot_needle = format!("vendor.splices.{slice_name}");
    let rust_needle = format!("vendor::splices::{slice_name}");

    for rel in core_files {
        let ext = Path::new(&rel)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let is_code_or_manifest = matches!(
            ext.as_str(),
            "rs" | "py" | "c" | "h" | "ts" | "tsx" | "js" | "jsx" | "toml" | "json"
        );
        if !is_code_or_manifest {
            continue;
        }
        let Ok(content) = fs::read_to_string(canon_root.join(&rel)) else {
            continue;
        };
        if content.contains(&slash_needle)
            || content.contains(&dot_needle)
            || content.contains(&rust_needle)
        {
            let is_manifest = matches!(
                Path::new(&rel).file_name().and_then(|s| s.to_str()),
                Some("Cargo.toml" | "pyproject.toml" | "package.json")
            );
            if is_manifest {
                clean_ejection_ok = false;
                failures.push(SeamCheckFailure {
                    invariant: "clean_ejection".into(),
                    detail: format!(
                        "host build manifest '{rel}' depends directly on vendor/splices/{slice_name}"
                    ),
                });
            } else {
                one_way_visibility_ok = false;
                clean_ejection_ok = false;
                failures.push(SeamCheckFailure {
                    invariant: "one_way_visibility".into(),
                    detail: format!(
                        "core file '{rel}' directly references vendor/splices/{slice_name}"
                    ),
                });
            }
        }
    }

    let ok = failures.is_empty();
    Ok(SeamReport {
        manifest_path: norm_manifest,
        slice_name,
        capability: manifest.capability,
        donor_commit: manifest.donor.commit,
        seam_path: seam_norm,
        slice_files_checked: slice_files.len(),
        slice_tree_sha256,
        one_way_visibility_ok,
        zero_lockfile_mutation_ok,
        clean_ejection_ok,
        ok,
        failures,
    })
}

/// Discover and verify all `vendor/splices/*/splice.json` manifests inside `repo_root`.
pub fn verify_all_seams(repo_root: &Path) -> MdeResult<SeamSuiteReport> {
    let canon_root = fs::canonicalize(repo_root).map_err(|e| {
        MdeError::new("ERR_REPO_ROOT", format!("cannot canonicalize repo root: {e}"))
    })?;
    let splices_dir = canon_root.join("vendor/splices");
    if !splices_dir.is_dir() {
        return Ok(SeamSuiteReport {
            ok: true,
            slices_verified: 0,
            reports: Vec::new(),
        });
    }

    let mut manifests = Vec::new();
    let entries = fs::read_dir(&splices_dir)
        .map_err(|e| MdeError::new("ERR_IO", format!("read vendor/splices failed: {e}")))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let candidate = path.join("splice.json");
            if candidate.is_file() {
                let name = entry.file_name().to_string_lossy().into_owned();
                manifests.push(format!("vendor/splices/{name}/splice.json"));
            }
        }
    }
    manifests.sort();

    let mut reports = Vec::with_capacity(manifests.len());
    for m in &manifests {
        reports.push(verify_seam_manifest(&canon_root, m)?);
    }
    let ok = reports.iter().all(|r| r.ok);
    Ok(SeamSuiteReport {
        ok,
        slices_verified: reports.len(),
        reports,
    })
}

fn collect_files_under(
    canon_root: &Path,
    dir: &Path,
    visited: &mut BTreeSet<PathBuf>,
    out: &mut Vec<String>,
) -> MdeResult<()> {
    let canon_dir = fs::canonicalize(dir).map_err(|e| {
        MdeError::new("ERR_PATH_OUT_OF_BOUNDS", format!("cannot resolve dir: {e}"))
    })?;
    if !canon_dir.starts_with(canon_root) {
        return Err(MdeError::new(
            "ERR_PATH_OUT_OF_BOUNDS",
            "vendored directory escapes repository root",
        ));
    }
    if !visited.insert(canon_dir) {
        return Err(MdeError::new(
            "ERR_SYMLINK_CYCLE",
            "directory cycle detected under vendor/splices",
        ));
    }

    let entries = fs::read_dir(dir)
        .map_err(|e| MdeError::new("ERR_IO", format!("read_dir failed: {e}")))?;
    let mut sorted: Vec<_> = entries.flatten().collect();
    sorted.sort_by_key(|e| e.file_name());

    for entry in sorted {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "__pycache__" || name == ".DS_Store" {
            continue;
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| MdeError::new("ERR_IO", format!("metadata failed: {e}")))?;
        if meta.file_type().is_symlink() {
            let target = fs::canonicalize(&path).map_err(|e| {
                MdeError::new(
                    "ERR_PATH_OUT_OF_BOUNDS",
                    format!("broken or escaping symlink in vendored slice ({name}): {e}"),
                )
            })?;
            if !target.starts_with(canon_root) {
                return Err(MdeError::new(
                    "ERR_PATH_OUT_OF_BOUNDS",
                    format!("symlink escapes repository root in vendored slice: {name}"),
                ));
            }
            if target.is_dir() {
                return Err(MdeError::new(
                    "ERR_SYMLINK_CYCLE",
                    format!("directory symlink forbidden in vendored slice: {name}"),
                ));
            }
        }

        if path.is_dir() {
            collect_files_under(canon_root, &path, visited, out)?;
        } else if path.is_file() {
            if let Ok(rel) = path.strip_prefix(canon_root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(())
}

fn collect_core_files(root: &Path) -> MdeResult<Vec<String>> {
    let mut out = Vec::new();
    let mut visited = BTreeSet::new();
    walk_core(root, root, &mut visited, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk_core(
    root: &Path,
    dir: &Path,
    visited: &mut BTreeSet<PathBuf>,
    out: &mut Vec<String>,
) -> MdeResult<()> {
    let Ok(canon_dir) = fs::canonicalize(dir) else {
        return Ok(());
    };
    if !canon_dir.starts_with(root) || !visited.insert(canon_dir) {
        return Ok(());
    }
    let entries = fs::read_dir(dir)
        .map_err(|e| MdeError::new("ERR_IO", format!("read_dir failed: {e}")))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if CORE_SKIP_DIRS.contains(&name.as_str()) {
            continue;
        }
        let path = entry.path();
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                continue;
            }
        }
        if path.is_dir() {
            walk_core(root, &path, visited, out)?;
        } else if path.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(())
}
