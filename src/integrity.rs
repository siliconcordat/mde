use crate::policy::confine_path;
use crate::types::{MdeError, MdeResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const DEFAULT_MANIFEST_NAME: &str = "SHA256SUMS";
pub const ALT_MANIFEST_NAME: &str = "MANIFEST.sha256";

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".mde",
    "target",
    "node_modules",
    ".venv",
    "__pycache__",
    ".pytest_cache",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnconfinedEntry {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityWriteResult {
    pub manifest: String,
    pub files_hashed: usize,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub manifest: String,
    pub manifest_present: bool,
    pub manifest_sha256: Option<String>,
    pub files_verified: usize,
    pub empty_manifest: bool,
    pub mismatched_files: Vec<String>,
    pub missing_files: Vec<String>,
    pub unlisted_files: Vec<String>,
    pub unconfined_paths: Vec<UnconfinedEntry>,
    pub malformed_lines: Vec<String>,
    pub duplicate_paths: Vec<String>,
    pub ok: bool,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn validate_manifest_name(name: &str) -> MdeResult<String> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.contains('\0')
    {
        return Err(MdeError::new(
            "ERR_INVALID_MANIFEST",
            format!("manifest name must be a plain root filename: {name}"),
        ));
    }
    Ok(name.to_string())
}

fn gitignore_ignores_cargo_lock(root: &Path) -> bool {
    let Ok(text) = fs::read_to_string(root.join(".gitignore")) else {
        return false;
    };
    text.lines()
        .map(str::trim)
        .any(|l| l == "Cargo.lock" || l == "/Cargo.lock")
}

fn collect_manifest_files(root: &Path, manifest_name: &str) -> MdeResult<Vec<String>> {
    let canon_root = fs::canonicalize(root).map_err(|e| {
        MdeError::new("ERR_REPO_ROOT", format!("cannot canonicalize root: {e}"))
    })?;
    let skip_cargo_lock = gitignore_ignores_cargo_lock(&canon_root);
    let mut files = Vec::new();
    walk_confined(
        &canon_root,
        &canon_root,
        manifest_name,
        skip_cargo_lock,
        &mut files,
    )?;
    files.sort();
    Ok(files)
}

fn walk_confined(
    canon_root: &Path,
    dir: &Path,
    manifest_name: &str,
    skip_cargo_lock: bool,
    out: &mut Vec<String>,
) -> MdeResult<()> {
    let entries = fs::read_dir(dir)
        .map_err(|e| MdeError::new("ERR_IO", format!("read_dir failed: {e}")))?;
    let mut sorted_entries: Vec<_> = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MdeError::new("ERR_IO", format!("read_dir entry failed: {e}")))?;
    sorted_entries.sort_by_key(|e| e.file_name());

    for entry in sorted_entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if SKIP_DIRS.contains(&name.as_str()) {
            continue;
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| MdeError::new("ERR_IO", format!("metadata failed: {e}")))?;
        let ft = meta.file_type();

        if ft.is_symlink() {
            let resolved = fs::canonicalize(&path).map_err(|e| {
                MdeError::new(
                    "ERR_PATH_OUT_OF_BOUNDS",
                    format!("broken or escaping symlink {name}: {e}"),
                )
            })?;
            if !resolved.starts_with(canon_root) {
                return Err(MdeError::new(
                    "ERR_PATH_OUT_OF_BOUNDS",
                    format!("symlink escapes repository root: {name}"),
                ));
            }
            if resolved.is_dir() {
                return Err(MdeError::new(
                    "ERR_PATH_OUT_OF_BOUNDS",
                    format!("directory symlink rejected by integrity walk: {name}"),
                ));
            }
        }

        if ft.is_dir() {
            walk_confined(canon_root, &path, manifest_name, skip_cargo_lock, out)?;
        } else if ft.is_file() || ft.is_symlink() {
            let rel = path
                .strip_prefix(canon_root)
                .map_err(|e| MdeError::new("ERR_IO", format!("strip_prefix failed: {e}")))?
                .to_string_lossy()
                .replace('\\', "/");
            if rel == manifest_name
                || rel == DEFAULT_MANIFEST_NAME
                || rel == ALT_MANIFEST_NAME
                || rel.ends_with(".DS_Store")
                || (skip_cargo_lock && rel == "Cargo.lock")
            {
                continue;
            }
            out.push(rel);
        }
    }
    Ok(())
}

/// Write a deterministic, sorted Plane 1 SHA-256 manifest (`SHA256SUMS` or `MANIFEST.sha256`).
pub fn write_manifest(root: &Path, manifest_name: &str) -> MdeResult<IntegrityWriteResult> {
    let manifest = validate_manifest_name(manifest_name)?;
    let canon_root = fs::canonicalize(root).map_err(|e| {
        MdeError::new("ERR_REPO_ROOT", format!("cannot canonicalize root: {e}"))
    })?;
    let files = collect_manifest_files(&canon_root, &manifest)?;

    let mut content = String::new();
    for rel in &files {
        let (_, abs) = confine_path(&canon_root, rel)?;
        let bytes = fs::read(&abs)
            .map_err(|e| MdeError::new("ERR_IO", format!("failed to read {rel}: {e}")))?;
        let digest = sha256_hex(&bytes);
        content.push_str(&format!("{digest}  {rel}\n"));
    }

    let manifest_sha256 = sha256_hex(content.as_bytes());
    fs::write(canon_root.join(&manifest), content.as_bytes())
        .map_err(|e| MdeError::new("ERR_IO", format!("failed to write {manifest}: {e}")))?;

    Ok(IntegrityWriteResult {
        manifest,
        files_hashed: files.len(),
        manifest_sha256,
    })
}

/// Verify a repository tree against `SHA256SUMS` or `MANIFEST.sha256`.
/// Rejects path traversal, escaping symlinks, malformed lines, duplicates, missing, modified,
/// and (when `strict_unlisted` is true) unlisted extra files.
pub fn verify_manifest(
    root: &Path,
    manifest_name: &str,
    strict_unlisted: bool,
) -> MdeResult<IntegrityReport> {
    let manifest = validate_manifest_name(manifest_name)?;
    let canon_root = fs::canonicalize(root).map_err(|e| {
        MdeError::new("ERR_REPO_ROOT", format!("cannot canonicalize root: {e}"))
    })?;
    let manifest_path = canon_root.join(&manifest);

    let mut report = IntegrityReport {
        manifest: manifest.clone(),
        manifest_present: manifest_path.is_file(),
        manifest_sha256: None,
        files_verified: 0,
        empty_manifest: false,
        mismatched_files: Vec::new(),
        missing_files: Vec::new(),
        unlisted_files: Vec::new(),
        unconfined_paths: Vec::new(),
        malformed_lines: Vec::new(),
        duplicate_paths: Vec::new(),
        ok: false,
    };

    if !manifest_path.is_file() {
        return Ok(report);
    }

    let raw_bytes = fs::read(&manifest_path)
        .map_err(|e| MdeError::new("ERR_IO", format!("failed to read {manifest}: {e}")))?;
    report.manifest_sha256 = Some(sha256_hex(&raw_bytes));
    let raw_text = String::from_utf8_lossy(&raw_bytes);

    let mut listed: BTreeSet<String> = BTreeSet::new();

    for line in raw_text.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.trim().is_empty() {
            continue;
        }
        let Some((digest, rel)) = trimmed.split_once("  ") else {
            report.malformed_lines.push(trimmed.to_string());
            continue;
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            report.malformed_lines.push(trimmed.to_string());
            continue;
        }
        if rel.contains('\\') || rel.starts_with("./") || rel.contains("/./") || rel.ends_with("/.")
        {
            report.unconfined_paths.push(UnconfinedEntry {
                path: rel.to_string(),
                error: "noncanonical_path".to_string(),
            });
            continue;
        }

        let (norm, abs) = match confine_path(&canon_root, rel) {
            Ok(pair) => pair,
            Err(err) => {
                report.unconfined_paths.push(UnconfinedEntry {
                    path: rel.to_string(),
                    error: err.code,
                });
                continue;
            }
        };

        if !listed.insert(norm.clone()) {
            report.duplicate_paths.push(norm);
            continue;
        }

        if !abs.is_file() {
            report.missing_files.push(norm);
            continue;
        }

        let actual_bytes = fs::read(&abs)
            .map_err(|e| MdeError::new("ERR_IO", format!("failed to read {norm}: {e}")))?;
        if sha256_hex(&actual_bytes) != digest {
            report.mismatched_files.push(norm);
        } else {
            report.files_verified += 1;
        }
    }

    let live_files = collect_manifest_files(&canon_root, &manifest)?;
    for rel in live_files {
        if !listed.contains(&rel) {
            report.unlisted_files.push(rel);
        }
    }

    // Fail closed on vacuous empty manifests even when strict_unlisted is false.
    report.empty_manifest = listed.is_empty() || report.files_verified == 0;
    if report.empty_manifest {
        report
            .malformed_lines
            .push("ERR_EMPTY_MANIFEST: manifest verified zero files".to_string());
    }

    let core_clean = !report.empty_manifest
        && report.mismatched_files.is_empty()
        && report.missing_files.is_empty()
        && report.unconfined_paths.is_empty()
        && report.malformed_lines.is_empty()
        && report.duplicate_paths.is_empty();

    report.ok = core_clean && (!strict_unlisted || report.unlisted_files.is_empty());
    Ok(report)
}
