//! Filesystem-path safety and untrusted-string handling.
//!
//! Two distinct classes of string reach this module:
//!
//! * **Operator input** (case and evidence identifiers) is validated strictly
//!   and rejected when it does not match the expected shape.
//! * **Device-controlled data** (properties reported over ADB) is never
//!   validated as a path. It is sanitized before it is stored in a manifest and
//!   is only ever used to build a filename after aggressive normalization.
//!
//! Everything written below an evidence root is resolved through
//! [`join_inside`], which rejects absolute paths, parent traversal and symlinked
//! components before any file is opened.

use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// Maximum accepted length of an operator-supplied identifier.
const MAX_IDENTIFIER_LEN: usize = 64;
/// Maximum length of a device-derived string retained in the manifest.
const MAX_DEVICE_STRING_LEN: usize = 256;
/// Maximum length of a filename fragment derived from untrusted data.
const MAX_FILENAME_FRAGMENT_LEN: usize = 48;

/// Names that cannot be used as file names on Windows, in any letter case and
/// with or without an extension.
const WINDOWS_RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validates an operator-supplied identifier such as a case or evidence ID.
///
/// Identifiers become path components and appear in manifest file names, so the
/// accepted alphabet is deliberately narrow: ASCII letters, digits, `.`, `_`
/// and `-`. Leading dots and dashes are rejected so an identifier can never
/// produce a hidden file or be mistaken for a command-line flag.
pub fn validate_identifier(value: &str, field: &str) -> Result<String> {
    if value.is_empty() {
        return Err(Error::Usage(format!("{field} must not be empty")));
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(Error::Usage(format!(
            "{field} must be at most {MAX_IDENTIFIER_LEN} characters"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(Error::Usage(format!(
            "{field} may only contain ASCII letters, digits, '.', '_' and '-' (got `{value}`)"
        )));
    }
    if value.starts_with('.') || value.starts_with('-') {
        return Err(Error::Usage(format!(
            "{field} must not start with '.' or '-' (got `{value}`)"
        )));
    }
    if value.contains("..") {
        return Err(Error::Usage(format!(
            "{field} must not contain '..' (got `{value}`)"
        )));
    }
    if is_windows_reserved(value) {
        return Err(Error::Usage(format!(
            "{field} `{value}` is a reserved device name on Windows"
        )));
    }
    Ok(value.to_owned())
}

fn is_windows_reserved(value: &str) -> bool {
    let stem = value.split('.').next().unwrap_or(value);
    WINDOWS_RESERVED
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(stem))
}

/// Normalizes a device-reported string for storage in a manifest.
///
/// Control characters are removed rather than escaped so that a hostile device
/// cannot inject line breaks into the JSON Lines log or terminal escape
/// sequences into operator output. The result is length-capped.
pub fn sanitize_device_string(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DEVICE_STRING_LEN)
        .collect();
    cleaned.trim().to_owned()
}

/// Derives a safe filename fragment from an untrusted or free-form string.
///
/// Any character outside `[A-Za-z0-9._-]` becomes `_`, runs of `_` are
/// collapsed, and the result is truncated and stripped of leading dots and
/// dashes. Returns `None` when nothing usable remains.
pub fn sanitize_filename_fragment(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len().min(MAX_FILENAME_FRAGMENT_LEN));
    let mut last_was_separator = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            if ch == '.' && out.is_empty() {
                continue;
            }
            out.push(ch);
            last_was_separator = false;
        } else if !last_was_separator && !out.is_empty() {
            out.push('_');
            last_was_separator = true;
        }
        if out.chars().count() >= MAX_FILENAME_FRAGMENT_LEN {
            break;
        }
    }
    let trimmed = out.trim_matches(|c| c == '_' || c == '-' || c == '.');
    if trimmed.is_empty() || is_windows_reserved(trimmed) {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Joins `relative` onto `root`, guaranteeing the result stays inside `root`.
///
/// Rejects absolute paths, drive-relative and UNC prefixes, `.` and `..`
/// components. The check is purely lexical; [`ensure_no_symlinked_components`]
/// covers the filesystem-level escape via symbolic links.
pub fn join_inside(root: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.as_os_str().is_empty() {
        return Err(Error::Destination("empty relative path".into()));
    }
    let mut out = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let text = part.to_str().ok_or_else(|| {
                    Error::Destination(format!(
                        "path component in `{}` is not valid UTF-8",
                        relative.display()
                    ))
                })?;
                if text == "." || text == ".." {
                    return Err(Error::Destination(format!(
                        "path `{}` contains a parent-directory reference",
                        relative.display()
                    )));
                }
                out.push(text);
            }
            Component::CurDir => {
                return Err(Error::Destination(format!(
                    "path `{}` contains a '.' component",
                    relative.display()
                )));
            }
            Component::ParentDir => {
                return Err(Error::Destination(format!(
                    "path `{}` escapes the evidence root via '..'",
                    relative.display()
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(Error::Destination(format!(
                    "path `{}` must be relative to the evidence root",
                    relative.display()
                )));
            }
        }
    }
    Ok(out)
}

/// Verifies that no component of `path` below `root` is a symbolic link.
///
/// Called immediately before creating or opening evidence files. It cannot
/// eliminate the TOCTOU window on its own, which is why every evidence write
/// additionally uses `create_new` so the open fails if anything appeared in the
/// meantime.
pub fn ensure_no_symlinked_components(root: &Path, path: &Path) -> Result<()> {
    let relative = path.strip_prefix(root).map_err(|_| {
        Error::Destination(format!(
            "path `{}` is not inside evidence root `{}`",
            path.display(),
            root.display()
        ))
    })?;

    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(Error::Destination(format!(
                "unexpected component in `{}`",
                relative.display()
            )));
        };
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(Error::Destination(format!(
                        "`{}` is a symbolic link; refusing to follow it while handling evidence",
                        current.display()
                    )));
                }
            }
            // A component that does not exist yet cannot be a symlink.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::io("inspect", &current, e)),
        }
    }
    Ok(())
}

/// Canonicalizes a path and normalizes it for comparison.
///
/// On Windows, `std::fs::canonicalize` returns a verbatim (`\?\`) path.
/// Mixing verbatim and non-verbatim forms makes `strip_prefix` fail even when
/// one path really is inside the other, so every path that will be compared
/// against an evidence root goes through this function.
pub fn canonicalize(path: &Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(path).map_err(|e| Error::io("resolve", path, e))?;
    Ok(strip_verbatim_prefix(canonical))
}

/// Removes the Windows verbatim (`\\?\`) prefix from a canonical path.
///
/// UNC paths keep their prefix, because stripping it would change what they
/// resolve to.
fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    if cfg!(windows) {
        let text = path.to_string_lossy();
        if let Some(stripped) = text.strip_prefix(r"\\?\")
            && !stripped.starts_with("UNC\\")
        {
            return PathBuf::from(stripped);
        }
    }
    path
}

/// Renders `path` relative to `root` using forward slashes.
///
/// Manifests and `.sha256` side files must be byte-identical regardless of the
/// host operating system, so separators are normalized.
pub fn relative_slash_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        Error::Destination(format!(
            "path `{}` is not inside `{}`",
            path.display(),
            root.display()
        ))
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(Error::Destination(format!(
                "unexpected component in `{}`",
                relative.display()
            )));
        };
        parts.push(
            part.to_str()
                .ok_or_else(|| Error::Destination("path is not valid UTF-8".into()))?
                .to_owned(),
        );
    }
    if parts.is_empty() {
        return Err(Error::Destination("empty relative path".into()));
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::default_trait_access,
        clippy::format_push_string,
        clippy::integer_division,
        clippy::cast_sign_loss
    )]
    use super::*;

    #[test]
    fn accepts_conventional_identifiers() {
        assert_eq!(
            validate_identifier("CASE-001", "case id").unwrap(),
            "CASE-001"
        );
        assert_eq!(
            validate_identifier("EVIDENCE_001.a", "evidence id").unwrap(),
            "EVIDENCE_001.a"
        );
    }

    #[test]
    fn rejects_path_traversal_in_identifiers() {
        for bad in ["..", "../etc", "CASE/../..", "a..b"] {
            assert!(
                validate_identifier(bad, "case id").is_err(),
                "`{bad}` must be rejected"
            );
        }
    }

    #[test]
    fn rejects_separators_and_hidden_identifiers() {
        for bad in ["CASE/001", "CASE\\001", ".hidden", "-flag", "", "a b"] {
            assert!(
                validate_identifier(bad, "case id").is_err(),
                "`{bad}` must be rejected"
            );
        }
    }

    #[test]
    fn rejects_windows_reserved_identifiers() {
        for bad in ["CON", "nul", "Com1", "LPT9.raw"] {
            assert!(
                validate_identifier(bad, "evidence id").is_err(),
                "`{bad}` must be rejected"
            );
        }
    }

    #[test]
    fn rejects_overlong_identifiers() {
        let long = "A".repeat(MAX_IDENTIFIER_LEN + 1);
        assert!(validate_identifier(&long, "case id").is_err());
    }

    #[test]
    fn sanitizes_hostile_device_strings() {
        assert_eq!(sanitize_device_string("Pixel 7\n\rfake"), "Pixel 7fake");
        assert_eq!(sanitize_device_string("  spaced  "), "spaced");
        assert_eq!(sanitize_device_string("esc\u{1b}[31m"), "esc[31m");
        assert_eq!(sanitize_device_string("\0\0"), "");
        let long = "x".repeat(MAX_DEVICE_STRING_LEN + 50);
        assert_eq!(sanitize_device_string(&long).len(), MAX_DEVICE_STRING_LEN);
    }

    #[test]
    fn sanitizes_filename_fragments() {
        assert_eq!(
            sanitize_filename_fragment("Pixel 7a").as_deref(),
            Some("Pixel_7a")
        );
        assert_eq!(
            sanitize_filename_fragment("../../etc/passwd").as_deref(),
            Some("etc_passwd")
        );
        assert_eq!(
            sanitize_filename_fragment("a:b*c?").as_deref(),
            Some("a_b_c")
        );
        assert_eq!(sanitize_filename_fragment("///").as_deref(), None);
        assert_eq!(sanitize_filename_fragment("").as_deref(), None);
        assert_eq!(sanitize_filename_fragment("CON").as_deref(), None);
    }

    #[test]
    fn join_inside_rejects_escapes() {
        let root = Path::new("/evidence/CASE-001");
        assert!(join_inside(root, Path::new("../secret")).is_err());
        assert!(join_inside(root, Path::new("original/../../x")).is_err());
        assert!(join_inside(root, Path::new("./x")).is_err());
        assert!(join_inside(root, Path::new("")).is_err());
        #[cfg(windows)]
        assert!(join_inside(root, Path::new("C:\\Windows\\System32")).is_err());
        #[cfg(unix)]
        assert!(join_inside(root, Path::new("/etc/shadow")).is_err());
    }

    #[test]
    fn join_inside_accepts_nested_relative_paths() {
        let root = Path::new("/evidence/CASE-001");
        let joined = join_inside(root, Path::new("original/image.raw")).unwrap();
        assert!(joined.ends_with("image.raw"));
        assert!(joined.starts_with(root));
    }

    #[test]
    fn relative_paths_use_forward_slashes() {
        let root = Path::new("/evidence/CASE-001");
        let full = join_inside(root, Path::new("original/image.raw")).unwrap();
        assert_eq!(
            relative_slash_path(root, &full).unwrap(),
            "original/image.raw"
        );
    }

    #[test]
    fn relative_path_rejects_outside_root() {
        let root = Path::new("/evidence/CASE-001");
        assert!(relative_slash_path(root, Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn symlink_check_passes_for_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("original").join("image.raw");
        assert!(ensure_no_symlinked_components(dir.path(), &target).is_ok());
    }

    #[test]
    fn symlink_check_passes_for_plain_files() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("original");
        std::fs::create_dir_all(&sub).unwrap();
        let file = sub.join("image.raw");
        std::fs::write(&file, b"data").unwrap();
        assert!(ensure_no_symlinked_components(dir.path(), &file).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_check_detects_symlinked_directory() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let root = dir.path().join("case");
        std::fs::create_dir_all(&root).unwrap();
        let link = root.join("original");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let target = link.join("image.raw");
        assert!(ensure_no_symlinked_components(&root, &target).is_err());
    }
}
