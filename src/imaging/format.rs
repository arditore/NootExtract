//! Image format identification.
//!
//! Format is determined from file content where a documented signature exists,
//! and only falls back to the file name when it does not. A raw image has no
//! signature by definition, so `raw` is the residual case rather than a positive
//! identification — and the tool says so instead of implying otherwise.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, IoResultExt, Result};

/// Bytes read when probing a file signature.
const PROBE_LEN: usize = 512;
/// Offset of the POSIX tar magic field within the first header block.
const TAR_MAGIC_OFFSET: usize = 257;
/// EWF (Expert Witness Format) file signature.
const EWF_MAGIC: [u8; 8] = [b'E', b'V', b'F', 0x09, 0x0d, 0x0a, 0xff, 0x00];
/// EWF2 / Ex01 file signature.
const EWF2_MAGIC: [u8; 8] = [b'E', b'V', b'F', b'2', 0x0d, 0x0a, 0x81, 0x00];

/// Container formats the tool recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageFormat {
    /// Unstructured bit-stream image (`dd` output).
    Raw,
    /// A raw image split across sequentially numbered segments.
    RawSegmented,
    /// POSIX tar archive, produced by logical acquisition.
    Tar,
    /// EWF / EnCase evidence file (`.E01`).
    Ewf,
    /// EWF version 2 (`.Ex01`).
    Ewf2,
}

impl ImageFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::RawSegmented => "raw-segmented",
            Self::Tar => "tar",
            Self::Ewf => "ewf",
            Self::Ewf2 => "ewf2",
        }
    }

    /// Whether this build can produce the format as a conversion target.
    pub fn is_supported_conversion_target(self) -> bool {
        matches!(self, Self::RawSegmented | Self::Ewf)
    }

    /// Whether this build can read the format as a conversion source.
    ///
    /// Only formats whose bytes this tool interprets itself are listed. EWF is
    /// deliberately absent: reading it would mean reimplementing a mature
    /// library.
    pub fn is_supported_conversion_source(self) -> bool {
        matches!(self, Self::Raw | Self::Tar)
    }
}

impl fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ImageFormat {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "raw" | "dd" => Ok(Self::Raw),
            "raw-segmented" | "segmented" | "split-raw" => Ok(Self::RawSegmented),
            "tar" => Ok(Self::Tar),
            "ewf" | "e01" | "encase" => Ok(Self::Ewf),
            "ewf2" | "ex01" => Ok(Self::Ewf2),
            other => Err(Error::Usage(format!(
                "unknown image format `{other}` (known: raw, raw-segmented, tar, ewf)"
            ))),
        }
    }
}

/// How confidently a format was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FormatEvidence {
    /// A documented signature was found in the file content.
    Signature,
    /// Inferred from the file name only.
    FileName,
    /// Nothing identified the file; treated as an unstructured image.
    Assumed,
}

/// Outcome of probing a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatProbe {
    pub format: ImageFormat,
    pub evidence: FormatEvidence,
    pub size_bytes: u64,
}

impl FormatProbe {
    /// Operator-facing summary that does not overstate certainty.
    pub fn describe(&self) -> String {
        match self.evidence {
            FormatEvidence::Signature => {
                format!("{} (identified by file signature)", self.format)
            }
            FormatEvidence::FileName => {
                format!("{} (inferred from the file name only)", self.format)
            }
            FormatEvidence::Assumed => format!(
                "{} (no signature found; treated as an unstructured image)",
                self.format
            ),
        }
    }
}

/// Identifies the format of a file without modifying it.
pub fn probe(path: &Path) -> Result<FormatProbe> {
    let metadata = std::fs::symlink_metadata(path).ctx("inspect", path)?;
    if metadata.file_type().is_symlink() {
        return Err(Error::Destination(format!(
            "`{}` is a symbolic link; refusing to follow it",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(Error::InvalidData(format!(
            "`{}` is not a regular file",
            path.display()
        )));
    }

    let mut file = File::open(path).ctx("open", path)?;
    let mut header = vec![0u8; PROBE_LEN];
    let read = read_at_most(&mut file, &mut header)?;
    header.truncate(read);

    if let Some(format) = format_from_signature(&header) {
        return Ok(FormatProbe {
            format,
            evidence: FormatEvidence::Signature,
            size_bytes: metadata.len(),
        });
    }

    if let Some(format) = format_from_file_name(path) {
        return Ok(FormatProbe {
            format,
            evidence: FormatEvidence::FileName,
            size_bytes: metadata.len(),
        });
    }

    Ok(FormatProbe {
        format: ImageFormat::Raw,
        evidence: FormatEvidence::Assumed,
        size_bytes: metadata.len(),
    })
}

fn read_at_most(file: &mut File, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let Some(slice) = buffer.get_mut(filled..) else {
            break;
        };
        match file.read(slice) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::io("read", "<image header>", e)),
        }
    }
    Ok(filled)
}

/// Matches documented file signatures.
pub fn format_from_signature(header: &[u8]) -> Option<ImageFormat> {
    if header.starts_with(&EWF_MAGIC) {
        return Some(ImageFormat::Ewf);
    }
    if header.starts_with(&EWF2_MAGIC) {
        return Some(ImageFormat::Ewf2);
    }
    // POSIX tar stores "ustar" at offset 257 of the first 512-byte header.
    if let Some(magic) = header.get(TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + 5)
        && magic == b"ustar"
    {
        return Some(ImageFormat::Tar);
    }
    None
}

/// Infers a format from the file name when no signature is available.
fn format_from_file_name(path: &Path) -> Option<ImageFormat> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    let extension = name.rsplit('.').next()?;
    // Numeric extensions denote a segment of a split raw image.
    if extension.len() == 3 && extension.chars().all(|c| c.is_ascii_digit()) {
        return Some(ImageFormat::RawSegmented);
    }
    match extension {
        "raw" | "dd" | "img" | "bin" => Some(ImageFormat::Raw),
        "tar" => Some(ImageFormat::Tar),
        "e01" => Some(ImageFormat::Ewf),
        "ex01" => Some(ImageFormat::Ewf2),
        _ => None,
    }
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
    use std::io::Write;

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(content).unwrap();
        path
    }

    fn tar_header() -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header.splice(
            TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + 6,
            b"ustar\0".iter().copied(),
        );
        header
    }

    #[test]
    fn identifies_tar_by_signature() {
        let dir = tempfile::tempdir().unwrap();
        // Deliberately misleading extension: content must win.
        let path = write_file(dir.path(), "archive.raw", &tar_header());
        let probe = probe(&path).unwrap();
        assert_eq!(probe.format, ImageFormat::Tar);
        assert_eq!(probe.evidence, FormatEvidence::Signature);
        assert!(probe.describe().contains("signature"));
    }

    #[test]
    fn identifies_ewf_by_signature() {
        let dir = tempfile::tempdir().unwrap();
        let mut content = EWF_MAGIC.to_vec();
        content.extend_from_slice(&[0u8; 32]);
        let path = write_file(dir.path(), "image.bin", &content);
        assert_eq!(probe(&path).unwrap().format, ImageFormat::Ewf);
    }

    #[test]
    fn identifies_ewf2_by_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "image.bin", &EWF2_MAGIC);
        assert_eq!(probe(&path).unwrap().format, ImageFormat::Ewf2);
    }

    #[test]
    fn falls_back_to_the_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "disk.e01", b"not really ewf content");
        let probe = probe(&path).unwrap();
        assert_eq!(probe.format, ImageFormat::Ewf);
        assert_eq!(probe.evidence, FormatEvidence::FileName);
        assert!(probe.describe().contains("file name only"));
    }

    #[test]
    fn recognizes_segment_extensions() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "image.001", b"\x00\x01\x02");
        assert_eq!(probe(&path).unwrap().format, ImageFormat::RawSegmented);
    }

    #[test]
    fn unidentified_content_is_reported_as_assumed_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "mystery", &[0xaa; 1024]);
        let probe = probe(&path).unwrap();
        assert_eq!(probe.format, ImageFormat::Raw);
        assert_eq!(probe.evidence, FormatEvidence::Assumed);
        assert_eq!(probe.size_bytes, 1024);
        assert!(probe.describe().contains("no signature"));
    }

    #[test]
    fn handles_files_shorter_than_the_probe_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "tiny.raw", b"ab");
        let probe = probe(&path).unwrap();
        assert_eq!(probe.size_bytes, 2);
        assert_eq!(probe.format, ImageFormat::Raw);
    }

    #[test]
    fn handles_empty_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "empty.raw", b"");
        let probe = probe(&path).unwrap();
        assert_eq!(probe.size_bytes, 0);
    }

    #[test]
    fn rejects_directories_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(probe(dir.path()).is_err());
        assert!(probe(&dir.path().join("absent")).is_err());
    }

    #[test]
    fn parses_format_names() {
        assert_eq!("raw".parse::<ImageFormat>().unwrap(), ImageFormat::Raw);
        assert_eq!("dd".parse::<ImageFormat>().unwrap(), ImageFormat::Raw);
        assert_eq!("E01".parse::<ImageFormat>().unwrap(), ImageFormat::Ewf);
        assert_eq!(
            "segmented".parse::<ImageFormat>().unwrap(),
            ImageFormat::RawSegmented
        );
        assert!("qcow2".parse::<ImageFormat>().is_err());
    }

    #[test]
    fn conversion_capabilities_are_explicit() {
        assert!(ImageFormat::RawSegmented.is_supported_conversion_target());
        assert!(ImageFormat::Ewf.is_supported_conversion_target());
        assert!(!ImageFormat::Raw.is_supported_conversion_target());
        assert!(ImageFormat::Raw.is_supported_conversion_source());
        assert!(ImageFormat::Tar.is_supported_conversion_source());
        assert!(!ImageFormat::Ewf.is_supported_conversion_source());
    }
}
