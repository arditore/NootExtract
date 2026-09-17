//! Streaming cryptographic hashing.
//!
//! Forensic images are routinely larger than host memory, so every digest in
//! NootExtract is computed incrementally over a fixed-size buffer. No function
//! in this module ever materializes a whole artifact in RAM, and the same code
//! path is used whether the bytes come from a file on disk or from a live ADB
//! stream, so an acquisition digest and a later verification digest are
//! produced identically.

use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, IoResultExt, Result};
use crate::util::cancel::CancellationToken;

/// Read/hash block size.
///
/// 1 MiB keeps syscall overhead low on multi-gigabyte images while bounding
/// resident memory to a constant independent of artifact size.
pub const HASH_BUFFER_SIZE: usize = 1024 * 1024;

/// Supported digest algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashAlgorithm {
    /// SHA-256. Always computed; the baseline integrity guarantee.
    Sha256,
    /// SHA-512. Optional secondary digest.
    Sha512,
}

impl HashAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => Ok(Self::Sha256),
            "sha512" | "sha-512" => Ok(Self::Sha512),
            other => Err(Error::Usage(format!(
                "unknown hash algorithm `{other}` (supported: sha256, sha512)"
            ))),
        }
    }
}

/// The digests computed for a single artifact.
///
/// `sha256` is mandatory so that every artifact has a comparable baseline
/// digest; `sha512` is present only when it was requested at acquisition time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestSet {
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
}

impl DigestSet {
    /// Returns the digest for `algorithm`, if it was computed.
    pub fn get(&self, algorithm: HashAlgorithm) -> Option<&str> {
        match algorithm {
            HashAlgorithm::Sha256 => Some(self.sha256.as_str()),
            HashAlgorithm::Sha512 => self.sha512.as_deref(),
        }
    }

    /// Constant-shape comparison of two digest sets.
    ///
    /// Only algorithms present in *both* sets participate. Digests are compared
    /// case-insensitively because third-party tools emit upper-case hex.
    pub fn matches(&self, other: &Self) -> bool {
        if !self.sha256.eq_ignore_ascii_case(&other.sha256) {
            return false;
        }
        match (&self.sha512, &other.sha512) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => true,
        }
    }
}

/// Incremental multi-algorithm hasher.
#[derive(Debug, Default)]
pub struct MultiHasher {
    sha256: Sha256,
    sha512: Option<Sha512>,
    bytes: u64,
}

impl MultiHasher {
    /// Creates a hasher. SHA-256 is always enabled; SHA-512 is opt-in.
    pub fn new(with_sha512: bool) -> Self {
        Self {
            sha256: Sha256::new(),
            sha512: if with_sha512 {
                Some(Sha512::new())
            } else {
                None
            },
            bytes: 0,
        }
    }

    /// Creates a hasher enabling every algorithm in `algorithms`.
    pub fn for_algorithms(algorithms: &[HashAlgorithm]) -> Self {
        Self::new(algorithms.contains(&HashAlgorithm::Sha512))
    }

    /// Feeds a chunk into every enabled digest.
    ///
    /// The byte counter saturates rather than wrapping; a wrapped length would
    /// be recorded in the manifest as a false artifact size.
    pub fn update(&mut self, chunk: &[u8]) {
        self.sha256.update(chunk);
        if let Some(sha512) = self.sha512.as_mut() {
            sha512.update(chunk);
        }
        self.bytes = self.bytes.saturating_add(chunk.len() as u64);
    }

    /// Number of bytes hashed so far.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Consumes the hasher and returns the lower-case hex digests.
    pub fn finish(self) -> HashReport {
        HashReport {
            bytes: self.bytes,
            digests: DigestSet {
                sha256: hex(&self.sha256.finalize()),
                sha512: self.sha512.map(|h| hex(&h.finalize())),
            },
        }
    }
}

/// Result of hashing a byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashReport {
    /// Number of bytes consumed.
    pub bytes: u64,
    /// Computed digests.
    pub digests: DigestSet,
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail; the result is discarded deliberately.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Hashes an arbitrary reader with bounded memory use.
///
/// `progress` is invoked with the running byte total after each block so that a
/// caller can drive a progress bar without the hashing loop knowing about the
/// UI. Cancellation is checked once per block, giving a worst-case latency of
/// one buffer.
pub fn hash_reader<R: Read>(
    reader: &mut R,
    with_sha512: bool,
    cancel: &CancellationToken,
    progress: &mut dyn FnMut(u64),
) -> Result<HashReport> {
    let mut hasher = MultiHasher::new(with_sha512);
    let mut buffer = vec![0u8; HASH_BUFFER_SIZE];
    loop {
        cancel.check()?;
        let read = reader
            .read(&mut buffer)
            .map_err(|source| Error::io("read", "<stream>", source))?;
        if read == 0 {
            break;
        }
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| Error::InvalidData("reader reported an impossible length".into()))?;
        hasher.update(chunk);
        progress(hasher.bytes());
    }
    Ok(hasher.finish())
}

/// Hashes a file on disk, opening it read-only.
///
/// The file is never opened for writing, so hashing an original evidence file
/// cannot alter it.
pub fn hash_file(
    path: &Path,
    with_sha512: bool,
    cancel: &CancellationToken,
    progress: &mut dyn FnMut(u64),
) -> Result<HashReport> {
    let file = File::open(path).ctx("open", path)?;
    let mut reader = BufReader::with_capacity(HASH_BUFFER_SIZE, file);
    hash_reader(&mut reader, with_sha512, cancel, progress).map_err(|e| match e {
        Error::Io {
            operation, source, ..
        } => Error::io(operation, path, source),
        other => other,
    })
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

    /// Reference vectors from FIPS 180-4.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const EMPTY_SHA512: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    fn digest_of(data: &[u8]) -> HashReport {
        let mut cursor = std::io::Cursor::new(data.to_vec());
        hash_reader(&mut cursor, true, &CancellationToken::new(), &mut |_| {}).unwrap()
    }

    #[test]
    fn matches_known_vectors() {
        let empty = digest_of(b"");
        assert_eq!(empty.digests.sha256, EMPTY_SHA256);
        assert_eq!(empty.digests.sha512.as_deref(), Some(EMPTY_SHA512));
        assert_eq!(empty.bytes, 0);

        let abc = digest_of(b"abc");
        assert_eq!(abc.digests.sha256, ABC_SHA256);
        assert_eq!(abc.digests.sha512.as_deref(), Some(ABC_SHA512));
        assert_eq!(abc.bytes, 3);
    }

    #[test]
    fn sha512_is_optional() {
        let mut cursor = std::io::Cursor::new(b"abc".to_vec());
        let report =
            hash_reader(&mut cursor, false, &CancellationToken::new(), &mut |_| {}).unwrap();
        assert_eq!(report.digests.sha256, ABC_SHA256);
        assert!(report.digests.sha512.is_none());
    }

    #[test]
    fn chunked_input_matches_single_shot() {
        // Larger than the read buffer, so the streaming loop runs many times.
        let data: Vec<u8> = (0..(HASH_BUFFER_SIZE * 2 + 12345))
            .map(|i| (i % 251) as u8)
            .collect();

        let streamed = digest_of(&data);

        let mut incremental = MultiHasher::new(true);
        for chunk in data.chunks(7919) {
            incremental.update(chunk);
        }
        let incremental = incremental.finish();

        assert_eq!(streamed, incremental);
        assert_eq!(streamed.bytes, data.len() as u64);
    }

    #[test]
    fn hashes_files_without_loading_them_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.raw");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"abc").unwrap();
        file.sync_all().unwrap();

        let mut observed = Vec::new();
        let report = hash_file(&path, true, &CancellationToken::new(), &mut |total| {
            observed.push(total);
        })
        .unwrap();

        assert_eq!(report.digests.sha256, ABC_SHA256);
        assert_eq!(observed, vec![3]);
    }

    #[test]
    fn missing_file_reports_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.raw");
        let err = hash_file(&path, false, &CancellationToken::new(), &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("absent.raw"), "{err}");
    }

    #[test]
    fn cancellation_stops_hashing() {
        let data = vec![0u8; HASH_BUFFER_SIZE * 4];
        let mut cursor = std::io::Cursor::new(data);
        let token = CancellationToken::new();
        token.cancel();
        let err = hash_reader(&mut cursor, false, &token, &mut |_| {}).unwrap_err();
        assert!(matches!(err, Error::Cancelled));
    }

    #[test]
    fn digest_sets_compare_case_insensitively() {
        let lower = DigestSet {
            sha256: ABC_SHA256.to_owned(),
            sha512: None,
        };
        let upper = DigestSet {
            sha256: ABC_SHA256.to_uppercase(),
            sha512: None,
        };
        assert!(lower.matches(&upper));
    }

    #[test]
    fn digest_sets_detect_mismatch() {
        let a = DigestSet {
            sha256: ABC_SHA256.to_owned(),
            sha512: None,
        };
        let b = DigestSet {
            sha256: EMPTY_SHA256.to_owned(),
            sha512: None,
        };
        assert!(!a.matches(&b));
    }

    #[test]
    fn sha512_mismatch_is_detected_when_both_present() {
        let a = DigestSet {
            sha256: ABC_SHA256.to_owned(),
            sha512: Some(ABC_SHA512.to_owned()),
        };
        let b = DigestSet {
            sha256: ABC_SHA256.to_owned(),
            sha512: Some(EMPTY_SHA512.to_owned()),
        };
        assert!(!a.matches(&b));
    }

    #[test]
    fn algorithm_parsing_round_trips() {
        assert_eq!(
            "sha256".parse::<HashAlgorithm>().unwrap(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            "SHA-512".parse::<HashAlgorithm>().unwrap(),
            HashAlgorithm::Sha512
        );
        assert!("md5".parse::<HashAlgorithm>().is_err());
        assert!("".parse::<HashAlgorithm>().is_err());
    }
}
