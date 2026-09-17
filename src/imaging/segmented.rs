//! Segmented raw image creation.
//!
//! Splits a raw image into sequentially numbered segments (`.001`, `.002`, …),
//! the convention understood by Autopsy, The Sleuth Kit and EnCase for split
//! raw evidence. The concatenation of the segments is byte-identical to the
//! source, which the conversion proves by hashing the source stream as it is
//! read and recording that digest alongside the per-segment digests.
//!
//! The source is opened read-only and is never modified. Segments are new
//! derived artifacts; the original stays exactly where it was.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::acquisition::backend::ProgressSink;
use crate::error::{Error, IoResultExt, Result};
use crate::evidence::manifest::{ArtifactRole, EvidenceClass};
use crate::evidence::store::{EvidenceStore, FinishedArtifact};
use crate::hashing::{DigestSet, MultiHasher};
use crate::util::cancel::CancellationToken;

/// Default segment size. 2 GiB stays below the 4 GiB limit of FAT32 transfer
/// media while keeping the segment count manageable for large images.
pub const DEFAULT_SEGMENT_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Smallest segment size accepted.
pub const MIN_SEGMENT_SIZE: u64 = 1024 * 1024;

/// Highest segment number representable with a three-digit extension.
pub const MAX_SEGMENTS: u32 = 999;

/// Read block size.
const READ_BUFFER_SIZE: usize = 1024 * 1024;

/// Result of a segmentation run.
#[derive(Debug)]
pub struct SegmentationResult {
    pub segments: Vec<FinishedArtifact>,
    /// Digest of the source stream as read during conversion.
    pub source_digests: DigestSet,
    pub total_bytes: u64,
}

/// Splits `source` into segments inside the store's `derived/` directory.
///
/// `base_name` is the segment set's stem; segment *n* is written as
/// `<base_name>.NNN`. Returns an error before writing anything if the source
/// would need more than [`MAX_SEGMENTS`] segments.
pub fn segment_image(
    store: &EvidenceStore,
    source: &Path,
    base_name: &str,
    segment_size: u64,
    with_sha512: bool,
    cancel: &CancellationToken,
    progress: &mut dyn ProgressSink,
) -> Result<SegmentationResult> {
    if segment_size < MIN_SEGMENT_SIZE {
        return Err(Error::Usage(format!(
            "segment size must be at least {MIN_SEGMENT_SIZE} bytes"
        )));
    }

    let metadata = std::fs::symlink_metadata(source).ctx("inspect", source)?;
    if metadata.file_type().is_symlink() {
        return Err(Error::Destination(format!(
            "`{}` is a symbolic link; refusing to follow it",
            source.display()
        )));
    }
    if !metadata.is_file() {
        return Err(Error::InvalidData(format!(
            "`{}` is not a regular file",
            source.display()
        )));
    }
    let source_size = metadata.len();

    let planned = planned_segment_count(source_size, segment_size)?;
    store.ensure_space(source_size, 2)?;

    let file = File::open(source).ctx("open", source)?;
    let mut reader = BufReader::with_capacity(READ_BUFFER_SIZE, file);
    let mut buffer = vec![0u8; READ_BUFFER_SIZE];

    let mut source_hasher = MultiHasher::new(with_sha512);
    let mut segments: Vec<FinishedArtifact> = Vec::new();
    let mut index: u32 = 1;
    let mut writer = open_segment(store, base_name, index, with_sha512)?;
    let mut segment_bytes: u64 = 0;
    let mut total_bytes: u64 = 0;

    progress.start(Some(source_size));

    loop {
        cancel.check()?;
        let read = reader.read(&mut buffer).ctx("read", source)?;
        if read == 0 {
            break;
        }
        let mut chunk = buffer.get(..read).unwrap_or(&[]);
        source_hasher.update(chunk);

        // A read block may straddle a segment boundary, so it is split.
        while !chunk.is_empty() {
            let remaining_in_segment = segment_size.saturating_sub(segment_bytes);
            if remaining_in_segment == 0 {
                let finished = writer.finish_complete()?;
                segments.push(finished.with_segment_index(index));
                index = index
                    .checked_add(1)
                    .ok_or_else(|| Error::InvalidData("segment index overflow".into()))?;
                if index > MAX_SEGMENTS {
                    return Err(Error::Usage(format!(
                        "segmenting `{}` would need more than {MAX_SEGMENTS} segments; use a \
                         larger --segment-size",
                        source.display()
                    )));
                }
                writer = open_segment(store, base_name, index, with_sha512)?;
                segment_bytes = 0;
                continue;
            }

            let take = usize::try_from(remaining_in_segment)
                .unwrap_or(usize::MAX)
                .min(chunk.len());
            let (head, tail) = chunk.split_at(take);
            writer.write_chunk(head)?;
            segment_bytes = segment_bytes.saturating_add(head.len() as u64);
            total_bytes = total_bytes.saturating_add(head.len() as u64);
            chunk = tail;
        }

        progress.update(total_bytes);
    }

    let finished = writer.finish_complete()?;
    segments.push(finished.with_segment_index(index));
    progress.finish(total_bytes);

    if total_bytes != source_size {
        return Err(Error::Integrity(format!(
            "read {total_bytes} bytes from `{}` but the file reported {source_size} bytes; \
             the source changed during conversion",
            source.display()
        )));
    }
    debug_assert!(segments.len() as u64 <= u64::from(planned).max(1));

    Ok(SegmentationResult {
        segments,
        source_digests: source_hasher.finish().digests,
        total_bytes,
    })
}

/// Number of segments a source of `source_size` will produce.
///
/// An empty source still produces one (empty) segment, so the segment set is
/// never an empty directory that later looks like data loss.
pub fn planned_segment_count(source_size: u64, segment_size: u64) -> Result<u32> {
    if segment_size == 0 {
        return Err(Error::Usage(
            "segment size must be greater than zero".into(),
        ));
    }
    let count = source_size.div_ceil(segment_size).max(1);
    let count = u32::try_from(count).map_err(|_| {
        Error::Usage("the requested segment size produces too many segments".into())
    })?;
    if count > MAX_SEGMENTS {
        return Err(Error::Usage(format!(
            "the requested segment size would produce {count} segments, more than the \
             {MAX_SEGMENTS} that three-digit extensions allow; use a larger --segment-size"
        )));
    }
    Ok(count)
}

/// Segment file name for index `n`, for example `image.003`.
pub fn segment_file_name(base_name: &str, index: u32) -> String {
    format!("{base_name}.{index:03}")
}

fn open_segment(
    store: &EvidenceStore,
    base_name: &str,
    index: u32,
    with_sha512: bool,
) -> Result<crate::evidence::store::ArtifactWriter> {
    store.create_artifact(
        EvidenceClass::Derived,
        &segment_file_name(base_name, index),
        ArtifactRole::ImageSegment,
        "raw-segmented",
        with_sha512,
    )
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
    use crate::acquisition::backend::NullProgress;
    use crate::hashing::hash_file;

    fn store_with_source(content: &[u8]) -> (tempfile::TempDir, EvidenceStore, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();
        let source = store.root().join("original").join("image.raw");
        std::fs::write(&source, content).unwrap();
        (dir, store, source)
    }

    fn concatenated(store: &EvidenceStore, segments: &[FinishedArtifact]) -> Vec<u8> {
        let mut out = Vec::new();
        for segment in segments {
            let path = store.root().join(
                segment
                    .relative_path
                    .replace('/', std::path::MAIN_SEPARATOR_STR),
            );
            out.extend_from_slice(&std::fs::read(&path).unwrap());
        }
        out
    }

    #[test]
    fn splits_into_the_expected_number_of_segments() {
        let content: Vec<u8> = (0..(MIN_SEGMENT_SIZE * 2 + 500) as usize)
            .map(|i| (i % 251) as u8)
            .collect();
        let (_guard, store, source) = store_with_source(&content);

        let result = segment_image(
            &store,
            &source,
            "image",
            MIN_SEGMENT_SIZE,
            false,
            &CancellationToken::new(),
            &mut NullProgress,
        )
        .unwrap();

        assert_eq!(result.segments.len(), 3);
        assert_eq!(result.total_bytes, content.len() as u64);
        assert_eq!(result.segments[0].relative_path, "derived/image.001");
        assert_eq!(result.segments[1].relative_path, "derived/image.002");
        assert_eq!(result.segments[2].relative_path, "derived/image.003");
        assert_eq!(result.segments[0].size_bytes, MIN_SEGMENT_SIZE);
        assert_eq!(result.segments[1].size_bytes, MIN_SEGMENT_SIZE);
        assert_eq!(result.segments[2].size_bytes, 500);
        assert_eq!(result.segments[0].segment_index, Some(1));
    }

    #[test]
    fn concatenation_reproduces_the_source_exactly() {
        let content: Vec<u8> = (0..(MIN_SEGMENT_SIZE as usize * 2 + 12_345))
            .map(|i| (i % 253) as u8)
            .collect();
        let (_guard, store, source) = store_with_source(&content);

        let result = segment_image(
            &store,
            &source,
            "image",
            MIN_SEGMENT_SIZE,
            true,
            &CancellationToken::new(),
            &mut NullProgress,
        )
        .unwrap();

        assert_eq!(concatenated(&store, &result.segments), content);

        let source_digest =
            hash_file(&source, true, &CancellationToken::new(), &mut |_| {}).unwrap();
        assert_eq!(result.source_digests, source_digest.digests);
    }

    #[test]
    fn leaves_the_source_untouched() {
        let content = vec![0x5au8; MIN_SEGMENT_SIZE as usize + 10];
        let (_guard, store, source) = store_with_source(&content);
        let before = std::fs::read(&source).unwrap();

        segment_image(
            &store,
            &source,
            "image",
            MIN_SEGMENT_SIZE,
            false,
            &CancellationToken::new(),
            &mut NullProgress,
        )
        .unwrap();

        assert_eq!(std::fs::read(&source).unwrap(), before);
        assert!(source.exists());
    }

    #[test]
    fn an_empty_source_produces_one_empty_segment() {
        let (_guard, store, source) = store_with_source(b"");
        let result = segment_image(
            &store,
            &source,
            "image",
            MIN_SEGMENT_SIZE,
            false,
            &CancellationToken::new(),
            &mut NullProgress,
        )
        .unwrap();
        assert_eq!(result.segments.len(), 1);
        assert_eq!(result.segments[0].size_bytes, 0);
        assert_eq!(result.total_bytes, 0);
    }

    #[test]
    fn a_source_smaller_than_one_segment_is_copied_whole() {
        let (_guard, store, source) = store_with_source(b"small image");
        let result = segment_image(
            &store,
            &source,
            "image",
            MIN_SEGMENT_SIZE,
            false,
            &CancellationToken::new(),
            &mut NullProgress,
        )
        .unwrap();
        assert_eq!(result.segments.len(), 1);
        assert_eq!(concatenated(&store, &result.segments), b"small image");
    }

    #[test]
    fn rejects_an_undersized_segment_size() {
        let (_guard, store, source) = store_with_source(b"data");
        let err = segment_image(
            &store,
            &source,
            "image",
            1024,
            false,
            &CancellationToken::new(),
            &mut NullProgress,
        )
        .unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 2);
    }

    #[test]
    fn refuses_to_overwrite_existing_segments() {
        let (_guard, store, source) = store_with_source(b"data");
        std::fs::write(store.root().join("derived").join("image.001"), b"old").unwrap();

        let err = segment_image(
            &store,
            &source,
            "image",
            MIN_SEGMENT_SIZE,
            false,
            &CancellationToken::new(),
            &mut NullProgress,
        )
        .unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 6);
        assert_eq!(
            std::fs::read(store.root().join("derived").join("image.001")).unwrap(),
            b"old"
        );
    }

    #[test]
    fn cancellation_stops_segmentation() {
        let content = vec![0u8; MIN_SEGMENT_SIZE as usize * 2];
        let (_guard, store, source) = store_with_source(&content);
        let token = CancellationToken::new();
        token.cancel();

        let err = segment_image(
            &store,
            &source,
            "image",
            MIN_SEGMENT_SIZE,
            false,
            &token,
            &mut NullProgress,
        )
        .unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 130);
    }

    #[test]
    fn plans_segment_counts_correctly() {
        assert_eq!(planned_segment_count(0, 1024).unwrap(), 1);
        assert_eq!(planned_segment_count(1, 1024).unwrap(), 1);
        assert_eq!(planned_segment_count(1024, 1024).unwrap(), 1);
        assert_eq!(planned_segment_count(1025, 1024).unwrap(), 2);
        assert_eq!(planned_segment_count(4096, 1024).unwrap(), 4);
    }

    #[test]
    fn rejects_plans_exceeding_the_segment_limit() {
        assert!(planned_segment_count(u64::MAX, MIN_SEGMENT_SIZE).is_err());
        assert!(planned_segment_count(1000 * 1024, 1024).is_err());
        assert!(planned_segment_count(1024, 0).is_err());
    }

    #[test]
    fn segment_names_are_zero_padded() {
        assert_eq!(segment_file_name("image", 1), "image.001");
        assert_eq!(segment_file_name("image", 42), "image.042");
        assert_eq!(segment_file_name("image", 999), "image.999");
    }
}
