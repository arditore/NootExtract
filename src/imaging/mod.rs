//! Forensic image formats and conversion.
//!
//! Conversion always produces a new derived artifact. The source is opened
//! read-only and is never renamed, truncated or rewritten, and no conversion is
//! ever performed by changing a file extension: either the bytes are
//! restructured by this crate, or the work is delegated to an established
//! library and its output is hashed and manifested like any other artifact.

pub mod archive;
pub mod ewf;
pub mod format;
pub mod segmented;

pub use archive::{ExtractionOptions, ExtractionResult, SkippedEntry, extract_tar};
pub use ewf::{EwfConversion, EwfConverter, EwfParameters};
pub use format::{FormatEvidence, FormatProbe, ImageFormat, probe};
pub use segmented::{DEFAULT_SEGMENT_SIZE, SegmentationResult, segment_image};
