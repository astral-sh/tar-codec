//! Python APIs for `tar-codec`.
//!
//! These APIs are intentionally only a subset of those in `tar-codec`,
//! and intentionally do not include any of the lower-level APIs exposed
//! by `tar-framing`.

use std::{
    collections::VecDeque,
    io as std_io,
    ops::Range,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex, TryLockError, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use pyo3::{
    IntoPyObjectExt,
    exceptions::{PyOverflowError, PyRuntimeError, PyTypeError, PyValueError},
    prelude::*,
    pybacked::PyBackedBytes,
    pyclass::{PyTraverseError, PyVisit},
    types::{PyBytes, PyMemoryView, PySlice},
};
use tar_codec::{
    Archive as NativeArchiveTrait, ArchiveBuilder as _, BuildError as NativeBuildError,
    Builder as NativeBuilder, DecodeError as NativeDecodeError, DecodePolicy as NativeDecodePolicy,
    EncodeError as NativeEncodeError, EntryMetadata as NativeEntryMetadata,
    ExtractError as NativeExtractError, FilePayload as NativeFilePayload, Member as NativeMember,
    MemberPayload as NativeMemberPayload, PaxDecodePolicy as NativePaxDecodePolicy,
    PaxVendorExtensionPolicy as NativePaxVendorExtensionPolicy, SpecialKind as NativeSpecialKind,
    TarArchive as NativeTarArchive, TarEncoder as NativeTarEncoder,
    TarMemberPayload as NativeTarMemberPayload,
    builder::{BuilderPolicy as NativeBuilderPolicy, SymlinkPolicy as NativeBuildSymlinkPolicy},
    extract::{
        ExtractPolicy as NativeExtractPolicy, LinkPolicy as NativeLinkPolicy,
        SymlinkPolicy as NativeExtractSymlinkPolicy, extract_blocking as native_extract_blocking,
    },
};
use tar_framing::{
    BLOCK_SIZE, DEFAULT_MAX_GLOBAL_PAX_EXTENSIONS_SIZE, DEFAULT_MAX_GNU_EXTENSION_SIZE,
    DEFAULT_MAX_PAX_EXTENSION_SIZE,
};
use tokio::{
    io::{AsyncRead, AsyncWriteExt as _, BufReader, ReadBuf},
    runtime::Runtime,
};

use crate::{
    InvalidatedPayloadError,
    io::{self, Input, Output, OutputTarget, Reader, into_python_io_error, original_python_error},
    runtime::Blocking,
};

const DEFAULT_READ_CHUNK_SIZE: usize = 64 * 1024;
const MEMBER_BATCH_SIZE: usize = 64;

/// Accesses a caller-owned stream while holding its ownership lock.
fn with_stream<T>(
    stream: &Mutex<Option<Arc<Py<PyAny>>>>,
    operation: impl FnOnce(&mut Option<Arc<Py<PyAny>>>) -> T,
) -> T {
    let mut stream = stream
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    operation(&mut stream)
}

/// Releases a caller-owned stream reference after unlocking its ownership slot.
fn release_stream(stream: &Mutex<Option<Arc<Py<PyAny>>>>) {
    let stream = with_stream(stream, Option::take);
    drop(stream);
}

/// An archive member's type.
#[pyclass(
    module = "tar_codec",
    eq,
    eq_int,
    rename_all = "SCREAMING_SNAKE_CASE",
    from_py_object
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemberKind {
    File,
    Directory,
    SymbolicLink,
    HardLink,
    CharacterDevice,
    BlockDevice,
    Fifo,
}

/// Symbolic-link handling when building an archive.
#[pyclass(
    module = "tar_codec",
    eq,
    eq_int,
    rename_all = "SCREAMING_SNAKE_CASE",
    from_py_object
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BuildSymlinkPolicy {
    Reject,
    Preserve,
}

impl From<BuildSymlinkPolicy> for NativeBuildSymlinkPolicy {
    fn from(policy: BuildSymlinkPolicy) -> Self {
        match policy {
            BuildSymlinkPolicy::Reject => Self::Reject,
            BuildSymlinkPolicy::Preserve => Self::Preserve,
        }
    }
}

/// Symbolic-link handling during extraction.
#[pyclass(
    module = "tar_codec",
    eq,
    eq_int,
    rename_all = "SCREAMING_SNAKE_CASE",
    from_py_object
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExtractSymlinkPolicy {
    Preserve,
    Skip,
    Reject,
}

impl From<ExtractSymlinkPolicy> for NativeExtractSymlinkPolicy {
    fn from(policy: ExtractSymlinkPolicy) -> Self {
        match policy {
            ExtractSymlinkPolicy::Preserve => Self::Preserve,
            ExtractSymlinkPolicy::Skip => Self::Skip,
            ExtractSymlinkPolicy::Reject => Self::Reject,
        }
    }
}

/// Policy for unknown vendor-namespaced pax records.
#[pyclass(module = "tar_codec", eq, frozen, from_py_object)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PaxVendorExtensionPolicy {
    policy: NativePaxVendorExtensionPolicy,
}

impl Default for PaxVendorExtensionPolicy {
    fn default() -> Self {
        Self {
            policy: NativePaxVendorExtensionPolicy::RejectUnknown,
        }
    }
}

#[pymethods]
impl PaxVendorExtensionPolicy {
    /// Rejects all unknown vendor-namespaced pax records.
    #[classattr]
    const REJECT_UNKNOWN: Self = Self {
        policy: NativePaxVendorExtensionPolicy::RejectUnknown,
    };

    /// Ignores all unknown vendor-namespaced pax records.
    #[classattr]
    const ALLOW_UNKNOWN: Self = Self {
        policy: NativePaxVendorExtensionPolicy::AllowUnknown,
    };

    /// Ignores only the supplied complete vendor-namespaced keywords.
    #[staticmethod]
    fn ignore(keywords: Vec<String>) -> Self {
        Self {
            policy: NativePaxVendorExtensionPolicy::ignore(keywords),
        }
    }

    fn __repr__(&self) -> String {
        format!("PaxVendorExtensionPolicy({:?})", self.policy)
    }
}

/// Options for decoding pax extensions.
#[pyclass(module = "tar_codec", frozen, get_all, from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PaxDecodePolicy {
    max_extension_size: u64,
    max_global_extensions_size: u64,
    allow_non_utf8_pax_vendor_values: bool,
    allow_global_pax_extensions: bool,
    vendor_extension_policy: PaxVendorExtensionPolicy,
    allow_duplicate_pax_records: bool,
    allow_global_pax_member_metadata: bool,
}

impl Default for PaxDecodePolicy {
    fn default() -> Self {
        Self {
            max_extension_size: DEFAULT_MAX_PAX_EXTENSION_SIZE,
            max_global_extensions_size: DEFAULT_MAX_GLOBAL_PAX_EXTENSIONS_SIZE,
            allow_non_utf8_pax_vendor_values: true,
            allow_global_pax_extensions: true,
            vendor_extension_policy: PaxVendorExtensionPolicy::default(),
            allow_duplicate_pax_records: false,
            allow_global_pax_member_metadata: false,
        }
    }
}

impl PaxDecodePolicy {
    fn native(self) -> NativePaxDecodePolicy {
        NativePaxDecodePolicy::default()
            .max_extension_size(self.max_extension_size)
            .max_global_extensions_size(self.max_global_extensions_size)
            .allow_non_utf8_pax_vendor_values(self.allow_non_utf8_pax_vendor_values)
            .allow_global_pax_extensions(self.allow_global_pax_extensions)
            .vendor_extension_policy(self.vendor_extension_policy.policy)
            .allow_duplicate_pax_records(self.allow_duplicate_pax_records)
            .allow_global_pax_member_metadata(self.allow_global_pax_member_metadata)
    }
}

#[pymethods]
impl PaxDecodePolicy {
    #[new]
    #[pyo3(signature = (
        *,
        max_extension_size = DEFAULT_MAX_PAX_EXTENSION_SIZE,
        max_global_extensions_size = DEFAULT_MAX_GLOBAL_PAX_EXTENSIONS_SIZE,
        allow_non_utf8_pax_vendor_values = true,
        allow_global_pax_extensions = true,
        vendor_extension_policy = None,
        allow_duplicate_pax_records = false,
        allow_global_pax_member_metadata = false
    ))]
    fn new(
        max_extension_size: u64,
        max_global_extensions_size: u64,
        allow_non_utf8_pax_vendor_values: bool,
        allow_global_pax_extensions: bool,
        vendor_extension_policy: Option<PyRef<'_, PaxVendorExtensionPolicy>>,
        allow_duplicate_pax_records: bool,
        allow_global_pax_member_metadata: bool,
    ) -> Self {
        Self {
            max_extension_size,
            max_global_extensions_size,
            allow_non_utf8_pax_vendor_values,
            allow_global_pax_extensions,
            vendor_extension_policy: vendor_extension_policy
                .map_or_else(PaxVendorExtensionPolicy::default, |policy| {
                    (*policy).clone()
                }),
            allow_duplicate_pax_records,
            allow_global_pax_member_metadata,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "PaxDecodePolicy(max_extension_size={}, max_global_extensions_size={}, allow_non_utf8_pax_vendor_values={}, allow_global_pax_extensions={}, vendor_extension_policy={}, allow_duplicate_pax_records={}, allow_global_pax_member_metadata={})",
            self.max_extension_size,
            self.max_global_extensions_size,
            self.allow_non_utf8_pax_vendor_values,
            self.allow_global_pax_extensions,
            self.vendor_extension_policy.__repr__(),
            self.allow_duplicate_pax_records,
            self.allow_global_pax_member_metadata,
        )
    }
}

/// Options for decoding tar archives.
#[pyclass(module = "tar_codec", frozen, get_all, from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct DecodePolicy {
    allow_gnu: bool,
    allow_all_nul_numeric_fields: bool,
    max_gnu_extension_size: u64,
    pax_policy: PaxDecodePolicy,
}

impl Default for DecodePolicy {
    fn default() -> Self {
        Self {
            allow_gnu: true,
            allow_all_nul_numeric_fields: true,
            max_gnu_extension_size: DEFAULT_MAX_GNU_EXTENSION_SIZE,
            pax_policy: PaxDecodePolicy::default(),
        }
    }
}

impl DecodePolicy {
    fn native(self) -> NativeDecodePolicy {
        NativeDecodePolicy::default()
            .allow_gnu(self.allow_gnu)
            .allow_all_nul_numeric_fields(self.allow_all_nul_numeric_fields)
            .max_gnu_extension_size(self.max_gnu_extension_size)
            .pax_policy(self.pax_policy.native())
    }
}

#[pymethods]
impl DecodePolicy {
    #[new]
    #[pyo3(signature = (
        *,
        allow_gnu = true,
        allow_all_nul_numeric_fields = true,
        max_gnu_extension_size = DEFAULT_MAX_GNU_EXTENSION_SIZE,
        pax_policy = None
    ))]
    fn new(
        allow_gnu: bool,
        allow_all_nul_numeric_fields: bool,
        max_gnu_extension_size: u64,
        pax_policy: Option<PyRef<'_, PaxDecodePolicy>>,
    ) -> Self {
        Self {
            allow_gnu,
            allow_all_nul_numeric_fields,
            max_gnu_extension_size,
            pax_policy: pax_policy
                .map_or_else(PaxDecodePolicy::default, |policy| (*policy).clone()),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "DecodePolicy(allow_gnu={}, allow_all_nul_numeric_fields={}, max_gnu_extension_size={}, pax_policy={})",
            self.allow_gnu,
            self.allow_all_nul_numeric_fields,
            self.max_gnu_extension_size,
            self.pax_policy.__repr__(),
        )
    }
}

/// Options for building tar archives.
#[pyclass(module = "tar_codec", frozen, get_all, from_py_object)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct BuilderPolicy {
    symlink_policy: BuildSymlinkPolicy,
    validate_names: bool,
}

impl Default for BuilderPolicy {
    fn default() -> Self {
        Self {
            symlink_policy: BuildSymlinkPolicy::Reject,
            validate_names: true,
        }
    }
}

impl BuilderPolicy {
    fn native(self) -> NativeBuilderPolicy {
        let mut policy = NativeBuilderPolicy::default().symlink_policy(self.symlink_policy.into());
        if !self.validate_names {
            policy = policy.name_validator(None);
        }
        policy
    }
}

#[pymethods]
impl BuilderPolicy {
    #[new]
    #[pyo3(signature = (*, symlink_policy = None, validate_names = true))]
    fn new(symlink_policy: Option<BuildSymlinkPolicy>, validate_names: bool) -> Self {
        Self {
            symlink_policy: symlink_policy.unwrap_or(BuildSymlinkPolicy::Reject),
            validate_names,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "BuilderPolicy(symlink_policy={:?}, validate_names={})",
            self.symlink_policy, self.validate_names
        )
    }
}

/// Options for extracting symbolic and hard links.
#[pyclass(module = "tar_codec", frozen, get_all, from_py_object)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct LinkPolicy {
    symlink_policy: ExtractSymlinkPolicy,
    allow_hard_links: bool,
    allow_ambient_targets: bool,
    allow_missing_targets: bool,
}

impl Default for LinkPolicy {
    fn default() -> Self {
        Self {
            symlink_policy: ExtractSymlinkPolicy::Preserve,
            allow_hard_links: false,
            allow_ambient_targets: false,
            allow_missing_targets: true,
        }
    }
}

impl LinkPolicy {
    fn native(self) -> NativeLinkPolicy {
        NativeLinkPolicy::default()
            .symlink_policy(self.symlink_policy.into())
            .allow_hard_links(self.allow_hard_links)
            .allow_ambient_targets(self.allow_ambient_targets)
            .allow_missing_targets(self.allow_missing_targets)
    }
}

#[pymethods]
impl LinkPolicy {
    #[new]
    #[pyo3(signature = (
        *,
        symlink_policy = None,
        allow_hard_links = false,
        allow_ambient_targets = false,
        allow_missing_targets = true
    ))]
    fn new(
        symlink_policy: Option<ExtractSymlinkPolicy>,
        allow_hard_links: bool,
        allow_ambient_targets: bool,
        allow_missing_targets: bool,
    ) -> Self {
        Self {
            symlink_policy: symlink_policy.unwrap_or(ExtractSymlinkPolicy::Preserve),
            allow_hard_links,
            allow_ambient_targets,
            allow_missing_targets,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "LinkPolicy(symlink_policy={:?}, allow_hard_links={}, allow_ambient_targets={}, allow_missing_targets={})",
            self.symlink_policy,
            self.allow_hard_links,
            self.allow_ambient_targets,
            self.allow_missing_targets,
        )
    }
}

/// Options for extracting tar archives.
#[pyclass(module = "tar_codec", frozen, get_all, from_py_object)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExtractPolicy {
    allow_overwrites: bool,
    validate_names: bool,
    link_policy: LinkPolicy,
}

impl Default for ExtractPolicy {
    fn default() -> Self {
        Self {
            allow_overwrites: true,
            validate_names: true,
            link_policy: LinkPolicy::default(),
        }
    }
}

impl ExtractPolicy {
    fn native(self) -> NativeExtractPolicy {
        let mut policy = NativeExtractPolicy::default()
            .allow_overwrites(self.allow_overwrites)
            .link_policy(self.link_policy.native());
        if !self.validate_names {
            policy = policy.name_validator(None);
        }
        policy
    }
}

#[pymethods]
impl ExtractPolicy {
    #[new]
    #[pyo3(signature = (*, allow_overwrites = true, validate_names = true, link_policy = None))]
    fn new(
        allow_overwrites: bool,
        validate_names: bool,
        link_policy: Option<PyRef<'_, LinkPolicy>>,
    ) -> Self {
        Self {
            allow_overwrites,
            validate_names,
            link_policy: link_policy.map_or_else(LinkPolicy::default, |policy| *policy),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "ExtractPolicy(allow_overwrites={}, validate_names={}, link_policy={})",
            self.allow_overwrites,
            self.validate_names,
            self.link_policy.__repr__(),
        )
    }
}

/// An archive reader that can discard in-memory payloads without copying.
struct ArchiveReader {
    inner: Reader,
    source: Arc<ArchiveSource>,
}

impl AsyncRead for ArchiveReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std_io::Result<()>> {
        if self.source.discarding.load(Ordering::Acquire)
            && let Some(result) = self.inner.discard(buffer)
        {
            return Poll::Ready(result);
        }

        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

/// An archive source and its active payload generation.
#[derive(Debug)]
struct ArchiveSource {
    // Payload handles may outlive the archive, but must not retain its input bytes.
    bytes: Weak<PyBackedBytes>,
    // Starting position of an archive read from an already-positioned BytesIO.
    offset: usize,
    // True only during payload.skip(); tells ArchiveReader to advance its
    // in-memory cursor without copying bytes already exposed directly.
    discarding: AtomicBool,
    // Generation of the currently readable member payload. Zero means no
    // active payload, so advancing or closing invalidates older handles.
    generation: AtomicU64,
    // Set when closing or extracting; unlike an inactive generation,
    // permanently rejects iteration, context entry, and direct payload reads.
    closed: AtomicBool,
}

impl ArchiveSource {
    fn payload(
        self: &Arc<Self>,
        bytes: &Arc<PyBackedBytes>,
        position: u64,
        size: u64,
        generation: u64,
    ) -> Option<Arc<DirectPayload>> {
        let range = self.payload_range(bytes, position, size)?;

        Some(Arc::new(DirectPayload {
            source: Arc::clone(self),
            range,
            offset: AtomicUsize::new(0),
            generation,
        }))
    }

    fn payload_range(
        &self,
        bytes: &PyBackedBytes,
        position: u64,
        size: u64,
    ) -> Option<Range<usize>> {
        let position = usize::try_from(position).ok()?.checked_add(BLOCK_SIZE)?;
        let size = usize::try_from(size).ok()?;
        let padded_len = size.checked_next_multiple_of(BLOCK_SIZE)?;
        let start = position.checked_add(self.offset)?;
        bytes.get(start..start.checked_add(padded_len)?)?;
        Some(start..start.checked_add(size)?)
    }

    fn activate(&self, generation: u64) {
        self.generation.store(generation, Ordering::Release);
    }

    fn invalidate(&self) {
        self.generation.store(0, Ordering::Release);
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.invalidate();
    }
}

/// A payload backed by its archive's original bytes.
#[derive(Debug)]
struct DirectPayload {
    source: Arc<ArchiveSource>,
    range: Range<usize>,
    offset: AtomicUsize,
    generation: u64,
}

impl DirectPayload {
    fn take(&self, limit: Option<usize>) -> PyResult<Range<usize>> {
        let mut offset = self.offset.load(Ordering::Acquire);

        loop {
            if self.source.closed.load(Ordering::Acquire) {
                return Err(PyRuntimeError::new_err("the archive is closed"));
            }

            if self.source.generation.load(Ordering::Acquire) != self.generation {
                return Err(invalidated_payload());
            }

            let remaining = self.range.len().saturating_sub(offset);
            let len = limit.unwrap_or(remaining).min(remaining);
            let next = offset.saturating_add(len);

            match self.offset.compare_exchange_weak(
                offset,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let start = self.range.start.saturating_add(offset);
                    return Ok(start..start.saturating_add(len));
                }
                Err(current) => offset = current,
            }
        }
    }

    fn read(&self, py: Python<'_>, limit: Option<usize>) -> PyResult<Py<PyMemoryView>> {
        let range = self.take(limit)?;

        // Existing memoryviews own their bytes; new reads require a live archive.
        let bytes = self
            .source
            .bytes
            .upgrade()
            .ok_or_else(invalidated_payload)?;
        let start = isize::try_from(range.start)
            .map_err(|_| PyOverflowError::new_err("the payload exceeds the supported size"))?;
        let end = isize::try_from(range.end)
            .map_err(|_| PyOverflowError::new_err("the payload exceeds the supported size"))?;

        Ok(PyMemoryView::from(&bytes.as_ref().into_bound_py_any(py)?)?
            .get_item(PySlice::new(py, start, end, 1))?
            .cast_into::<PyMemoryView>()?
            .unbind())
    }
}

/// Either a zero-copy in-memory payload or a generation-checked stream.
#[derive(Clone, Debug)]
enum Payload {
    Direct(Arc<DirectPayload>),
    Streaming(u64),
}

#[derive(Debug)]
struct MemberSnapshot {
    kind: MemberKind,
    path: String,
    size: Option<u64>,
    executable: Option<bool>,
    target: Option<String>,
    payload: Option<Payload>,
}

type MemberBatch = VecDeque<PyResult<MemberSnapshot>>;

type NativeArchive = NativeTarArchive<BufReader<ArchiveReader>>;

/// The state of an archive reader.
struct ArchiveState {
    archive: Option<NativeArchive>,
    input: Option<Input>,
    // The sole strong owner, cleared when archive input is no longer needed.
    bytes: Option<Arc<PyBackedBytes>>,
    policy: NativeDecodePolicy,
    generation: u64,
    payload_remaining: u64,
    buffer: Vec<u8>,
    offset: usize,
    iterated: bool,
}

impl ArchiveState {
    /// Opens the archive source when needed.
    fn open(&mut self, runtime: &Runtime, source: &Arc<ArchiveSource>) -> PyResult<()> {
        if self.archive.is_some() {
            return Ok(());
        }

        let input = self.input.take().ok_or_else(|| {
            PyRuntimeError::new_err("the archive has already been extracted or closed")
        })?;
        let reader = runtime
            .block_on(input.into_reader())
            .map_err(into_python_io_error)?;
        let capture = matches!(&reader, Reader::Stream(_));
        let capacity = if capture { DEFAULT_READ_CHUNK_SIZE } else { 0 };
        let reader = BufReader::with_capacity(
            capacity,
            ArchiveReader {
                inner: reader,
                source: Arc::clone(source),
            },
        );
        self.archive = Some(NativeTarArchive::new(reader).with_policy(self.policy.clone()));
        Ok(())
    }

    fn next(&mut self, runtime: &Runtime, source: &Arc<ArchiveSource>) -> PyResult<MemberBatch> {
        // EOF drops the reader to release its file handle; subsequent iteration stays exhausted.
        if self.iterated && self.archive.is_none() {
            self.bytes = None;
            return Ok(VecDeque::new());
        }

        self.open(runtime, source)?;
        self.iterated = true;
        let mut batch = VecDeque::with_capacity(MEMBER_BATCH_SIZE);

        loop {
            let archive = self.archive.as_mut().ok_or_else(|| {
                PyRuntimeError::new_err("the archive has already been extracted or closed")
            })?;
            let member = match runtime.block_on(archive.next_member()) {
                Ok(Some(member)) => member,
                Ok(None) => {
                    self.archive = None;
                    break;
                }
                Err(error) => {
                    batch.push_back(Err(map_decode_error(error)));
                    break;
                }
            };
            self.generation = self.generation.checked_add(1).ok_or_else(|| {
                PyOverflowError::new_err(
                    "the archive member generation exceeded its supported range",
                )
            })?;

            let (kind, metadata, size, executable, target) = match member {
                NativeMember::File {
                    metadata,
                    size,
                    executable,
                    ..
                } => (
                    MemberKind::File,
                    metadata,
                    Some(size),
                    Some(executable),
                    None,
                ),
                NativeMember::HardLink {
                    metadata,
                    target,
                    size,
                    ..
                } => (
                    MemberKind::HardLink,
                    metadata,
                    Some(size),
                    None,
                    Some(target),
                ),
                NativeMember::Directory { metadata } => {
                    (MemberKind::Directory, metadata, None, None, None)
                }
                NativeMember::SymbolicLink { metadata, target } => {
                    (MemberKind::SymbolicLink, metadata, None, None, Some(target))
                }
                NativeMember::Special { metadata, kind } => (
                    match kind {
                        NativeSpecialKind::CharacterDevice => MemberKind::CharacterDevice,
                        NativeSpecialKind::BlockDevice => MemberKind::BlockDevice,
                        NativeSpecialKind::Fifo => MemberKind::Fifo,
                    },
                    metadata,
                    None,
                    None,
                    None,
                ),
            };

            let payload = size.map(|size| {
                self.bytes
                    .as_ref()
                    .and_then(|bytes| {
                        source.payload(bytes, metadata.position, size, self.generation)
                    })
                    .map_or_else(|| Payload::Streaming(self.generation), Payload::Direct)
            });

            let snapshot = MemberSnapshot {
                kind,
                path: metadata.path,
                size,
                executable,
                target,
                payload,
            };

            if let Some(size) = size {
                self.payload_remaining = size;
                self.buffer.clear();
                self.offset = 0;
                if matches!(&snapshot.payload, Some(Payload::Direct(_))) {
                    source.discarding.store(true, Ordering::Release);
                    let result = runtime.block_on(archive.payload().skip());
                    source.discarding.store(false, Ordering::Release);
                    if let Err(error) = result {
                        batch.push_back(Err(map_decode_error(error)));
                        break;
                    }
                } else {
                    batch.push_back(Ok(snapshot));
                    break;
                }
            }
            batch.push_back(Ok(snapshot));
            if batch.len() == MEMBER_BATCH_SIZE || self.bytes.is_none() {
                break;
            }
        }

        if batch.is_empty() && self.archive.is_none() {
            self.bytes = None;
        }

        Ok(batch)
    }

    fn read_into(
        &mut self,
        runtime: &Runtime,
        source: &ArchiveSource,
        generation: u64,
        output: &mut [u8],
    ) -> PyResult<()> {
        if source.generation.load(Ordering::Acquire) != generation {
            return Err(invalidated_payload());
        }
        let archive = self.archive.as_mut().ok_or_else(invalidated_payload)?;
        let buffer = &mut self.buffer;
        let offset = &mut self.offset;
        let written = runtime
            .block_on(async {
                let mut written = 0;
                while written < output.len() {
                    if *offset == buffer.len() {
                        buffer.clear();
                        *offset = 0;
                        let read = archive
                            .payload()
                            .read_aligned(&mut output[written..])
                            .await?;
                        if read != 0 {
                            written += read;
                            continue;
                        }
                        let target = output
                            .len()
                            .div_ceil(4)
                            .clamp(DEFAULT_READ_CHUNK_SIZE, io::MAX_PYTHON_STREAM_READ_BYTES)
                            .min(output.len().saturating_sub(written));
                        if !archive.payload().next_chunk(buffer, target).await? {
                            break;
                        }
                    }
                    let available = buffer.len().saturating_sub(*offset);
                    let len = available.min(output.len().saturating_sub(written));
                    output[written..written + len].copy_from_slice(&buffer[*offset..*offset + len]);
                    *offset += len;
                    written += len;
                }
                Ok::<usize, NativeDecodeError>(written)
            })
            .map_err(map_decode_error)?;
        self.payload_remaining = self.payload_remaining.saturating_sub(written as u64);
        if written != output.len() {
            return Err(PyRuntimeError::new_err(
                "the archive payload ended before its declared size",
            ));
        }
        Ok(())
    }
}

struct ArchiveCursor {
    state: Blocking<ArchiveState>,
    source: Arc<ArchiveSource>,
    pending: Mutex<MemberBatch>,
}

/// An archive with direct access to its source bytes.
struct ExtractionArchive {
    archive: NativeArchive,
    source: Arc<ArchiveSource>,
    bytes: Option<Arc<PyBackedBytes>>,
}

/// An extraction payload with an optional source range.
struct ExtractionPayload<'a> {
    payload: NativeTarMemberPayload<'a, BufReader<ArchiveReader>>,
    source: &'a ArchiveSource,
    bytes: Option<&'a PyBackedBytes>,
    range: Option<Range<usize>>,
}

impl<'a> ExtractionPayload<'a> {
    fn new(
        payload: NativeTarMemberPayload<'a, BufReader<ArchiveReader>>,
        source: &'a ArchiveSource,
        bytes: Option<&'a PyBackedBytes>,
        position: u64,
        size: u64,
    ) -> Self {
        Self {
            payload,
            source,
            bytes,
            range: bytes.and_then(|bytes| source.payload_range(bytes, position, size)),
        }
    }
}

impl NativeMemberPayload for ExtractionPayload<'_> {
    type Error = NativeDecodeError;

    fn remaining_bytes(&self) -> Option<&[u8]> {
        self.bytes?.get(self.range.as_ref()?.clone())
    }

    async fn next_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, Self::Error> {
        let result = self.payload.next_chunk(buffer, target_len).await?;
        if result && let Some(range) = &mut self.range {
            range.start = range.start.saturating_add(buffer.len()).min(range.end);
        }
        Ok(result)
    }

    async fn skip(self) -> Result<(), Self::Error> {
        let direct = self.range.is_some();
        if direct {
            self.source.discarding.store(true, Ordering::Release);
        }
        let result = self.payload.skip().await;
        if direct {
            self.source.discarding.store(false, Ordering::Release);
        }
        result
    }
}

impl NativeArchiveTrait for ExtractionArchive {
    type Error = NativeDecodeError;
    type Payload<'a> = ExtractionPayload<'a>;

    async fn next_member<'a>(
        &'a mut self,
    ) -> Result<Option<NativeMember<Self::Payload<'a>>>, Self::Error> {
        let source = self.source.as_ref();
        let bytes = self.bytes.as_deref();
        Ok(self
            .archive
            .next_member()
            .await?
            .map(|member| match member {
                NativeMember::File {
                    metadata,
                    size,
                    executable,
                    payload,
                } => {
                    let payload =
                        ExtractionPayload::new(payload, source, bytes, metadata.position, size);
                    NativeMember::File {
                        metadata,
                        size,
                        executable,
                        payload,
                    }
                }
                NativeMember::HardLink {
                    metadata,
                    target,
                    size,
                    payload,
                } => {
                    let payload =
                        ExtractionPayload::new(payload, source, bytes, metadata.position, size);
                    NativeMember::HardLink {
                        metadata,
                        target,
                        size,
                        payload,
                    }
                }
                NativeMember::Directory { metadata } => NativeMember::Directory { metadata },
                NativeMember::SymbolicLink { metadata, target } => {
                    NativeMember::SymbolicLink { metadata, target }
                }
                NativeMember::Special { metadata, kind } => {
                    NativeMember::Special { metadata, kind }
                }
            }))
    }
}

/// A one-pass tar archive reader.
#[pyclass(module = "tar_codec", frozen)]
pub(crate) struct TarArchive {
    cursor: Arc<ArchiveCursor>,
    stream: Mutex<Option<Arc<Py<PyAny>>>>,
}

#[pymethods]
impl TarArchive {
    #[new]
    #[pyo3(signature = (source, policy = None))]
    fn new(
        py: Python<'_>,
        source: &Bound<'_, PyAny>,
        policy: Option<PyRef<'_, DecodePolicy>>,
    ) -> PyResult<Self> {
        let input = io::parse_input(py, source, io::InputPurpose::Archive)?;
        let open_immediately = matches!(&input, Input::Path(_));
        let stream = match &input {
            Input::Memory(input) => input.stream.as_ref().map(Arc::clone),
            Input::Stream(stream) => Some(Arc::clone(stream)),
            Input::Path(_) => None,
        };
        let (bytes, offset) = match &input {
            Input::Memory(input) => (Some(Arc::new(input.bytes.clone_ref(py))), input.position),
            Input::Path(_) | Input::Stream(_) => (None, 0),
        };
        let archive_source = Arc::new(ArchiveSource {
            bytes: bytes.as_ref().map_or_else(Weak::new, Arc::downgrade),
            offset,
            discarding: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        });
        let policy = policy.map_or_else(DecodePolicy::default, |policy| (*policy).clone());

        let cursor = Arc::new(ArchiveCursor {
            state: Blocking::new(ArchiveState {
                archive: None,
                input: Some(input),
                bytes,
                policy: policy.native(),
                generation: 0,
                payload_remaining: 0,
                buffer: Vec::new(),
                offset: 0,
                iterated: false,
            })?,
            source: archive_source,
            pending: Mutex::new(VecDeque::new()),
        });
        if open_immediately {
            cursor
                .state
                .with(py, |runtime, state| state.open(runtime, &cursor.source))?;
        }

        Ok(Self {
            cursor,
            stream: Mutex::new(stream),
        })
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        // Expose archive -> stream cycles to Python's garbage collector.
        with_stream(&self.stream, |stream| visit.call(stream.as_deref()))
    }

    fn __iter__(this: PyRef<'_, Self>) -> PyRef<'_, Self> {
        this
    }

    fn __next__(this: PyRef<'_, Self>) -> PyResult<Option<Member>> {
        let py = this.py();
        let cursor = Arc::clone(&this.cursor);
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(PyRuntimeError::new_err(
                "a tar stream callback cannot re-enter its active archive",
            ));
        }
        if cursor.source.closed.load(Ordering::Acquire) {
            return Err(PyRuntimeError::new_err("the archive is closed"));
        }
        let mut pending = loop {
            match cursor.pending.try_lock() {
                Ok(pending) => break pending,
                Err(TryLockError::WouldBlock) => py.detach(|| drop(cursor.pending.lock())),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(PyRuntimeError::new_err("the tar member cursor is poisoned"));
                }
            }
        };
        cursor.source.invalidate();
        if pending.is_empty() {
            *pending = cursor
                .state
                .with(py, |runtime, state| state.next(runtime, &cursor.source))?;
        }
        let snapshot = pending.pop_front().transpose()?;
        drop(pending);
        let Some(snapshot) = snapshot else {
            release_stream(&this.stream);
            return Ok(None);
        };
        if let Some(payload) = &snapshot.payload {
            let generation = match payload {
                Payload::Direct(payload) => payload.generation,
                Payload::Streaming(generation) => *generation,
            };
            cursor.source.activate(generation);
        }
        let has_stream = with_stream(&this.stream, |stream| stream.is_some());
        let archive = has_stream.then(|| Py::from(this));
        Ok(Some(Member::from_snapshot(snapshot, cursor, archive)))
    }

    /// Enters the archive context.
    fn __enter__(this: PyRef<'_, Self>) -> PyResult<PyRef<'_, Self>> {
        if this.cursor.source.closed.load(Ordering::Acquire) {
            return Err(PyRuntimeError::new_err("the archive is closed"));
        }
        Ok(this)
    }

    /// Closes the archive.
    fn __exit__(
        &self,
        py: Python<'_>,
        _exception_type: Option<&Bound<'_, PyAny>>,
        _exception: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.close(py)
    }

    /// Extracts the archive if member iteration has not started.
    #[pyo3(signature = (destination, policy = None))]
    fn extract_in(
        &self,
        py: Python<'_>,
        destination: PathBuf,
        policy: Option<PyRef<'_, ExtractPolicy>>,
    ) -> PyResult<()> {
        let policy = policy.map_or_else(ExtractPolicy::default, |policy| *policy);
        let result = self.cursor.state.with(py, move |runtime, state| {
            if state.iterated {
                return Err(PyRuntimeError::new_err(
                    "an archive cannot be extracted after member iteration has started",
                ));
            }
            let result = state.open(runtime, &self.cursor.source).and_then(|()| {
                let archive = state.archive.take().ok_or_else(|| {
                    PyRuntimeError::new_err("the archive has already been extracted or closed")
                })?;
                runtime
                    .block_on(native_extract_blocking(
                        ExtractionArchive {
                            archive,
                            source: Arc::clone(&self.cursor.source),
                            bytes: state.bytes.take(),
                        },
                        destination,
                        policy.native(),
                    ))
                    .map_err(map_extract_error)
            });
            self.cursor.source.close();
            state.bytes = None;
            Ok(result)
        })?;
        release_stream(&self.stream);
        result
    }

    /// Closes the archive without closing its source.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        self.cursor.state.with(py, |_, state| {
            if self.cursor.source.closed.load(Ordering::Acquire) {
                return Ok(());
            }
            self.cursor.source.close();
            state.archive = None;
            state.input = None;
            state.bytes = None;
            Ok(())
        })?;
        release_stream(&self.stream);
        Ok(())
    }
}

/// An archive member.
#[pyclass(module = "tar_codec", frozen)]
pub(crate) struct Member {
    #[pyo3(get)]
    kind: MemberKind,
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    size: Option<u64>,
    #[pyo3(get)]
    executable: Option<bool>,
    #[pyo3(get)]
    target: Option<String>,
    cursor: Arc<ArchiveCursor>,
    archive: Option<Py<TarArchive>>,
    payload: Option<Payload>,
}

impl Member {
    fn from_snapshot(
        snapshot: MemberSnapshot,
        cursor: Arc<ArchiveCursor>,
        archive: Option<Py<TarArchive>>,
    ) -> Self {
        Self {
            kind: snapshot.kind,
            path: snapshot.path,
            size: snapshot.size,
            executable: snapshot.executable,
            target: snapshot.target,
            cursor,
            archive,
            payload: snapshot.payload,
        }
    }
}

#[pymethods]
impl Member {
    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        // Expose the member -> archive -> stream ownership chain.
        visit.call(&self.archive)
    }

    #[getter]
    fn payload(&self, py: Python<'_>) -> Option<MemberPayload> {
        self.payload.as_ref().map(|payload| MemberPayload {
            cursor: Arc::clone(&self.cursor),
            archive: self.archive.as_ref().map(|archive| archive.clone_ref(py)),
            payload: payload.clone(),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Member(kind={:?}, path={:?}, size={:?})",
            self.kind, self.path, self.size
        )
    }
}

/// A payload cursor invalidated when member iteration advances.
#[pyclass(module = "tar_codec", frozen)]
pub(crate) struct MemberPayload {
    cursor: Arc<ArchiveCursor>,
    archive: Option<Py<TarArchive>>,
    payload: Payload,
}

impl MemberPayload {
    fn read_payload(&self, py: Python<'_>, limit: Option<usize>) -> PyResult<Py<PyMemoryView>> {
        let generation = match &self.payload {
            Payload::Direct(payload) => return payload.read(py, limit),
            Payload::Streaming(generation) => *generation,
        };

        let bytes = self.cursor.state.with(py, |runtime, state| {
            let payload_remaining = usize::try_from(state.payload_remaining)
                .map_err(|_| PyOverflowError::new_err("the payload exceeds the supported size"))?;
            let len = limit.unwrap_or(payload_remaining).min(payload_remaining);
            Python::attach(|py| {
                PyBytes::new_with(py, len, |output| {
                    py.detach(|| state.read_into(runtime, &self.cursor.source, generation, output))
                })
                .map(Bound::unbind)
            })
        })?;
        Ok(PyMemoryView::from(bytes.bind(py).as_any())?.unbind())
    }
}

#[pymethods]
impl MemberPayload {
    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        // Expose the payload -> archive -> stream ownership chain.
        visit.call(&self.archive)
    }

    /// Reads up to `size` bytes as a read-only memory view.
    #[pyo3(signature = (size = -1))]
    fn read(&self, py: Python<'_>, size: isize) -> PyResult<Py<PyMemoryView>> {
        let limit = match size {
            -1 => None,
            0.. => Some(usize::try_from(size).map_err(|_| {
                PyOverflowError::new_err("the requested payload size does not fit in memory")
            })?),
            _ => return Err(PyValueError::new_err("read size must be at least -1")),
        };

        self.read_payload(py, limit)
    }
}

fn invalidated_payload() -> PyErr {
    InvalidatedPayloadError::new_err(
        "the member payload is no longer active because the archive cursor advanced",
    )
}

fn map_decode_error(error: NativeDecodeError) -> PyErr {
    if let Some(original) = original_python_error(&error) {
        return original;
    }

    let position = match &error {
        NativeDecodeError::Framing(error) => error.position,
        NativeDecodeError::InvalidUtf8 { position, .. }
        | NativeDecodeError::PolicyViolation { position, .. } => *position,
    };
    let exception = crate::DecodeError::new_err(error.to_string());
    Python::attach(|py| {
        let _ = exception.value(py).setattr("position", position);
    });
    exception
}

fn map_extract_error(error: NativeExtractError<NativeDecodeError>) -> PyErr {
    original_python_error(&error).unwrap_or_else(|| crate::ExtractError::new_err(error.to_string()))
}

fn map_build_error(error: NativeBuildError<NativeEncodeError>) -> PyErr {
    original_python_error(&error).unwrap_or_else(|| match error {
        NativeBuildError::Encoder(error) => crate::EncodeError::new_err(error.to_string()),
        error => crate::BuildError::new_err(error.to_string()),
    })
}

struct BuilderState {
    target: Option<OutputTarget>,
    policy: NativeBuilderPolicy,
    builder: Option<NativeBuilder<NativeTarEncoder<Output>>>,
}

impl BuilderState {
    fn native(
        &mut self,
        runtime: &Runtime,
    ) -> PyResult<&mut NativeBuilder<NativeTarEncoder<Output>>> {
        if self.builder.is_none() {
            let target = self.target.take().ok_or_else(|| {
                PyRuntimeError::new_err("the archive builder has already been finalized")
            })?;
            let output = runtime
                .block_on(target.into_output())
                .map_err(into_python_io_error)?;
            self.builder = Some(
                NativeTarEncoder::new(output)
                    .builder()
                    .with_policy(self.policy),
            );
        }

        self.builder.as_mut().ok_or_else(|| {
            PyRuntimeError::new_err("the archive builder has already been finalized")
        })
    }

    fn close(&mut self, runtime: &Runtime) -> PyResult<()> {
        if self.builder.is_none() && self.target.is_none() {
            return Ok(());
        }

        self.native(runtime)?;
        let builder = self.builder.take().ok_or_else(|| {
            PyRuntimeError::new_err("the archive builder has already been finalized")
        })?;

        let mut output = runtime
            .block_on(builder.finish_into_inner())
            .map(NativeTarEncoder::into_inner)
            .map_err(map_build_error)?;
        // Native finalization writes the archive terminator but leaves sink
        // finalization to its caller; make buffered Python streams immediately readable.
        runtime.block_on(output.flush()).map_err(|source| {
            map_build_error(NativeBuildError::Encoder(NativeEncodeError::Write {
                source,
            }))
        })
    }

    fn abort(&mut self) {
        self.target = None;
        self.builder = None;
    }
}

/// A pax tar archive builder.
#[pyclass(module = "tar_codec", frozen)]
pub(crate) struct Builder {
    state: Blocking<BuilderState>,
    sink: Mutex<Option<Arc<Py<PyAny>>>>,
}

#[pymethods]
impl Builder {
    #[new]
    #[pyo3(signature = (sink, policy = None))]
    fn new(
        py: Python<'_>,
        sink: &Bound<'_, PyAny>,
        policy: Option<PyRef<'_, BuilderPolicy>>,
    ) -> PyResult<Self> {
        let target = io::parse_output(py, sink)?;
        let filesystem = matches!(&target, OutputTarget::Path(_));
        let sink = match &target {
            OutputTarget::Path(_) => None,
            OutputTarget::Stream(writer) => Some(Arc::clone(&writer.sink)),
        };
        let policy = policy.map_or_else(BuilderPolicy::default, |policy| *policy);
        let state = Blocking::new(BuilderState {
            target: Some(target),
            policy: policy.native(),
            builder: None,
        })?;
        if filesystem {
            state.with(py, |runtime, state| state.native(runtime).map(|_| ()))?;
        }
        Ok(Self {
            state,
            sink: Mutex::new(sink),
        })
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        // Expose builder -> stream cycles to Python's garbage collector.
        with_stream(&self.sink, |sink| visit.call(sink.as_deref()))
    }

    /// Enters the archive builder context.
    fn __enter__(this: PyRef<'_, Self>) -> PyResult<PyRef<'_, Self>> {
        this.state.with(this.py(), |_, state| {
            if state.builder.is_none() && state.target.is_none() {
                return Err(PyRuntimeError::new_err(
                    "the archive builder has already been finalized",
                ));
            }
            Ok(())
        })?;
        Ok(this)
    }

    /// Finalizes the archive unless the context raised an exception.
    fn __exit__(
        &self,
        py: Python<'_>,
        exception_type: Option<&Bound<'_, PyAny>>,
        _exception: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        if exception_type.is_some() {
            self.state.with(py, |_, state| {
                state.abort();
                Ok(())
            })?;
            release_stream(&self.sink);
            return Ok(());
        }

        self.close(py)
    }

    /// Adds a complete buffer or path, or exactly `size` bytes from a stream.
    #[pyo3(signature = (path, payload, *, size = None, executable = false))]
    fn add_file(
        &self,
        py: Python<'_>,
        path: PathBuf,
        payload: &Bound<'_, PyAny>,
        size: Option<u64>,
        executable: bool,
    ) -> PyResult<()> {
        let metadata = NativeEntryMetadata::default().executable(executable);
        let input = io::parse_input(py, payload, io::InputPurpose::Payload)?;

        let streaming = match &input {
            Input::Memory(input) => input.stream.is_some(),
            Input::Path(_) => false,
            Input::Stream(_) => true,
        };
        if streaming != size.is_some() {
            return Err(PyTypeError::new_err(if streaming {
                "a binary stream payload requires an explicit size"
            } else {
                "only binary stream payloads accept an explicit size"
            }));
        }

        let _source = if let Input::Memory(input) = &input
            && input.stream.is_none()
        {
            Some(io::PythonWriteSource::new(py, &input.bytes))
        } else {
            None
        };

        self.state.with(py, move |runtime, state| {
            let builder = state.native(runtime)?;
            runtime.block_on(add_file(builder, path, input, size, metadata))
        })
    }

    /// Adds a directory.
    fn add_directory(&self, py: Python<'_>, path: PathBuf) -> PyResult<()> {
        self.state.with(py, move |runtime, state| {
            runtime
                .block_on(state.native(runtime)?.add_directory(path))
                .map_err(map_build_error)
        })
    }

    /// Recursively adds a directory and its contents.
    fn add_directory_all(&self, py: Python<'_>, path: PathBuf) -> PyResult<()> {
        self.state.with(py, move |runtime, state| {
            runtime
                .block_on(state.native(runtime)?.add_directory_all(path))
                .map_err(map_build_error)
        })
    }

    /// Finalizes and flushes the archive without closing its sink.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let result = self
            .state
            .with(py, |runtime, state| Ok(state.close(runtime)))?;
        release_stream(&self.sink);
        result
    }
}

async fn add_file(
    builder: &mut NativeBuilder<NativeTarEncoder<Output>>,
    path: PathBuf,
    input: Input,
    size: Option<u64>,
    metadata: NativeEntryMetadata,
) -> PyResult<()> {
    if let Input::Memory(input) = &input
        && input.stream.is_none()
    {
        return builder
            .add_file(path, NativeFilePayload::from(&input.bytes[..]), metadata)
            .await
            .map_err(map_build_error);
    }

    let payload = match input {
        Input::Path(source) => NativeFilePayload::from_path(source)
            .await
            .map_err(into_python_io_error)?,
        input => {
            let size = size.ok_or_else(|| {
                PyTypeError::new_err("a binary stream payload requires an explicit size")
            })?;
            let reader = input.into_reader().await.map_err(into_python_io_error)?;
            NativeFilePayload::new(size, reader)
        }
    };
    builder
        .add_file(path, payload, metadata)
        .await
        .map_err(map_build_error)
}

/// Registers the Python archive classes.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<MemberKind>()?;
    module.add_class::<BuildSymlinkPolicy>()?;
    module.add_class::<ExtractSymlinkPolicy>()?;
    module.add_class::<PaxVendorExtensionPolicy>()?;
    module.add_class::<PaxDecodePolicy>()?;
    module.add_class::<DecodePolicy>()?;
    module.add_class::<BuilderPolicy>()?;
    module.add_class::<LinkPolicy>()?;
    module.add_class::<ExtractPolicy>()?;
    module.add_class::<TarArchive>()?;
    module.add_class::<Member>()?;
    module.add_class::<MemberPayload>()?;
    module.add_class::<Builder>()?;
    Ok(())
}
