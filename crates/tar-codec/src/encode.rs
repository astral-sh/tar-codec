//! Pure-pax tar encoding for the format-neutral archive builder.
//!
//! [`TarEncoder`] owns tar framing, payload padding, sequence numbers, and the
//! end marker. [`archive_trait::Builder`] supplies high-level entry addition
//! and recursive filesystem traversal. Compression remains the caller's
//! concern.

use std::io;

use archive_trait::{
    ArchiveBuilder, BuildError, EntryMetadata,
    builder::{BuildFailure, EntryPayload},
};
use tar_framing::{
    UstarKind,
    write::{
        FramingWriteError, PaxMember, end_marker_bytes, frame_pax_member_into, payload_padding,
    },
};
use thiserror::Error;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// A pure-pax format writer for use with [`ArchiveBuilder::builder`].
pub struct TarEncoder<W> {
    writer: W,
    sequence: u64,
    framing_buffer: Vec<u8>,
}

impl<W> TarEncoder<W> {
    /// Creates an encoder writing an uncompressed pax archive into `writer`.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            sequence: 0,
            framing_buffer: Vec::new(),
        }
    }
}

impl<W: AsyncWrite + Unpin> TarEncoder<W> {
    async fn write_member(
        &mut self,
        member: PaxMember<'_>,
    ) -> Result<(), BuildFailure<EncodeError>> {
        let next_sequence = self.sequence.checked_add(1).ok_or_else(|| {
            BuildFailure::recoverable(BuildError::Encoder(EncodeError::ArithmeticOverflow {
                context: "pax member sequence",
            }))
        })?;
        frame_pax_member_into(self.sequence, member, &mut self.framing_buffer)
            .map_err(EncodeError::Framing)
            .map_err(BuildError::Encoder)
            .map_err(BuildFailure::recoverable)?;
        if let Err(source) = self.writer.write_all(&self.framing_buffer).await {
            return Err(BuildFailure::poisoned(BuildError::Encoder(
                EncodeError::Write { source },
            )));
        }
        self.sequence = next_sequence;
        Ok(())
    }

    async fn write_payload(
        &mut self,
        payload: &mut EntryPayload<'_>,
    ) -> Result<(), BuildFailure<EncodeError>> {
        while let Some(chunk) = payload.next_chunk().await.map_err(BuildFailure::poisoned)? {
            self.write_bytes(chunk).await?;
        }
        let padding = payload_padding(payload.size());
        if !padding.is_empty() {
            self.write_bytes(padding).await?;
        }
        Ok(())
    }

    async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), BuildFailure<EncodeError>> {
        if let Err(source) = self.writer.write_all(bytes).await {
            return Err(BuildFailure::poisoned(BuildError::Encoder(
                EncodeError::Write { source },
            )));
        }
        Ok(())
    }
}

impl<W: AsyncWrite + Unpin> ArchiveBuilder for TarEncoder<W> {
    type Error = EncodeError;

    async fn finish_archive(&mut self) -> Result<(), BuildFailure<Self::Error>> {
        self.write_bytes(end_marker_bytes()).await
    }

    async fn write_file_member(
        &mut self,
        path: &str,
        payload: &mut EntryPayload<'_>,
        metadata: EntryMetadata,
    ) -> Result<(), BuildFailure<Self::Error>> {
        self.write_member(PaxMember {
            path,
            kind: UstarKind::Regular,
            size: payload.size(),
            link_path: None,
            executable: metadata.is_executable(),
        })
        .await?;
        self.write_payload(payload).await
    }

    async fn write_directory_member(
        &mut self,
        path: &str,
    ) -> Result<(), BuildFailure<Self::Error>> {
        self.write_member(PaxMember {
            path,
            kind: UstarKind::Directory,
            size: 0,
            link_path: None,
            executable: false,
        })
        .await
    }

    async fn write_symbolic_link_member(
        &mut self,
        path: &str,
        target: &str,
    ) -> Result<(), BuildFailure<Self::Error>> {
        self.write_member(PaxMember {
            path,
            kind: UstarKind::SymbolicLink,
            size: 0,
            link_path: Some(target),
            executable: false,
        })
        .await
    }
}

/// A tar-specific failure while creating a pure-pax archive.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// A wire-format member could not be framed.
    #[error(transparent)]
    Framing(#[from] FramingWriteError),
    /// Writing the output archive failed.
    #[error("failed to write archive output")]
    Write {
        /// The underlying writer error.
        #[source]
        source: io::Error,
    },
    /// A tar sequence computation exceeded this API's range.
    #[error("arithmetic overflow while computing {context}")]
    ArithmeticOverflow {
        /// The failed computation.
        context: &'static str,
    },
}
