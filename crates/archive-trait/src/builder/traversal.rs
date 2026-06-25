//! Bounded filesystem traversal for recursive archive building.
//!
//! Directory walking is synchronous filesystem work, so [`TraversalStream`]
//! runs [`WalkDir`] on Tokio's blocking pool and sends typed entries back to the
//! async builder. This lets traversal overlap with payload reads and archive
//! writes without blocking the async executor.
//!
//! The producer sends entries in batches rather than one at a time. The channel
//! holds one completed batch while the producer fills the next one, bounding
//! lookahead while amortizing channel wakeups.
//!
//! [`WalkDir`] is configured for deterministic depth-first traversal with
//! directories before their contents and never follows symbolic links.
//! Depending on [`super::BuilderPolicy`], source links are rejected or reported
//! as link entries whose textual targets are preserved without applying
//! extraction policy.

use std::{
    io,
    path::{Path, PathBuf},
};

use thiserror::Error;
use tokio::{sync::mpsc, task::JoinHandle};
use walkdir::{DirEntry, IntoIter, WalkDir};

use super::SymlinkPolicy;
use crate::name::NameValidation;

/// Number of filesystem entries grouped into one producer batch.
///
/// This is an internal performance tuning knob. Larger batches reduce channel
/// overhead but increase traversal lookahead and delay late source errors.
pub(crate) const DIRECTORY_TRAVERSAL_BATCH_ENTRIES: usize = 256;
/// Number of completed batches allowed to wait for the builder.
///
/// The producer may also be filling one additional batch locally.
const DIRECTORY_TRAVERSAL_BUFFER_BATCHES: usize = 1;

/// One source filesystem entry normalized for recursive archive building.
#[derive(Debug)]
pub(crate) struct TraversalEntry {
    /// Source path used when opening regular files or reporting errors.
    pub(crate) source: PathBuf,
    /// Normalized archive path beneath the recursive root basename.
    pub(crate) archive_path: String,
    /// Supported filesystem kind and any kind-specific traversal metadata.
    pub(crate) kind: TraversalKind,
}

/// Filesystem kinds supported by recursive archive building.
#[derive(Debug)]
pub(crate) enum TraversalKind {
    /// A real directory.
    Directory,
    /// A real regular file.
    Regular,
    /// A symbolic link represented by its UTF-8 textual target.
    SymbolicLink { target: String },
}

/// Asynchronous consumer side of one blocking directory traversal.
///
/// The channel and producer task stay private so the builder only depends on a
/// small typed stream abstraction.
pub(crate) struct TraversalStream {
    entries: mpsc::Receiver<Vec<TraversalEntry>>,
    task: JoinHandle<Result<(), TraversalError>>,
}

impl TraversalStream {
    /// Receives the next bounded batch, or [`None`] after traversal completes.
    pub(crate) async fn recv(&mut self) -> Option<Vec<TraversalEntry>> {
        self.entries.recv().await
    }

    /// Stops unused production and waits for the blocking traversal task.
    ///
    /// The receiver is dropped before awaiting the task so a producer blocked
    /// on a full channel can terminate when the builder exits early.
    pub(crate) async fn finish(self) -> Result<(), TraversalError> {
        drop(self.entries);
        self.task.await?
    }
}

/// A failure while traversing a recursive archive source.
#[derive(Debug, Error)]
pub enum TraversalError {
    /// A traversed source entry unexpectedly falls outside the recursive root.
    #[error("invalid archive path {path:?}: {reason}")]
    InvalidArchivePath {
        /// The source entry outside the recursive root.
        path: PathBuf,
        /// The failed traversal invariant.
        reason: &'static str,
    },
    /// An archive name was rejected by the configured builder policy.
    #[error("archive {context} rejected by builder policy: {value:?}")]
    NameRejected {
        /// The role of the rejected archive text.
        context: &'static str,
        /// The rejected UTF-8 value.
        value: String,
    },
    /// A source path component cannot be represented by this UTF-8-only builder.
    #[error("source path is not valid UTF-8: {path}")]
    NonUtf8SourcePath {
        /// The affected source filesystem path.
        path: PathBuf,
    },
    /// A symbolic-link target cannot be represented by this UTF-8-only builder.
    #[error("symbolic-link target is not valid UTF-8: {path}")]
    NonUtf8LinkTarget {
        /// The affected symbolic-link source path.
        path: PathBuf,
    },
    /// The recursive source directory is not a real directory.
    #[error("source directory is not a real directory: {path}")]
    SourceNotDirectory {
        /// The rejected source directory.
        path: PathBuf,
    },
    /// The builder policy rejects source symbolic links.
    #[error("symbolic link rejected by builder policy: {path}")]
    SymbolicLinkRejected {
        /// The rejected symbolic link.
        path: PathBuf,
    },
    /// The recursive source contains a filesystem node outside the supported subset.
    #[error("unsupported filesystem entry type: {path}")]
    UnsupportedFilesystemType {
        /// The rejected source filesystem path.
        path: PathBuf,
    },
    /// A source traversal filesystem operation failed.
    #[error("failed to {operation} {path}: {source}")]
    Filesystem {
        /// The operation that failed.
        operation: &'static str,
        /// The affected source filesystem path.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The blocking traversal task failed to complete.
    #[error("failed to complete blocking directory traversal: {0}")]
    BlockingTask(#[from] tokio::task::JoinError),
}

/// Starts a bounded, blocking traversal beneath `source`.
///
/// The root basename is validated before spawning so rejected roots fail
/// without starting background work or producing entries.
pub(crate) fn stream_directory_entries(
    source: PathBuf,
    validation: NameValidation,
    symlink_policy: SymlinkPolicy,
) -> Result<TraversalStream, TraversalError> {
    let Some(archive_path) = source
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
    else {
        return Err(TraversalError::NonUtf8SourcePath {
            path: source.to_path_buf(),
        });
    };
    validate_name(&archive_path, validation, "member path")?;
    let (sender, receiver) = mpsc::channel(DIRECTORY_TRAVERSAL_BUFFER_BATCHES);
    // Await channel backpressure outside the blocking pool so source
    // preparation and asynchronous file I/O can always acquire a worker.
    let task = tokio::spawn(async move {
        let mut producer = TraversalProducer::new(source, archive_path, validation, symlink_policy);
        loop {
            let (next_producer, entries) =
                tokio::task::spawn_blocking(move || producer.next_batch()).await??;
            producer = next_producer;
            let Some(entries) = entries else {
                return Ok(());
            };
            if sender.send(entries).await.is_err() {
                return Ok(());
            }
        }
    });
    Ok(TraversalStream {
        entries: receiver,
        task,
    })
}

/// Blocking traversal state moved through one bounded worker task per batch.
struct TraversalProducer {
    source: PathBuf,
    archive_path: String,
    validation: NameValidation,
    symlink_policy: SymlinkPolicy,
    entries: IntoIter,
}

impl TraversalProducer {
    fn new(
        source: PathBuf,
        archive_path: String,
        validation: NameValidation,
        symlink_policy: SymlinkPolicy,
    ) -> Self {
        let entries = WalkDir::new(&source)
            .follow_links(false)
            .follow_root_links(false)
            .sort_by_file_name()
            .into_iter();
        Self {
            source,
            archive_path,
            validation,
            symlink_policy,
            entries,
        }
    }

    fn next_batch(mut self) -> Result<(Self, Option<Vec<TraversalEntry>>), TraversalError> {
        let mut entries = Vec::with_capacity(DIRECTORY_TRAVERSAL_BATCH_ENTRIES);
        while entries.len() < DIRECTORY_TRAVERSAL_BATCH_ENTRIES {
            let Some(entry) = self.entries.next() else {
                break;
            };
            let entry = entry.map_err(|error| {
                let path = error.path().unwrap_or(&self.source).to_path_buf();
                TraversalError::Filesystem {
                    operation: "traverse source directory",
                    path,
                    source: error.into(),
                }
            })?;
            entries.push(traversal_entry(
                &self.source,
                &self.archive_path,
                self.validation,
                self.symlink_policy,
                entry,
            )?);
        }
        let entries = if entries.is_empty() {
            None
        } else {
            Some(entries)
        };
        Ok((self, entries))
    }
}

/// Converts one [`WalkDir`] entry into the builder's supported filesystem model.
///
/// Preserved links retain their UTF-8 textual targets for framing; extraction
/// policy is left to archive consumers.
fn traversal_entry(
    source: &Path,
    archive_path: &str,
    validation: NameValidation,
    symlink_policy: SymlinkPolicy,
    entry: DirEntry,
) -> Result<TraversalEntry, TraversalError> {
    let path = entry.path();
    let file_type = entry.file_type();
    let kind = if file_type.is_dir() {
        TraversalKind::Directory
    } else if file_type.is_file() {
        TraversalKind::Regular
    } else if file_type.is_symlink() {
        if symlink_policy == SymlinkPolicy::Reject {
            return Err(TraversalError::SymbolicLinkRejected {
                path: path.to_path_buf(),
            });
        }
        let target = std::fs::read_link(path).map_err(|source| TraversalError::Filesystem {
            operation: "read symbolic link",
            path: path.to_path_buf(),
            source,
        })?;
        let Some(target) = target.to_str().map(str::to_owned) else {
            return Err(TraversalError::NonUtf8LinkTarget {
                path: path.to_path_buf(),
            });
        };
        validate_name(&target, validation, "symbolic-link target")?;
        TraversalKind::SymbolicLink { target }
    } else {
        return Err(TraversalError::UnsupportedFilesystemType {
            path: path.to_path_buf(),
        });
    };
    if entry.depth() == 0 && !matches!(&kind, TraversalKind::Directory) {
        return Err(TraversalError::SourceNotDirectory {
            path: source.to_path_buf(),
        });
    }
    let relative = path
        .strip_prefix(source)
        .map_err(|_| TraversalError::InvalidArchivePath {
            path: path.to_path_buf(),
            reason: "source entry is outside recursive root",
        })?;
    let archive_path = if relative.as_os_str().is_empty() {
        archive_path.to_owned()
    } else {
        join_archive_path(archive_path, relative, path, validation)?
    };
    Ok(TraversalEntry {
        source: entry.into_path(),
        archive_path,
        kind,
    })
}

fn join_archive_path(
    archive_path: &str,
    relative: &Path,
    source_path: &Path,
    validation: NameValidation,
) -> Result<String, TraversalError> {
    let mut joined = archive_path.to_owned();
    for component in relative {
        let Some(component) = component.to_str() else {
            return Err(TraversalError::NonUtf8SourcePath {
                path: source_path.to_path_buf(),
            });
        };
        joined.push('/');
        joined.push_str(component);
    }
    validate_name(&joined, validation, "member path")?;
    Ok(joined)
}

fn validate_name(
    name: &str,
    validation: NameValidation,
    context: &'static str,
) -> Result<(), TraversalError> {
    if validation.accepts(name) {
        Ok(())
    } else {
        Err(TraversalError::NameRejected {
            context,
            value: name.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_native_relative_paths_with_archive_separators() {
        let relative = Path::new("nested").join("file");
        assert!(matches!(
            join_archive_path("tree", &relative, &relative, NameValidation::Default),
            Ok(path) if path == "tree/nested/file"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn preserves_backslashes_in_source_path_components() {
        let relative = Path::new("nested\\file");
        assert!(matches!(
            join_archive_path(
                "tree",
                relative,
                relative,
                NameValidation::Default,
            ),
            Ok(path) if path == r"tree/nested\file"
        ));
    }
}
