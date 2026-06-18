//! Single-task creation and replacement of validated small files.

use std::{
    io::{self, Write as _},
    path::Path,
};

use cap_std::fs::{Dir, File as CapFile, Metadata};

use super::{FileOpenMode, directory_is_empty, metadata_is_link, remove_file_or_symlink};
use crate::ExtractError;

/// Whether a buffered file may replace an existing destination leaf.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum BufferedFileReplacement {
    /// An existing leaf is a collision.
    Disallowed,
    /// An existing leaf may be replaced after no-follow inspection.
    Allowed,
    /// The leaf is an archive-owned file and may use the direct replacement path.
    ExpectedFile,
}

/// A failure while creating or replacing a validated buffered file.
pub(super) enum BufferedFileError {
    Collision,
    Filesystem {
        operation: &'static str,
        source: io::Error,
    },
}

impl BufferedFileError {
    fn filesystem(operation: &'static str, source: io::Error) -> Self {
        Self::Filesystem { operation, source }
    }

    pub(super) fn into_extract<E>(self, path: &Path) -> ExtractError<E> {
        match self {
            Self::Collision => ExtractError::PathCollision {
                path: path.to_owned(),
            },
            Self::Filesystem { operation, source } => {
                ExtractError::filesystem(operation, path.to_owned(), source)
            }
        }
    }
}

/// Creates or safely replaces and writes one fully validated small file.
pub(super) fn write_buffered_file(
    directory: &Dir,
    path: &Path,
    executable: bool,
    contents: &[u8],
    replacement: BufferedFileReplacement,
) -> Result<(), BufferedFileError> {
    // Unique destination access makes this the common duplicate-member path.
    // If the leaf changed unexpectedly, fall through to no-follow inspection.
    if replacement == BufferedFileReplacement::ExpectedFile && directory.remove_file(path).is_ok() {
        let file = open_new_file(directory, path, executable)
            .map_err(|source| BufferedFileError::filesystem("create file", source))?;
        return write_buffered_contents(file, contents);
    }

    let create_error = match open_new_file(directory, path, executable) {
        Ok(file) => return write_buffered_contents(file, contents),
        Err(error) => error,
    };
    let metadata = match directory.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(BufferedFileError::filesystem("create file", create_error));
        }
        Err(error) => return Err(BufferedFileError::filesystem("inspect", error)),
    };
    if replacement == BufferedFileReplacement::Disallowed {
        return Err(BufferedFileError::Collision);
    }
    remove_buffered_leaf(directory, path, &metadata)?;
    let file = open_new_file(directory, path, executable)
        .map_err(|source| BufferedFileError::filesystem("create file", source))?;
    write_buffered_contents(file, contents)
}

fn write_buffered_contents(mut file: CapFile, contents: &[u8]) -> Result<(), BufferedFileError> {
    file.write_all(contents)
        .map_err(|source| BufferedFileError::filesystem("write file", source))
}

fn open_new_file(directory: &Dir, path: &Path, executable: bool) -> io::Result<CapFile> {
    let options = FileOpenMode::CreateNew { executable }.options();
    directory.open_with(path, &options)
}

fn remove_buffered_leaf(
    directory: &Dir,
    path: &Path,
    metadata: &Metadata,
) -> Result<(), BufferedFileError> {
    if metadata.is_dir() && !metadata_is_link(metadata) {
        let is_empty = directory_is_empty(directory, path)
            .map_err(|source| BufferedFileError::filesystem("inspect directory", source))?;
        if !is_empty {
            return Err(BufferedFileError::Collision);
        }
        return directory
            .remove_dir(path)
            .map_err(|source| BufferedFileError::filesystem("remove directory", source));
    }

    remove_file_or_symlink(directory, path, metadata_is_link(metadata))
        .map_err(|source| BufferedFileError::filesystem("remove file", source))
}
