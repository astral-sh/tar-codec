"""Tar archive encoding, decoding, and extraction."""

from __future__ import annotations

from os import PathLike
from typing import TYPE_CHECKING, BinaryIO, TypeAlias

from . import _tar_codec
from ._tar_codec import (
    BuildError as BuildError,
    Builder as Builder,
    BuilderPolicy as BuilderPolicy,
    BuildSymlinkPolicy as BuildSymlinkPolicy,
    DecodeError as DecodeError,
    DecodePolicy as DecodePolicy,
    EncodeError as EncodeError,
    ExtractError as ExtractError,
    ExtractPolicy as ExtractPolicy,
    ExtractSymlinkPolicy as ExtractSymlinkPolicy,
    InvalidatedPayloadError as InvalidatedPayloadError,
    LinkPolicy as LinkPolicy,
    Member as Member,
    MemberKind as MemberKind,
    MemberPayload as MemberPayload,
    PaxDecodePolicy as PaxDecodePolicy,
    PaxVendorExtensionPolicy as PaxVendorExtensionPolicy,
    TarArchive as TarArchive,
)

if TYPE_CHECKING:
    from ._tar_codec import ArchiveSink, ArchiveSource
else:
    ArchiveSource: TypeAlias = (
        bytes | bytearray | memoryview | str | PathLike[str] | BinaryIO
    )
    ArchiveSink: TypeAlias = str | PathLike[str] | BinaryIO

__version__ = _tar_codec.__version__

__all__ = (*_tar_codec.__all__, "ArchiveSource", "ArchiveSink")
