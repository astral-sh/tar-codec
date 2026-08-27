from __future__ import annotations

import io
import tarfile
from dataclasses import dataclass
from typing import TYPE_CHECKING

import tar_codec

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer, WriteableBuffer


@dataclass(frozen=True)
class ArchiveEntry:
    name: str
    data: bytes = b""
    kind: bytes = tarfile.REGTYPE
    link_name: str = ""
    pax_headers: tuple[tuple[str, str], ...] = ()


def make_archive(
    entries: tuple[ArchiveEntry, ...], *, archive_format: int = tarfile.PAX_FORMAT
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=archive_format) as archive:
        for entry in entries:
            metadata = tarfile.TarInfo(entry.name)
            metadata.type, metadata.linkname = entry.kind, entry.link_name
            metadata.mode = 0o644
            metadata.mtime, metadata.pax_headers = 0, dict(entry.pax_headers)
            regular = entry.kind in (tarfile.REGTYPE, tarfile.AREGTYPE)
            metadata.size = len(entry.data) if regular else 0
            archive.addfile(metadata, io.BytesIO(entry.data) if regular else None)
    return output.getvalue()


def read_archive(archive_bytes: bytes) -> dict[str, bytes | None]:
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        return {
            member.name: payload.read()
            if (payload := archive.extractfile(member)) is not None
            else None
            for member in archive
        }


def member_payload(member: tar_codec.Member) -> tar_codec.MemberPayload:
    if member.payload is None:
        raise AssertionError("expected an archive member with a payload")
    return member.payload


class ShortReader:
    def __init__(self, source: bytes, *, maximum_read: int = 7) -> None:
        self.source, self.maximum_read = io.BytesIO(source), maximum_read

    def read(self, size: int = -1) -> bytes:
        return self.source.read(
            min(size if size >= 0 else self.maximum_read, self.maximum_read)
        )


class ShortReadIntoReader(io.BytesIO):
    def __init__(self, source: bytes, *, maximum_read: int = 47) -> None:
        super().__init__(source)
        self.maximum_read = maximum_read

    def readinto(self, buffer: WriteableBuffer, /) -> int:
        return super().readinto(memoryview(buffer)[: self.maximum_read])


class ShortWriter(io.BytesIO):
    def __init__(self, *, maximum_write: int = 11) -> None:
        super().__init__()
        self.maximum_write = maximum_write

    def write(self, data: ReadableBuffer, /) -> int:
        return super().write(memoryview(data)[: self.maximum_write])


class StreamCallbackError(Exception):
    pass
