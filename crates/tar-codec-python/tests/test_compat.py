from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import unittest
from typing import Literal

import tar_codec

from _support import ArchiveEntry, member_payload

Compression = Literal["gz", "bz2", "xz"]
CompressedStream = gzip.GzipFile | bz2.BZ2File | lzma.LZMAFile

COMPRESSIONS: tuple[Compression, ...] = ("gz", "bz2", "xz")
ENTRIES = (
    ArchiveEntry("directory/hello.txt", b"hello from a compressed archive"),
    ArchiveEntry("directory/" + "p" * 120, bytes(range(256)) * 17),
    ArchiveEntry("empty.txt"),
)
EXPECTED: dict[str, bytes] = {entry.name: entry.data for entry in ENTRIES}


def compressed_stream(
    stream: io.BytesIO, compression: Compression, mode: Literal["rb", "wb"]
) -> CompressedStream:
    match compression:
        case "gz":
            return gzip.GzipFile(fileobj=stream, mode=mode)
        case "bz2":
            return bz2.BZ2File(stream, mode)
        case "xz":
            return lzma.LZMAFile(stream, mode)


def tarfile_writer(stream: io.BytesIO, compression: Compression) -> tarfile.TarFile:
    match compression:
        case "gz":
            return tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.PAX_FORMAT)
        case "bz2":
            return tarfile.open(fileobj=stream, mode="w:bz2", format=tarfile.PAX_FORMAT)
        case "xz":
            return tarfile.open(fileobj=stream, mode="w:xz", format=tarfile.PAX_FORMAT)


class TarfileCompatibilityTests(unittest.TestCase):
    def test_tarfile_reads_compressed_tar_codec_archives(self) -> None:
        for compression in COMPRESSIONS:
            with self.subTest(compression=compression):
                output = io.BytesIO()
                with compressed_stream(output, compression, "wb") as compressed:
                    with tar_codec.Builder(compressed) as archive:
                        for entry in ENTRIES:
                            archive.add_file(entry.name, entry.data)

                with tarfile.open(
                    fileobj=io.BytesIO(output.getvalue()), mode="r:*"
                ) as archive:
                    actual = {
                        member.name: payload.read()
                        if (payload := archive.extractfile(member)) is not None
                        else None
                        for member in archive
                    }
                self.assertEqual(actual, EXPECTED)

    def test_tar_codec_reads_compressed_tarfile_archives(self) -> None:
        for compression in COMPRESSIONS:
            with self.subTest(compression=compression):
                output = io.BytesIO()
                with tarfile_writer(output, compression) as archive:
                    for entry in ENTRIES:
                        metadata = tarfile.TarInfo(entry.name)
                        metadata.size = len(entry.data)
                        archive.addfile(metadata, io.BytesIO(entry.data))

                actual: dict[str, bytes | memoryview | None] = {}
                with compressed_stream(
                    io.BytesIO(output.getvalue()), compression, "rb"
                ) as decompressed:
                    with tar_codec.TarArchive(decompressed) as archive:
                        for member in archive:
                            actual[member.path] = (
                                member_payload(member).read()
                                if member.payload is not None
                                else None
                            )
                self.assertEqual(actual, EXPECTED)
