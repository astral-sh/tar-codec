from __future__ import annotations

import gc
import importlib.metadata
import io
import multiprocessing
import os
import sys
import tarfile
import tempfile
import unittest
import weakref
from multiprocessing.connection import Connection
from pathlib import Path
from tarfile import GNU_FORMAT
from types import SimpleNamespace
from typing import cast

import tar_codec
from tar_codec import ArchiveSink, ArchiveSource

from _support import (
    ArchiveEntry,
    ShortReadIntoReader,
    ShortReader,
    ShortWriter,
    StreamCallbackError,
    make_archive,
    member_payload,
    read_archive,
)


def raise_callback(message: str) -> None:
    raise StreamCallbackError(message)


def decode_member(source: ArchiveSource) -> tuple[str, memoryview]:
    member = next(tar_codec.TarArchive(source))
    return member.path, member_payload(member).read()


def memory_builder() -> tuple[io.BytesIO, tar_codec.Builder]:
    output = io.BytesIO()
    return output, tar_codec.Builder(output)


def decode_forked_archives(
    path: Path, inherited: tar_codec.TarArchive, connection: Connection
) -> None:
    member = next(inherited)
    inherited_entry = member.path, bytes(member_payload(member).read())
    with tar_codec.TarArchive(path) as archive:
        member = next(archive)
        connection.send(
            (inherited_entry, (member.path, bytes(member_payload(member).read())))
        )
    connection.close()


HELLO_MEMBER = ("hello", b"hello")
HELLO_ARCHIVE = make_archive((ArchiveEntry(*HELLO_MEMBER),))
GNU_ARCHIVE = make_archive((ArchiveEntry(*HELLO_MEMBER),), archive_format=GNU_FORMAT)
PAYLOAD_SOURCES = (
    ShortReader,
    ShortReadIntoReader,
    io.BytesIO,
    bytes,
    bytearray,
    memoryview,
)
FAILING_READINTO = SimpleNamespace(
    read=lambda _: b"", readinto=lambda _: raise_callback("readinto failed")
)


class CyclicStream(io.BytesIO):
    owner: object


class TrackedBytes(bytes):
    marker: io.BytesIO


class OversizedReader:
    def __init__(self, source: bytes, *, noncontiguous: bool) -> None:
        self.source = io.BytesIO(source)
        self.noncontiguous = noncontiguous

    def read(self, size: int) -> bytes | memoryview:
        if size < 1024 * 1024:
            return self.source.read(size)
        contents = self.source.read(size + 1)
        return memoryview(contents)[::-1] if self.noncontiguous else contents


class FailingFlush(io.BytesIO):
    def flush(self) -> None:
        raise_callback("flush failed")


class FailingLookup(io.BytesIO):
    @property
    def readinto(self) -> object:
        raise StreamCallbackError("lookup failed")


class ArchiveCodecTests(unittest.TestCase):
    def test_installs_dependency_free_archive_package(self) -> None:
        self.assertEqual(tar_codec.__version__, importlib.metadata.version("tar-codec"))
        self.assertFalse(importlib.metadata.requires("tar-codec"))

    def test_reads_sources_and_validates_payloads_and_decode_policies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.tar"
            path.write_bytes(HELLO_ARCHIVE)
            in_memory = (HELLO_ARCHIVE, GNU_ARCHIVE, io.BytesIO(HELLO_ARCHIVE))
            for source in (*in_memory, ShortReader(HELLO_ARCHIVE), path, str(path)):
                self.assertEqual(decode_member(source), HELLO_MEMBER)
            with self.assertRaises(FileNotFoundError):
                tar_codec.TarArchive(path.with_name("missing.tar"))
        for source_type, readonly in (
            (bytearray, False),
            (memoryview, False),
            (memoryview, True),
        ):
            mutable = bytearray(HELLO_ARCHIVE)
            source = source_type(mutable)
            if readonly and isinstance(source, memoryview):
                source = source.toreadonly()
            archive = tar_codec.TarArchive(source)
            mutable[0] ^= 1
            self.assertEqual(member_payload(next(archive)).read(), b"hello")

        def interleave(chunk: bytes) -> memoryview:
            return memoryview(b"".join(bytes((byte, 0)) for byte in chunk))[::2]

        for convert in (lambda chunk: memoryview(chunk).cast("H"), interleave):
            source = io.BytesIO(HELLO_ARCHIVE)
            reader = SimpleNamespace(
                read=lambda size, source=source: convert(source.read(min(size, 48)))
            )
            self.assertEqual(decode_member(cast(ArchiveSource, reader)), HELLO_MEMBER)

        contents = bytes(range(256)) * (64 * 1024 + 1)
        archive = make_archive((ArchiveEntry("large", contents),))
        member = next(tar_codec.TarArchive(archive))
        first, second = member_payload(member), member_payload(member)
        prefix = b"".join((first.read(17), second.read(65_545)))
        self.assertEqual(first.read(0), b"")
        self.assertEqual(b"".join((prefix, first.read())), contents)
        self.assertEqual((first.read(), second.read()), (b"", b""))
        truncated = archive[: tarfile.BLOCKSIZE + len(contents) - 1]
        missing_padding = HELLO_ARCHIVE[: tarfile.BLOCKSIZE + 5]
        oversized = tarfile.TarInfo("oversized")
        oversized.size = sys.maxsize
        for source in (
            truncated,
            io.BytesIO(truncated),
            missing_padding,
            oversized.tobuf(format=GNU_FORMAT),
        ):
            with self.assertRaises(tar_codec.DecodeError):
                member_payload(next(tar_codec.TarArchive(source))).read()

        corrupt, long_path = bytearray(HELLO_ARCHIVE), "nested/" + "p" * 120
        corrupt[0] ^= 1
        restricted_pax = tar_codec.DecodePolicy(
            pax_policy=tar_codec.PaxDecodePolicy(max_extension_size=0)
        )
        for source, policy in (
            (corrupt, None),
            (HELLO_ARCHIVE[:511], None),
            (GNU_ARCHIVE, tar_codec.DecodePolicy(allow_gnu=False)),
            (make_archive((ArchiveEntry(long_path, b"x"),)), restricted_pax),
        ):
            with self.assertRaises(tar_codec.DecodeError):
                next(tar_codec.TarArchive(source, policy))

    def test_forwards_vendor_pax_policies(self) -> None:
        vendor = "".join(("Ac", "me"))
        keyword = ".".join((vendor, "attribute"))
        archive = make_archive(
            (ArchiveEntry("file", pax_headers=((keyword, "value"),)),)
        )
        self.assertEqual(
            tar_codec.PaxDecodePolicy().vendor_extension_policy,
            tar_codec.PaxVendorExtensionPolicy.REJECT_UNKNOWN,
        )
        with self.assertRaises(tar_codec.DecodeError):
            next(tar_codec.TarArchive(archive))

        policy = tar_codec.DecodePolicy(
            pax_policy=tar_codec.PaxDecodePolicy(
                vendor_extension_policy=tar_codec.PaxVendorExtensionPolicy.ignore(
                    [vendor]
                )
            )
        )
        self.assertEqual(next(tar_codec.TarArchive(archive, policy)).path, "file")

    def test_streams_payloads_across_partial_reads(self) -> None:
        entries = (
            ArchiveEntry("prefix", b"p" * 2_048),
            ArchiveEntry("crossing", bytes(range(256)) * 4),
            ArchiveEntry("medium", bytes(range(256)) * 516),
            ArchiveEntry("trailing", b"tail"),
        )
        archive = make_archive(entries)
        source = ShortReadIntoReader(archive)
        reader = tar_codec.TarArchive(source)
        self.assertIs(iter(reader), reader)
        for entry in entries:
            with self.subTest(member=entry.name):
                member = next(reader)
                self.assertEqual(member.path, entry.name)
                if entry.name == "prefix":
                    with tempfile.TemporaryDirectory() as directory:
                        with self.assertRaisesRegex(RuntimeError, "iteration"):
                            reader.extract_in(directory)
                self.assertEqual(member_payload(member).read(), entry.data)
        reader.close()
        self.assertFalse(source.closed)

    @unittest.skipUnless(
        "fork" in multiprocessing.get_all_start_methods(),
        "process forking is unavailable",
    )
    def test_reinitializes_runtime_after_fork(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.tar"
            path.write_bytes(
                make_archive(
                    (ArchiveEntry("first", b"first"), ArchiveEntry("next", b"next"))
                )
            )
            inherited = tar_codec.TarArchive(path)
            self.assertEqual(member_payload(next(inherited)).read(), b"first")

            context = multiprocessing.get_context("fork")
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(
                target=decode_forked_archives, args=(path, inherited, sender)
            )
            process.start()
            sender.close()
            try:
                self.assertTrue(receiver.poll(10), "the forked child did not finish")
                self.assertEqual(
                    receiver.recv(),
                    (("next", b"next"), ("first", b"first")),
                )
                process.join(timeout=5)
                self.assertEqual(process.exitcode, 0)
            finally:
                if process.is_alive():
                    process.kill()
                    process.join(timeout=5)
                receiver.close()
                inherited.close()

            self.assertEqual(decode_member(path), ("first", b"first"))

    def test_reads_stable_views_from_in_memory_and_binary_stream_sources(self) -> None:
        contents = bytes(range(256)) * 33 + b"tail"
        archive_bytes = make_archive(
            (ArchiveEntry("first", contents), ArchiveEntry("next", b"tail"))
        )
        prefixed = io.BytesIO(b"prefix" + archive_bytes)
        prefixed.seek(len(b"prefix"))
        sources: tuple[tuple[str, ArchiveSource], ...] = (
            ("bytes", archive_bytes),
            ("immutable-memoryview", memoryview(archive_bytes)),
            (
                "sliced-memoryview",
                memoryview(b"prefix" + archive_bytes + b"suffix")[6:-6],
            ),
            ("bytes-io", io.BytesIO(archive_bytes)),
            ("positioned-bytes-io", prefixed),
            ("short-reader", ShortReader(archive_bytes, maximum_read=257)),
            ("short-readinto", ShortReadIntoReader(archive_bytes)),
        )

        for name, source in sources:
            with self.subTest(source=name):
                archive = tar_codec.TarArchive(source)
                payload = member_payload(next(archive))
                first = payload.read(17)
                remaining = payload.read(len(contents))

                self.assertIsInstance(first, memoryview)
                self.assertIsInstance(remaining, memoryview)
                self.assertTrue(first.readonly)
                self.assertTrue(remaining.readonly)
                if name == "immutable-memoryview":
                    self.assertTrue(first.obj is archive_bytes)
                self.assertEqual(first, contents[:17])
                self.assertEqual(remaining, contents[17:])
                self.assertEqual(member_payload(next(archive)).read(), b"tail")

                with self.assertRaises(tar_codec.InvalidatedPayloadError):
                    payload.read()

                archive.close()
                with self.assertRaisesRegex(RuntimeError, "the archive is closed"):
                    payload.read()
                self.assertEqual(first, contents[:17])
                self.assertEqual(remaining, contents[17:])
                if isinstance(source, io.BytesIO):
                    self.assertFalse(source.closed)

    def test_collects_stream_cycles_through_all_archive_objects(self) -> None:
        for stream_type in (io.BytesIO, CyclicStream):
            for kind in ("archive", "builder", "member", "payload"):
                with self.subTest(stream=stream_type.__name__, owner=kind):
                    stream = stream_type(HELLO_ARCHIVE)
                    if kind == "builder":
                        owner: object = tar_codec.Builder(stream)
                    else:
                        archive = tar_codec.TarArchive(stream)
                        match kind:
                            case "archive":
                                owner = archive
                            case "member":
                                owner = next(archive)
                            case "payload":
                                owner = member_payload(next(archive))
                        del archive

                    setattr(stream, "owner", owner)
                    reference = weakref.ref(stream)
                    del owner, stream
                    gc.collect()
                    self.assertIsNone(reference())

    def test_releases_caller_owned_streams_after_completion(self) -> None:
        corrupt = bytearray(HELLO_ARCHIVE)
        corrupt[2 * tarfile.BLOCKSIZE] ^= 1
        for kind in (
            "closed archive",
            "exhausted archive",
            "failed in-memory decoding",
            "failed streaming decoding",
            "extracted archive",
            "failed extraction",
            "failed initialization",
            "builder",
            "aborted builder",
            "failed builder",
        ):
            with self.subTest(owner=kind):
                match kind:
                    case "failed builder":
                        stream_type: type[io.BytesIO] = FailingFlush
                    case "failed initialization":
                        stream_type = FailingLookup
                    case "failed streaming decoding":
                        stream_type = ShortReadIntoReader
                    case _:
                        stream_type = io.BytesIO
                stream = stream_type(
                    bytes(corrupt) if kind.endswith("decoding") else HELLO_ARCHIVE
                )
                reference = weakref.ref(stream)

                match kind:
                    case "closed archive":
                        archive = tar_codec.TarArchive(stream)
                        payload = member_payload(next(archive))
                        archive.close()
                        with self.assertRaises(RuntimeError):
                            payload.read()
                    case "exhausted archive":
                        archive = tar_codec.TarArchive(stream)
                        self.assertEqual(len(list(archive)), 1)
                    case "failed in-memory decoding" | "failed streaming decoding":
                        archive = tar_codec.TarArchive(stream)
                        self.assertEqual(member_payload(next(archive)).read(), b"hello")
                        with self.assertRaises(tar_codec.DecodeError):
                            next(archive)
                    case "extracted archive":
                        archive = tar_codec.TarArchive(stream)
                        with tempfile.TemporaryDirectory() as directory:
                            archive.extract_in(directory)
                    case "failed extraction":
                        archive = tar_codec.TarArchive(stream)
                        with tempfile.TemporaryDirectory() as directory:
                            destination = Path(directory) / "destination"
                            destination.write_bytes(b"not a directory")
                            with self.assertRaises(tar_codec.ExtractError):
                                archive.extract_in(destination)
                    case "failed initialization":
                        archive = tar_codec.TarArchive(stream)
                        with tempfile.TemporaryDirectory() as directory:
                            with self.assertRaisesRegex(
                                StreamCallbackError, "lookup failed"
                            ):
                                archive.extract_in(directory)
                        with self.assertRaisesRegex(RuntimeError, "closed"):
                            next(archive)
                    case "aborted builder":
                        builder = tar_codec.Builder(stream)
                        with self.assertRaisesRegex(StreamCallbackError, "body failed"):
                            with builder:
                                raise_callback("body failed")
                    case "failed builder":
                        builder = tar_codec.Builder(stream)
                        with self.assertRaisesRegex(
                            StreamCallbackError, "flush failed"
                        ):
                            builder.close()
                    case _:
                        builder = tar_codec.Builder(stream)
                        builder.close()

                self.assertFalse(stream.closed)
                del stream
                gc.collect()
                self.assertIsNone(reference())

    def test_releases_in_memory_archive_bytes_after_completion(self) -> None:
        for operation in ("close", "exhaust", "extract"):
            with self.subTest(operation=operation):
                marker = io.BytesIO()
                source = TrackedBytes(HELLO_ARCHIVE)
                source.marker = marker
                reference = weakref.ref(marker)
                archive = tar_codec.TarArchive(source)

                match operation:
                    case "close":
                        payload = member_payload(next(archive))
                        archive.close()
                        with self.assertRaises(RuntimeError):
                            payload.read()
                    case "exhaust":
                        self.assertEqual(len(list(archive)), 1)
                    case _:
                        with tempfile.TemporaryDirectory() as directory:
                            archive.extract_in(directory)

                del source, marker
                gc.collect()
                self.assertIsNone(reference())

    def test_releases_files_when_archive_iteration_is_exhausted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.tar"
            path.write_bytes(HELLO_ARCHIVE)
            archive = tar_codec.TarArchive(path)
            members = list(archive)
            self.assertEqual(members[0].path, "hello")
            for _ in range(2):
                with self.assertRaises(StopIteration):
                    next(archive)

            if os.name != "nt":
                descriptor_root = Path("/proc/self/fd")
                if not descriptor_root.exists():
                    descriptor_root = Path("/dev/fd")
                identity = path.stat()
                for descriptor in descriptor_root.iterdir():
                    try:
                        current = descriptor.stat()
                    except OSError:
                        continue
                    self.assertNotEqual(
                        (current.st_dev, current.st_ino),
                        (identity.st_dev, identity.st_ino),
                    )

    def test_context_managers_finalize_builders_and_close_archives(self) -> None:
        output = io.BytesIO()
        with tar_codec.Builder(output) as builder:
            builder.add_file("file", b"payload")
        builder.close()
        self.assertEqual(read_archive(output.getvalue()), {"file": b"payload"})
        self.assertFalse(output.closed)
        with self.assertRaises(RuntimeError):
            builder.add_file("another", b"payload")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.tar"
            path.write_bytes(b"existing contents")
            with tar_codec.Builder(path) as builder:
                self.assertEqual(path.read_bytes(), b"")
                builder.add_file("file", b"payload")
            self.assertEqual(read_archive(path.read_bytes()), {"file": b"payload"})

        source = io.BytesIO(output.getvalue())
        with tar_codec.TarArchive(source) as archive:
            payload = member_payload(next(archive))
            self.assertEqual(payload.read(), b"payload")
        self.assertFalse(source.closed)
        with self.assertRaises(RuntimeError):
            payload.read()
        archive.close()
        with self.assertRaises(RuntimeError):
            with archive:
                pass

        output = io.BytesIO()
        with self.assertRaisesRegex(StreamCallbackError, "body failed"):
            with tar_codec.Builder(output) as builder:
                builder.add_file("file", b"payload")
                raise_callback("body failed")
        self.assertFalse(output.closed)
        self.assertFalse(output.getvalue().endswith(bytes(tarfile.BLOCKSIZE * 2)))
        builder.close()
        with self.assertRaises(RuntimeError):
            with builder:
                pass

    def test_validates_callbacks_reentry_and_original_exceptions(self) -> None:
        for name, source in (
            ("read", SimpleNamespace(read=lambda _: raise_callback("read failed"))),
            ("readinto", FAILING_READINTO),
            ("lookup", FailingLookup()),
        ):
            with self.assertRaisesRegex(StreamCallbackError, f"{name}.*failed"):
                decode_member(cast(ArchiveSource, source))

        with self.assertRaises(TypeError):
            tar_codec.TarArchive(cast(ArchiveSource, SimpleNamespace(read=None)))
        for result, exception in zip(
            (sys.maxsize, -1, None), (ValueError, OverflowError, TypeError), strict=True
        ):
            source = SimpleNamespace(
                read=lambda _: b"",
                readinto=lambda _, value=result: value,
            )
            with self.assertRaises(exception):
                decode_member(cast(ArchiveSource, source))

        large_archive = make_archive((ArchiveEntry("large", b"x" * (5 * 1024 * 1024)),))
        for noncontiguous in (False, True):
            with self.subTest(noncontiguous=noncontiguous):
                source = OversizedReader(large_archive, noncontiguous=noncontiguous)
                payload = member_payload(next(tar_codec.TarArchive(source)))
                with self.assertRaisesRegex(ValueError, "requested size"):
                    payload.read()

        _, builder = memory_builder()
        nested = tar_codec.TarArchive(HELLO_ARCHIVE)
        self.addCleanup(nested.close)
        for callback in ("read", "readinto", "write"):
            for operation in (
                lambda: builder.add_directory("nested"),
                lambda: tar_codec.Builder(io.BytesIO()),
                lambda: next(nested),
            ):
                methods = {callback: lambda _, action=operation: action()}
                if callback == "readinto":
                    methods["read"] = lambda _: b""
                source = SimpleNamespace(**methods)
                with self.assertRaises(RuntimeError):
                    if callback == "write":
                        writer = cast(ArchiveSink, source)
                        tar_codec.Builder(writer).add_file("x", b"x")
                    else:
                        decode_member(cast(ArchiveSource, source))

    def test_builds_interoperable_archives_and_finishes_all_outputs(self) -> None:
        output, builder = memory_builder()
        long_path = "directory/" + "p" * 120
        builder.add_file("hello", b"hello")
        builder.add_directory("directory")
        builder.add_file("directory/run", b"run", executable=True)
        builder.add_file(long_path, b"PAX payload")
        builder.close()
        archive = output.getvalue()
        expected = {"hello": b"hello", "directory": None}
        expected.update({"directory/run": b"run", long_path: b"PAX payload"})
        self.assertEqual(read_archive(archive), expected)
        for member in tar_codec.TarArchive(archive):
            contents = expected[member.path]
            payload = member.payload
            self.assertEqual(member.size, None if contents is None else len(contents))
            self.assertEqual(
                member.executable,
                None if contents is None else member.path == "directory/run",
            )
            self.assertEqual(None if payload is None else payload.read(), contents)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as reader:
            self.assertTrue(reader.getmember("directory/run").mode & 0o111)
            self.assertEqual(reader.getmember(long_path).pax_headers["path"], long_path)

        underlying = io.BytesIO()
        buffered = io.BufferedWriter(underlying)
        builder = tar_codec.Builder(buffered)
        builder.add_file("buffered", b"payload")
        builder.close()
        self.assertEqual(read_archive(underlying.getvalue()), {"buffered": b"payload"})
        self.assertFalse(buffered.closed)

        contents = bytes(range(256)) * 1025
        with tempfile.TemporaryDirectory() as directory:
            for sink_index, kind in enumerate(("path", "string", "stream")):
                path = Path(directory) / f"{kind}.tar"
                writer = io.BytesIO()
                sink = (path, str(path), writer)[sink_index]
                builder = tar_codec.Builder(sink)
                builder.add_file("large", contents)
                builder.close()
                data = writer.getvalue() if kind == "stream" else path.read_bytes()
                self.assertEqual(read_archive(data), {"large": contents})

            source = Path(directory) / "source"
            (source / "nested").mkdir(parents=True)
            (source / "nested/file").write_bytes(b"payload")
            output, builder = memory_builder()
            builder.add_directory_all(source)
            builder.close()
            self.assertEqual(
                read_archive(output.getvalue())["source/nested/file"], b"payload"
            )

    def test_handles_streaming_sources_buffers_and_partial_writers(self) -> None:
        contents = bytes(range(256)) * 16
        for source_type in PAYLOAD_SOURCES:
            source = source_type(contents)
            output, builder = memory_builder()
            expected = {"all": contents}
            if isinstance(source, (bytes, bytearray, memoryview)):
                self.assertRaisesRegex(
                    TypeError,
                    "size",
                    builder.add_file,
                    "sized",
                    source,
                    size=len(contents),
                )
                builder.add_file("all", source)
            else:
                self.assertRaisesRegex(
                    TypeError, "size", builder.add_file, "unsized", source
                )
                builder.add_file("all", source, size=len(contents))
                builder.add_file("prefix", type(source)(contents), size=5)
                expected["prefix"] = contents[:5]
            builder.close()
            self.assertEqual(read_archive(output.getvalue()), expected)
            if isinstance(source, io.BytesIO):
                self.assertEqual(source.tell(), len(contents))
                self.assertFalse(source.closed)

        source = io.BytesIO(b"prefix" + contents)
        source.seek(len(b"prefix"))
        output, builder = memory_builder()
        builder.add_file("positioned", source, size=len(contents))
        builder.close()
        self.assertEqual(read_archive(output.getvalue()), {"positioned": contents})
        self.assertEqual(source.tell(), len(b"prefix") + len(contents))
        self.assertFalse(source.closed)

        source, output = io.BytesIO(b"before the suffix"), io.BytesIO()
        changed = False

        def mutate_source(data: memoryview) -> int:
            nonlocal changed
            if not changed:
                source.write(b"after!")
                source.seek(0)
                changed = True
            return output.write(data)

        builder = tar_codec.Builder(
            cast(ArchiveSink, SimpleNamespace(write=mutate_source))
        )
        builder.add_file("prefix", source, size=5)
        builder.close()
        self.assertEqual(read_archive(output.getvalue()), {"prefix": b"after"})
        self.assertEqual(source.tell(), 5)

        contents = bytes(range(256)) * 1025
        writer = ShortWriter(maximum_write=511)
        builder = tar_codec.Builder(writer)
        builder.add_file("large", contents)
        builder.add_file("prefix", io.BytesIO(contents), size=len(contents) - 17)
        builder.close()
        self.assertEqual(
            read_archive(writer.getvalue()),
            {"large": contents, "prefix": contents[:-17]},
        )

    def test_rejects_invalid_inputs_and_poisons_failed_builders(self) -> None:
        _, builder = memory_builder()
        self.assertRaises(TypeError, builder.add_file, "stream", io.BytesIO(b"x"))

        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing" / "archive.tar"
            with self.assertRaises(FileNotFoundError):
                tar_codec.Builder(missing)

            output, builder = memory_builder()
            with self.assertRaises(OSError):
                builder.add_file("directory", Path(directory))
            self.assertRaisesRegex(
                TypeError,
                "size",
                builder.add_file,
                "sized-directory",
                Path(directory),
                size=0,
            )
            builder.add_file("valid", b"x")
            builder.close()
            self.assertEqual(read_archive(output.getvalue()), {"valid": b"x"})

            source = Path(directory) / "source"
            source.write_bytes(b"payload")
            output, builder = memory_builder()
            self.assertRaisesRegex(
                TypeError, "size", builder.add_file, "sized-path", source, size=3
            )
            builder.add_file("path", source)
            builder.close()
            self.assertEqual(read_archive(output.getvalue()), {"path": b"payload"})

        for sink in (None, SimpleNamespace(write=None)):
            with self.subTest(sink=sink):
                with self.assertRaises(TypeError):
                    tar_codec.Builder(cast(ArchiveSink, sink))
        output, builder = memory_builder()
        builder.add_file("duplicate", b"x")
        for path in ("duplicate", "invalid:name"):
            with self.subTest(path=path):
                with self.assertRaises(tar_codec.BuildError):
                    builder.add_file(path, FailingLookup(), size=1)
        builder.add_file("valid", b"y")
        builder.close()
        self.assertEqual(
            read_archive(output.getvalue()), {"duplicate": b"x", "valid": b"y"}
        )

        policy, links = tar_codec.BuilderPolicy(), tar_codec.LinkPolicy()
        self.assertEqual(policy.symlink_policy, tar_codec.BuildSymlinkPolicy.REJECT)
        self.assertEqual(links.symlink_policy, tar_codec.ExtractSymlinkPolicy.PRESERVE)
        self.assertTrue(policy.validate_names)
        self.assertFalse(links.allow_hard_links)
        self.assertFalse(tar_codec.BuilderPolicy(validate_names=False).validate_names)
        self.assertFalse(tar_codec.ExtractPolicy(validate_names=False).validate_names)

        failed_reader = cast(ArchiveSource, FAILING_READINTO)
        failed_writer = cast(
            ArchiveSink,
            SimpleNamespace(write=lambda _: raise_callback("writer failed")),
        )
        for _name, sink, source, size, exception in (
            ("stream", io.BytesIO(), io.BytesIO(b"x"), 2, tar_codec.BuildError),
            ("readinto", io.BytesIO(), failed_reader, 1, StreamCallbackError),
            ("writer", failed_writer, b"x", None, StreamCallbackError),
        ):
            builder = tar_codec.Builder(sink)
            if size is None:
                self.assertRaises(exception, builder.add_file, "payload", source)
            else:
                self.assertRaises(
                    exception, builder.add_file, "payload", source, size=size
                )
            with self.assertRaises(tar_codec.BuildError):
                builder.add_directory("after-failure")

        failing_flush = cast(
            ArchiveSink,
            SimpleNamespace(
                write=lambda data: len(data),
                flush=lambda: raise_callback("flush failed"),
            ),
        )
        builder = tar_codec.Builder(failing_flush)
        builder.add_file("payload", b"x")
        with self.assertRaisesRegex(StreamCallbackError, "flush failed"):
            builder.close()

    def test_extracts_files_and_enforces_containment_and_link_policies(self) -> None:
        for name, entry, rejected in (
            ("safe", ArchiveEntry("nested/file", b"safe"), False),
            ("large", ArchiveEntry("nested/large", bytes(range(256)) * 4_100), False),
            ("escape", ArchiveEntry("../escaped", b"unsafe"), True),
        ):
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                destination = root / "destination"
                archive = tar_codec.TarArchive(make_archive((entry,)))
                if rejected:
                    with self.assertRaises(tar_codec.ExtractError):
                        archive.extract_in(destination)
                    self.assertFalse((root / "escaped").exists())
                else:
                    archive.extract_in(destination)
                    self.assertEqual(
                        (destination / entry.name).read_bytes(), entry.data
                    )
                with self.assertRaisesRegex(RuntimeError, "closed"):
                    next(archive)
                with self.assertRaisesRegex(RuntimeError, "closed"):
                    with archive:
                        pass

        target = ArchiveEntry("target", b"target")
        symlinks = tar_codec.ExtractSymlinkPolicy
        for name, kind, rejected in (
            ("reject symlink", tarfile.SYMTYPE, True),
            ("skip symlink", tarfile.SYMTYPE, False),
            ("reject hard link", tarfile.LNKTYPE, True),
            ("allow hard link", tarfile.LNKTYPE, False),
        ):
            with self.subTest(policy=name), tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / "destination"
                alias = ArchiveEntry("alias", kind=kind, link_name="target")
                archive = tar_codec.TarArchive(make_archive((target, alias)))
                if kind == tarfile.SYMTYPE:
                    symlink_policy = symlinks.REJECT if rejected else symlinks.SKIP
                    links = tar_codec.LinkPolicy(symlink_policy=symlink_policy)
                else:
                    links = tar_codec.LinkPolicy(allow_hard_links=not rejected)
                policy = tar_codec.ExtractPolicy(link_policy=links)
                if rejected:
                    with self.assertRaises(tar_codec.ExtractError):
                        archive.extract_in(destination, policy)
                else:
                    archive.extract_in(destination, policy)
                    self.assertEqual((destination / "target").read_bytes(), b"target")
                    self.assertEqual(
                        (destination / "alias").exists(), links.allow_hard_links
                    )
