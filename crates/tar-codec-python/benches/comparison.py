"""Compare tar-codec with Python's tarfile module."""

from __future__ import annotations

import argparse
import io
import platform
import shutil
import statistics
import tarfile
import tempfile
import timeit
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

import tar_codec

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

Entry = tuple[str, bytes]
Operation = Callable[[Path | None], object]


class ForwardStream(io.RawIOBase):
    """A nonseekable in-memory binary stream."""

    def __init__(self, source: bytes) -> None:
        super().__init__()
        self.source = io.BytesIO(source)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: WriteableBuffer, /) -> int:
        return self.source.readinto(buffer)


ArchiveSource = bytes | io.BytesIO | ForwardStream


def payload(size: int, salt: int = 0) -> bytes:
    pattern = bytes(range(251))
    start = salt % len(pattern)
    return (pattern * ((size + start + len(pattern) - 1) // len(pattern)))[
        start : start + size
    ]


def encode_tar_codec(entries: tuple[Entry, ...]) -> bytes:
    output = io.BytesIO()
    with tar_codec.Builder(output) as archive:
        for path, contents in entries:
            archive.add_file(path, contents)
    return output.getvalue()


def encode_tarfile(entries: tuple[Entry, ...]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path, contents in entries:
            member = tarfile.TarInfo(path)
            member.size, member.mode, member.mtime = len(contents), 0o644, 0
            member.pax_headers = {"path": path, "size": str(len(contents))}
            archive.addfile(member, io.BytesIO(contents))
    return output.getvalue()


def decode_tar_codec(source: ArchiveSource) -> tuple[tuple[str, memoryview], ...]:
    with tar_codec.TarArchive(source) as archive:
        return tuple(
            (member.path, payload.read())
            for member in archive
            if (payload := member.payload) is not None
        )


def decode_tarfile(source: ArchiveSource) -> tuple[Entry, ...]:
    source = io.BytesIO(source) if isinstance(source, bytes) else source
    mode = "r:" if source.seekable() else "r|"
    with tarfile.open(fileobj=source, mode=mode) as archive:
        return tuple(
            (member.name, payload.read())
            for member in archive
            if (payload := archive.extractfile(member)) is not None
        )


def extract(name: str, archive: bytes, destination: Path | None) -> None:
    if destination is None:
        raise RuntimeError("filesystem extraction requires a destination")
    if name == "tar-codec":
        with tar_codec.TarArchive(archive) as source:
            source.extract_in(destination)
        return
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
        if hasattr(tarfile, "data_filter"):
            source.extractall(destination, filter="data")
        else:
            source.extractall(destination)


def validate(entries: tuple[Entry, ...], archive: bytes, root: Path) -> None:
    for name, encode in (("tar-codec", encode_tar_codec), ("tarfile", encode_tarfile)):
        encoded = encode(entries)
        if any(
            decode(source) != entries
            for decode in (decode_tar_codec, decode_tarfile)
            for source in (encoded, io.BytesIO(encoded), ForwardStream(encoded))
        ):
            raise RuntimeError(f"{name} produced an invalid benchmark archive")
    for name in ("tar-codec", "tarfile"):
        destination = root / f"validate-{name}"
        destination.mkdir(parents=True)
        extract(name, archive, destination)
        if any(
            (destination / path).read_bytes() != contents for path, contents in entries
        ):
            raise RuntimeError(f"{name} produced incorrect extracted files")


def measure(
    operations: tuple[Operation, Operation],
    *,
    samples: int,
    warmups: int,
    extraction_root: Path | None,
) -> tuple[float, float]:
    durations: tuple[list[float], list[float]] = ([], [])
    destination: Path | None = None
    timers = tuple(
        timeit.Timer(lambda call=call: call(destination)) for call in operations
    )
    for index in range(warmups + samples):
        for implementation in (index % 2, (index + 1) % 2):
            destination = None
            if extraction_root is not None:
                name = ("tar-codec", "tarfile")[implementation]
                destination = extraction_root / f"{index}-{name}"
                destination.mkdir(parents=True)
            try:
                duration = timers[implementation].timeit(number=1)
                if index >= warmups:
                    durations[implementation].append(duration)
            finally:
                if destination is not None:
                    shutil.rmtree(destination)
    return statistics.median(durations[0]), statistics.median(durations[1])


def format_measurement(duration: float, payload_bytes: int) -> str:
    return f"{duration * 1_000:9.2f} ms {payload_bytes / duration / 1024**2:9.1f} MiB/s"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", "--iterations", type=int, default=25)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--large-file-size", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--small-file-count", type=int, default=1024)
    parser.add_argument("--small-file-size", type=int, default=1024)
    parser.add_argument(
        "--quick", action="store_true", help="run small smoke-test fixtures"
    )
    options = parser.parse_args()
    fields = ("samples", "large_file_size", "small_file_count", "small_file_size")
    if any(getattr(options, field) <= 0 for field in fields):
        parser.error("sample and fixture sizes must be positive")
    if options.warmups < 0:
        parser.error("warmups must be nonnegative")
    large_size = options.large_file_size
    small_count = options.small_file_count
    if options.quick:
        large_size = min(large_size, 64 * 1024)
        small_count = min(small_count, 8)
    fixtures = (
        ("large", (("large/payload.bin", payload(large_size)),)),
        (
            "many-small",
            tuple(
                (
                    f"many-small/directory-{index % 32:02}/file-{index:04}.txt",
                    payload(options.small_file_size, index),
                )
                for index in range(small_count)
            ),
        ),
        (
            "mixed",
            tuple(
                (
                    f"mixed/directory-{index % 3}/file-{index:02}.bin",
                    payload(max(1, min(size, large_size)), index),
                )
                for index, size in enumerate(
                    (
                        options.small_file_size,
                        17 * 1024,
                        64 * 1024,
                        257 * 1024,
                        512 * 1024,
                        large_size // 16,
                        large_size // 4,
                    )
                )
            ),
        ),
    )
    print(f"Python {platform.python_version()}; median of {options.samples} sample(s)")
    print("Speedup above 1.00x means tar-codec is faster.\n")
    print(
        f"{'workload':<12} {'operation':<14} "
        f"{'tar-codec':>24} {'tarfile':>24} {'speedup':>9}"
    )
    functions: tuple[tuple[str, Callable[..., object], Callable[..., object]], ...] = (
        ("encode", encode_tar_codec, encode_tarfile),
        ("decode", decode_tar_codec, decode_tarfile),
        ("decode-bytesio", decode_tar_codec, decode_tarfile),
        ("decode-stream", decode_tar_codec, decode_tarfile),
        ("extract", partial(extract, "tar-codec"), partial(extract, "tarfile")),
    )
    with tempfile.TemporaryDirectory(prefix="tar-codec-python-benchmark-") as directory:
        for workload, entries in fixtures:
            archive = encode_tarfile(entries)
            root = Path(directory) / workload
            validate(entries, archive, root)
            payload_bytes = sum(len(contents) for _, contents in entries)
            for operation, codec, reference in functions:

                def run(function: Callable[..., object]) -> Operation:
                    match operation:
                        case "decode-bytesio":
                            return lambda _destination: function(io.BytesIO(archive))
                        case "decode-stream":
                            return lambda _destination: function(ForwardStream(archive))
                        case "extract":
                            return lambda destination: function(archive, destination)
                        case "encode":
                            return lambda _destination: function(entries)
                        case _:
                            return lambda _destination: function(archive)

                times = measure(
                    (run(codec), run(reference)),
                    samples=options.samples,
                    warmups=options.warmups,
                    extraction_root=root if operation == "extract" else None,
                )
                print(
                    f"{workload:<12} {operation:<14} "
                    f"{format_measurement(times[0], payload_bytes):>24} "
                    f"{format_measurement(times[1], payload_bytes):>24} "
                    f"{times[1] / times[0]:8.2f}x"
                )


if __name__ == "__main__":
    main()
