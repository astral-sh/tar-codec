"""Parse source archives from PyPI's most-downloaded projects."""

from __future__ import annotations

import argparse
import bz2
import gzip
import io
import json
import lzma
import sys
import tarfile
import zlib
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from http.client import HTTPException
from itertools import zip_longest
from typing import BinaryIO, cast
from urllib.parse import quote
from urllib.request import Request, urlopen

import tar_codec

RANKINGS_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
PYPI_URL = "https://pypi.org/pypi"
ARCHIVE_SUFFIXES = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz",
    ".tbz2",
    ".tar.xz",
    ".txz",
)
READ_CHUNK_SIZE = 1024 * 1024
REQUEST_HEADERS = {"User-Agent": "tar-codec PyPI sdist torture test"}
ArchiveStream = BinaryIO | gzip.GzipFile | bz2.BZ2File | lzma.LZMAFile


@dataclass(frozen=True)
class SourceDistribution:
    filename: str
    url: str


@dataclass(frozen=True)
class ArchiveStatistics:
    members: int
    payload_bytes: int


@dataclass
class RunStatistics:
    passed: int = 0
    skipped: int = 0
    failed: int = 0
    members: int = 0
    payload_bytes: int = 0


def fetch_json(url: str, *, timeout: float) -> dict[str, object]:
    with urlopen(Request(url, headers=REQUEST_HEADERS), timeout=timeout) as response:
        document: object = json.load(response)
    if not isinstance(document, dict) or any(
        not isinstance(key, str) for key in document
    ):
        raise ValueError(f"expected a JSON object from {url}")
    return cast(dict[str, object], document)


def ranked_projects(rankings: dict[str, object]) -> tuple[str, ...]:
    rows = rankings.get("rows")
    if not isinstance(rows, list):
        raise ValueError("package rankings do not contain a rows array")
    projects: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(
            project := row.get("project"), str
        ):
            raise ValueError(f"invalid project in package ranking row {index}")
        projects.append(project)
    return tuple(projects)


def source_distribution(metadata: dict[str, object]) -> SourceDistribution | None:
    files = metadata.get("urls")
    if not isinstance(files, list):
        raise ValueError("PyPI response does not contain a release files array")
    for distribution in files:
        if not isinstance(distribution, dict):
            continue
        filename, url = distribution.get("filename"), distribution.get("url")
        if (
            distribution.get("packagetype") == "sdist"
            and isinstance(filename, str)
            and isinstance(url, str)
            and filename.lower().endswith(ARCHIVE_SUFFIXES)
        ):
            return SourceDistribution(filename, url)
    return None


@contextmanager
def decompressed_stream(source: BinaryIO, filename: str) -> Iterator[ArchiveStream]:
    match filename.lower():
        case name if name.endswith((".tar.gz", ".tgz")):
            with gzip.GzipFile(fileobj=source, mode="rb") as stream:
                yield stream
        case name if name.endswith((".tar.bz2", ".tbz", ".tbz2")):
            with bz2.BZ2File(source, mode="rb") as stream:
                yield stream
        case name if name.endswith((".tar.xz", ".txz")):
            with lzma.LZMAFile(source, mode="rb") as stream:
                yield stream
        case _:
            yield source


def parse_source_distribution(
    distribution: SourceDistribution, *, timeout: float
) -> ArchiveStatistics:
    with urlopen(
        Request(distribution.url, headers=REQUEST_HEADERS), timeout=timeout
    ) as response:
        archive_bytes = response.read()

    members, payload_bytes = 0, 0
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r|*") as reference:
        with decompressed_stream(
            io.BytesIO(archive_bytes), distribution.filename
        ) as stream:
            with tar_codec.TarArchive(stream) as archive:
                for members, (member, expected) in enumerate(
                    zip_longest(archive, reference), start=1
                ):
                    if member is None:
                        raise ValueError(
                            f"member {members} missing from tar_codec: "
                            f"tarfile has {expected.name!r}"
                        )
                    if expected is None:
                        raise ValueError(
                            f"member {members} missing from tarfile: "
                            f"tar_codec has {member.path!r}"
                        )
                    path = member.path.rstrip("/") if expected.isdir() else member.path
                    size = 0 if member.size is None else member.size
                    if (path, size) != (expected.name, expected.size):
                        raise ValueError(
                            f"member {members} mismatch: "
                            f"tar_codec has {member.path!r} ({size} bytes); "
                            f"tarfile has {expected.name!r} ({expected.size} bytes)"
                        )
                    if (payload := member.payload) is not None:
                        while chunk := payload.read(READ_CHUNK_SIZE):
                            payload_bytes += len(chunk)
    return ArchiveStatistics(members, payload_bytes)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--rankings-url", default=RANKINGS_URL)
    parser.add_argument("--pypi-url", default=PYPI_URL)
    options = parser.parse_args(arguments)
    if options.limit <= 0:
        parser.error("--limit must be positive")
    if options.offset < 0:
        parser.error("--offset must be nonnegative")
    if options.timeout <= 0:
        parser.error("--timeout must be positive")

    errors = (
        OSError,
        ValueError,
        EOFError,
        HTTPException,
        lzma.LZMAError,
        tarfile.TarError,
        zlib.error,
        tar_codec.DecodeError,
    )
    try:
        projects = ranked_projects(
            fetch_json(options.rankings_url, timeout=options.timeout)
        )[options.offset : options.offset + options.limit]
    except errors as error:
        print(f"FAIL package rankings: {error}", file=sys.stderr)
        return 1

    print(f"Checking {len(projects)} ranked PyPI project(s); parsing only.", flush=True)
    results = RunStatistics()
    for rank, project in enumerate(projects, start=options.offset + 1):
        prefix = f"[{rank}] {project}"
        try:
            metadata = fetch_json(
                f"{options.pypi_url.rstrip('/')}/{quote(project, safe='')}/json",
                timeout=options.timeout,
            )
            distribution = source_distribution(metadata)
            if distribution is None:
                results.skipped += 1
                print(
                    f"SKIP {prefix}: no supported tar source distribution", flush=True
                )
                continue
            archive = parse_source_distribution(distribution, timeout=options.timeout)
        except errors as error:
            results.failed += 1
            print(f"FAIL {prefix}: {type(error).__name__}: {error}", flush=True)
            continue

        results.passed += 1
        results.members += archive.members
        results.payload_bytes += archive.payload_bytes
        print(
            f"PASS {prefix}: {distribution.filename} "
            f"({archive.members} members, {archive.payload_bytes:,} payload bytes)",
            flush=True,
        )

    print(
        f"\nSummary: {results.passed} passed, {results.skipped} skipped, "
        f"{results.failed} failed; {results.members:,} members, "
        f"{results.payload_bytes:,} payload bytes."
    )
    return int(results.failed > 0)


if __name__ == "__main__":
    raise SystemExit(main())
