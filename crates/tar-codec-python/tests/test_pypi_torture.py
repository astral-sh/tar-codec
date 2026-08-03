from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import tarfile
import unittest
from collections.abc import Callable
from contextlib import nullcontext, redirect_stdout
from unittest.mock import patch
from urllib.request import Request

import pypi_torture

from _support import ArchiveEntry, make_archive


class PyPITortureTests(unittest.TestCase):
    def test_streams_and_fully_parses_supported_source_archive_formats(self) -> None:
        contents = b"payload" * (pypi_torture.READ_CHUNK_SIZE // 7 + 1)
        archive = make_archive(
            (
                ArchiveEntry("project", kind=tarfile.DIRTYPE),
                ArchiveEntry("project/large.bin", contents),
                ArchiveEntry("project/empty.bin"),
            )
        )
        compressions: tuple[tuple[str, Callable[[bytes], bytes]], ...] = (
            ("project.tar", lambda source: source),
            ("project.tar.gz", gzip.compress),
            ("project.tgz", gzip.compress),
            ("project.tar.bz2", bz2.compress),
            ("project.tbz2", bz2.compress),
            ("project.tar.xz", lzma.compress),
            ("project.txz", lzma.compress),
        )
        for filename, compress in compressions:
            with self.subTest(filename=filename):
                distribution = pypi_torture.SourceDistribution(
                    filename, "https://example.test/archive"
                )
                with patch(
                    "pypi_torture.urlopen", return_value=io.BytesIO(compress(archive))
                ):
                    actual = pypi_torture.parse_source_distribution(
                        distribution, timeout=5
                    )
                self.assertEqual(
                    actual,
                    pypi_torture.ArchiveStatistics(3, len(contents)),
                )

    def test_reports_ranked_results_and_continues_after_archive_failures(self) -> None:
        archive = make_archive((ArchiveEntry("project/file.txt", b"contents"),))
        projects = ("outside-before", "broken", "wheel-only", "zip-only", "valid")
        rankings = {"rows": [{"project": project} for project in projects]}
        metadata: dict[str, dict[str, object]] = {
            "broken": {
                "urls": [
                    {
                        "packagetype": "sdist",
                        "filename": "broken.tar.gz",
                        "url": "https://example.test/broken.tar.gz",
                    }
                ]
            },
            "wheel-only": {
                "urls": [
                    {
                        "packagetype": "bdist_wheel",
                        "filename": "wheel_only.whl",
                        "url": "https://example.test/wheel_only.whl",
                    }
                ]
            },
            "zip-only": {
                "urls": [
                    {
                        "packagetype": "sdist",
                        "filename": "zip_only.zip",
                        "url": "https://example.test/zip_only.zip",
                    }
                ]
            },
            "valid": {
                "urls": [
                    {
                        "packagetype": "sdist",
                        "filename": "valid.tar.gz",
                        "url": "https://example.test/valid.tar.gz",
                    }
                ]
            },
        }

        def response(request: Request, *, timeout: float) -> io.BytesIO:
            self.assertEqual(timeout, 5)
            match request.full_url:
                case "https://example.test/rankings":
                    return io.BytesIO(json.dumps(rankings).encode())
                case "https://example.test/broken.tar.gz":
                    return io.BytesIO(b"not a gzip archive")
                case "https://example.test/valid.tar.gz":
                    return io.BytesIO(gzip.compress(archive))
                case url if url.startswith("https://example.test/pypi/"):
                    project = url.removeprefix("https://example.test/pypi/")
                    project = project.removesuffix("/json")
                    return io.BytesIO(json.dumps(metadata[project]).encode())
                case _:
                    raise AssertionError(f"unexpected request: {request.full_url}")

        output = io.StringIO()
        with (
            patch("pypi_torture.urlopen", side_effect=response),
            redirect_stdout(output),
        ):
            exit_code = pypi_torture.main(
                (
                    "--rankings-url",
                    "https://example.test/rankings",
                    "--pypi-url",
                    "https://example.test/pypi",
                    "--offset",
                    "1",
                    "--limit",
                    "4",
                    "--timeout",
                    "5",
                )
            )

        self.assertEqual(exit_code, 1)
        self.assertNotIn("outside-before", output.getvalue())
        self.assertIn("FAIL [2] broken: ReadError", output.getvalue())
        self.assertIn("SKIP [3] wheel-only", output.getvalue())
        self.assertIn("SKIP [4] zip-only", output.getvalue())
        self.assertIn(
            "PASS [5] valid: valid.tar.gz (1 members, 8 payload bytes)",
            output.getvalue(),
        )
        self.assertIn("Summary: 1 passed, 2 skipped, 1 failed", output.getvalue())

    def test_rejects_different_or_missing_tarfile_members(self) -> None:
        archive = make_archive((ArchiveEntry("project/file.txt", b"contents"),))
        distribution = pypi_torture.SourceDistribution(
            "project.tar", "https://example.test/archive"
        )
        actual = tarfile.TarInfo("project/file.txt")
        actual.size = len(b"contents")
        different_name = tarfile.TarInfo("project/other.txt")
        different_name.size = actual.size
        different_size = tarfile.TarInfo(actual.name)
        different_size.size = actual.size + 1
        cases: tuple[tuple[str, tuple[tarfile.TarInfo, ...], str], ...] = (
            ("name", (different_name,), "member 1 mismatch"),
            ("size", (different_size,), "member 1 mismatch"),
            ("missing", (), "member 1 missing from tarfile"),
            ("extra", (actual, actual), "member 2 missing from tar_codec"),
        )

        for scenario, reference, expected_message in cases:
            with (
                self.subTest(scenario=scenario),
                patch("pypi_torture.urlopen", return_value=io.BytesIO(archive)),
                patch(
                    "pypi_torture.tarfile.open",
                    return_value=nullcontext(iter(reference)),
                ),
                self.assertRaisesRegex(ValueError, expected_message),
            ):
                pypi_torture.parse_source_distribution(distribution, timeout=5)
