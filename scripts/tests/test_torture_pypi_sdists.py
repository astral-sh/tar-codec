import hashlib
import io
import json
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from scripts.torture_pypi_sdists import (
    HarnessError,
    ProgressReporter,
    RANKING_URL,
    RankedProject,
    ensure_cached_archive,
    find_stale_task_roots,
    format_progress,
    format_stale_task_warnings,
    load_projects,
    parse_args,
    parse_failed_projects,
    result_record,
    sandbox_profile,
    select_newest_sdist,
    serialize_result,
    verify_sha256,
)


class TorturePypiSdistsTests(unittest.TestCase):
    def test_selects_newest_non_yanked_tar_gz_sdist(self) -> None:
        selected = select_newest_sdist(
            [
                {"filename": "project-3.whl", "upload-time": "2024-03-01T00:00:00Z"},
                {"filename": "project-1.tar.gz", "upload-time": "2024-01-01T00:00:00Z"},
                {"filename": "project-2.tar.gz", "upload-time": "2024-02-01T00:00:00Z"},
            ]
        )

        self.assertEqual(selected["filename"], "project-2.tar.gz")

    def test_excludes_yanked_sdists(self) -> None:
        selected = select_newest_sdist(
            [
                {"filename": "project-1.tar.gz", "upload-time": "2024-01-01T00:00:00Z"},
                {
                    "filename": "project-2.tar.gz",
                    "upload-time": "2024-02-01T00:00:00Z",
                    "yanked": "broken",
                },
            ]
        )

        self.assertEqual(selected["filename"], "project-1.tar.gz")

    def test_returns_none_when_no_sdist_exists(self) -> None:
        self.assertIsNone(select_newest_sdist([{"filename": "project.whl"}]))

    def test_loads_single_project_without_fetching_ranking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            with redirect_stderr(io.StringIO()):
                with patch("scripts.torture_pypi_sdists.request_bytes") as request_bytes:
                    projects = load_projects("logging", RANKING_URL, 10_000, 10, run_dir)

            request_bytes.assert_not_called()
            self.assertEqual(projects, [RankedProject(rank=None, project="logging")])
            self.assertFalse((run_dir / "ranking.json").exists())

    def test_loads_failed_projects_without_fetching_ranking(self) -> None:
        contents = (
            b'{"rank": 1, "project": "passed", "outcome": "passed"}\n'
            b'{"rank": 2, "project": "broken", "outcome": "failed_extract"}\n'
        )
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            source = run_dir / "source-results.jsonl"
            source.write_bytes(contents)
            with redirect_stderr(io.StringIO()):
                with patch("scripts.torture_pypi_sdists.request_bytes") as request_bytes:
                    projects = load_projects(
                        None, RANKING_URL, 10_000, 10, run_dir, source
                    )

            request_bytes.assert_not_called()
            self.assertEqual(projects, [RankedProject(rank=2, project="broken")])
            self.assertEqual((run_dir / "rerun-results.jsonl").read_bytes(), contents)
            self.assertFalse((run_dir / "ranking.json").exists())

    def test_parses_only_failed_projects_and_preserves_optional_rank(self) -> None:
        projects = parse_failed_projects(
            b'{"rank": 1, "project": "passed", "outcome": "passed"}\n'
            b'{"rank": 2, "project": "broken", "outcome": "failed_extract"}\n'
            b'{"rank": null, "project": "missing", "outcome": "failed_metadata"}\n'
        )

        self.assertEqual(
            projects,
            [
                RankedProject(rank=2, project="broken"),
                RankedProject(rank=None, project="missing"),
            ],
        )

    def test_rejects_malformed_rerun_results(self) -> None:
        with self.assertRaisesRegex(HarnessError, "line 1 is not valid JSON"):
            parse_failed_projects(b"not-json\n")

    def test_single_project_result_has_no_rank(self) -> None:
        record = result_record(RankedProject(rank=None, project="logging"))

        self.assertIsNone(record["rank"])
        self.assertEqual(record["project"], "logging")

    def test_parses_single_project_repro(self) -> None:
        args = parse_args(["--project", "logging"])

        self.assertEqual(args.project, "logging")
        self.assertEqual(args.limit, 10_000)

    def test_parses_failed_outcome_rerun(self) -> None:
        args = parse_args(["--rerun-failures", "results.jsonl"])

        self.assertEqual(args.rerun_failures, Path("results.jsonl"))
        self.assertEqual(args.limit, 10_000)

    def test_project_cannot_be_combined_with_limit(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parse_args(["--project", "logging", "--limit", "1"])

    def test_project_cannot_be_combined_with_ranking_url(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parse_args(["--project", "logging", "--ranking-url", "ranking.json"])

    def test_rerun_failures_cannot_be_combined_with_limit(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parse_args(["--rerun-failures", "results.jsonl", "--limit", "1"])

    def test_rerun_failures_cannot_be_combined_with_project(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parse_args(["--rerun-failures", "results.jsonl", "--project", "logging"])

    def test_rerun_failures_cannot_be_combined_with_ranking_url(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parse_args(
                    ["--rerun-failures", "results.jsonl", "--ranking-url", "ranking.json"]
                )

    def test_verifies_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "archive"
            path.write_bytes(b"contents")

            self.assertTrue(verify_sha256(path, hashlib.sha256(b"contents").hexdigest()))
            self.assertFalse(verify_sha256(path, hashlib.sha256(b"different").hexdigest()))

    def test_reuses_verified_cached_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.tar.gz"
            source.write_bytes(b"contents")
            sha256 = hashlib.sha256(b"contents").hexdigest()
            file = {"hashes": {"sha256": sha256}, "url": source.as_uri()}
            cache_dir = root / "cache"

            cached = ensure_cached_archive(file, cache_dir, 10)
            source.write_bytes(b"different")
            reused = ensure_cached_archive(file, cache_dir, 10)

            self.assertEqual(reused, cached)
            self.assertEqual(reused.read_bytes(), b"contents")

    def test_sandbox_profile_uses_canonical_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / "actual"
            actual.mkdir()
            link = root / "link"
            link.symlink_to(actual, target_is_directory=True)

            profile = sandbox_profile(link)

            self.assertIn(json.dumps(str(actual.resolve())), profile)
            self.assertNotIn(json.dumps(str(link)), profile)

    def test_serializes_jsonl_result(self) -> None:
        record = {
            "rank": 1,
            "project": "sampleproject",
            "outcome": "passed",
            "stderr": "",
        }

        serialized = serialize_result(record)

        self.assertTrue(serialized.endswith("\n"))
        self.assertEqual(json.loads(serialized), record)

    def test_finds_and_formats_stale_generated_task_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tasks_dir = Path(temporary)
            extract = tasks_dir / "extract-old"
            preflight = tasks_dir / "sandbox-preflight-old"
            unrelated = tasks_dir / "keep"
            extract.mkdir()
            preflight.mkdir()
            unrelated.mkdir()

            task_roots = find_stale_task_roots(tasks_dir)
            warnings = format_stale_task_warnings(task_roots)

            self.assertEqual(task_roots, [extract, preflight])
            self.assertEqual(
                warnings,
                [
                    "warning: found 2 stale task directories from interrupted runs; "
                    "leaving them in place",
                    f"warning: stale task directory: {extract}",
                    f"warning: stale task directory: {preflight}",
                ],
            )

    def test_formats_no_warning_without_stale_task_roots(self) -> None:
        self.assertEqual(format_stale_task_warnings([]), [])

    def test_formats_progress_with_outcome_totals(self) -> None:
        rendered = format_progress(
            completed=125,
            total=500,
            counts=Counter({"passed": 100, "skipped_no_sdist": 20, "failed_extract": 5}),
            elapsed_seconds=25,
            project="sampleproject",
            outcome="failed_extract",
        )

        self.assertEqual(
            rendered,
            "[run  25.0% 125/500] passed=100 skipped=20 failed=5 "
            "rate=5.0/s latest=sampleproject:failed_extract",
        )

    def test_non_interactive_progress_reports_checkpoints_failures_and_completion(self) -> None:
        output = io.StringIO()
        progress = ProgressReporter(total=3, output=output, checkpoint_interval=2)
        counts = Counter({"passed": 1})
        progress.update(1, counts, {"project": "one", "outcome": "passed"})
        counts["passed"] += 1
        progress.update(2, counts, {"project": "two", "outcome": "passed"})
        counts["failed_extract"] += 1
        progress.update(3, counts, {"project": "three", "outcome": "failed_extract"})

        rendered = output.getvalue()
        self.assertNotIn("latest=one:passed", rendered)
        self.assertIn("[run  66.7% 2/3]", rendered)
        self.assertIn("[run 100.0% 3/3]", rendered)
        self.assertIn("latest=three:failed_extract", rendered)

    def test_interactive_progress_refreshes_one_line(self) -> None:
        class TerminalOutput(io.StringIO):
            def isatty(self) -> bool:
                return True

        output = TerminalOutput()
        progress = ProgressReporter(total=1, output=output)
        progress.update(1, Counter({"passed": 1}), {"project": "one", "outcome": "passed"})
        progress.finish()

        self.assertTrue(output.getvalue().startswith("\r\033[K[run 100.0% 1/1]"))
        self.assertTrue(output.getvalue().endswith("\n"))


if __name__ == "__main__":
    unittest.main()
