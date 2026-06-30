#!/usr/bin/env python3
"""Exercise tar-codec extraction against popular PyPI source distributions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

RANKING_URL = (
    "https://raw.githubusercontent.com/hugovk/top-pypi-packages/"
    "main/top-pypi-packages-30-days.min.json"
)
PYPI_SIMPLE_URL = "https://pypi.org/simple/{project}/"
PYPI_SIMPLE_ACCEPT = "application/vnd.pypi.simple.v1+json"
USER_AGENT = "tar-codec-torture-harness/0.1"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class HarnessError(Exception):
    """A fatal harness setup error."""


class ChecksumError(Exception):
    """A downloaded archive did not match its advertised digest."""


class SandboxError(Exception):
    """The OS extraction sandbox could not be applied."""


@dataclass(frozen=True)
class RankedProject:
    rank: int | None
    project: str


@dataclass(frozen=True)
class HarnessConfig:
    cache_dir: Path
    jobs: int
    sandbox_exec: str | None
    tarpit: Path
    tasks_dir: Path
    timeout_seconds: float


@dataclass
class ProgressReporter:
    total: int
    output: TextIO = sys.stderr
    checkpoint_interval: int = 100

    def __post_init__(self) -> None:
        self.interactive = self.output.isatty()
        self.started = time.monotonic()
        self.rendered = False

    def update(self, completed: int, counts: Counter[str], result: dict[str, Any]) -> None:
        outcome = result["outcome"]
        if (
            not self.interactive
            and completed != self.total
            and completed % self.checkpoint_interval != 0
            and not outcome.startswith("failed_")
        ):
            return
        message = format_progress(
            completed,
            self.total,
            counts,
            time.monotonic() - self.started,
            result["project"],
            outcome,
        )
        if self.interactive:
            print(f"\r\033[K{message}", end="", file=self.output, flush=True)
            self.rendered = True
        else:
            print(message, file=self.output, flush=True)

    def finish(self) -> None:
        if self.rendered:
            print(file=self.output, flush=True)


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def project_name(value: str) -> str:
    project = value.strip()
    if not project:
        raise argparse.ArgumentTypeError("must not be empty")
    return project


def report_stage(stage: str, message: str) -> None:
    print(f"[{stage}] {message}", file=sys.stderr, flush=True)


def format_progress(
    completed: int,
    total: int,
    counts: Counter[str],
    elapsed_seconds: float,
    project: str,
    outcome: str,
) -> str:
    percent = completed / total * 100 if total else 100.0
    rate = completed / elapsed_seconds if elapsed_seconds else 0.0
    failed = sum(count for name, count in counts.items() if name.startswith("failed_"))
    return (
        f"[run {percent:5.1f}% {completed}/{total}] "
        f"passed={counts['passed']} skipped={counts['skipped_no_sdist']} "
        f"failed={failed} rate={rate:.1f}/s latest={project}:{outcome}"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--project",
        type=project_name,
        help="run only this PyPI project and skip the ranking download",
    )
    selection.add_argument(
        "--rerun-failures",
        type=Path,
        metavar="RESULTS_JSONL",
        help="rerun failed outcomes from an earlier results.jsonl and skip the ranking download",
    )
    selection.add_argument("--limit", type=positive_integer, default=10_000)
    parser.add_argument("--jobs", type=positive_integer, default=8)
    parser.add_argument("--work-dir", type=Path, default=Path("target/tarpit-pypi"))
    parser.add_argument("--tarpit", type=Path)
    parser.add_argument("--ranking-url", default=RANKING_URL)
    parser.add_argument("--timeout-seconds", type=positive_float, default=300.0)
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="run with temporary directories and tar-codec capability checks only",
    )
    args = parser.parse_args(argv)
    if (
        (args.project is not None or args.rerun_failures is not None)
        and args.ranking_url != RANKING_URL
    ):
        parser.error("--ranking-url cannot be used with --project or --rerun-failures")
    return args


def request_bytes(url: str, timeout_seconds: float, *, accept: str | None = None) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    if accept is not None:
        headers["Accept"] = accept
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return response.read()


def parse_ranking(contents: bytes, limit: int) -> list[RankedProject]:
    payload = json.loads(contents)
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise HarnessError("ranking payload does not contain a rows list")
    projects = []
    for rank, row in enumerate(rows[:limit], start=1):
        project = row.get("project") if isinstance(row, dict) else None
        if not isinstance(project, str) or not project:
            raise HarnessError(f"ranking row {rank} does not contain a project name")
        projects.append(RankedProject(rank=rank, project=project))
    return projects


def parse_failed_projects(contents: bytes) -> list[RankedProject]:
    projects = []
    for line_number, line in enumerate(contents.splitlines(), start=1):
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise HarnessError(f"rerun results line {line_number} is not valid JSON") from error
        if not isinstance(record, dict):
            raise HarnessError(f"rerun results line {line_number} is not a JSON object")
        outcome = record.get("outcome")
        if not isinstance(outcome, str):
            raise HarnessError(f"rerun results line {line_number} does not contain an outcome")
        if not outcome.startswith("failed_"):
            continue
        project = record.get("project")
        if not isinstance(project, str) or not project:
            raise HarnessError(
                f"rerun results line {line_number} does not contain a project name"
            )
        rank = record.get("rank")
        if rank is not None and (
            isinstance(rank, bool) or not isinstance(rank, int) or rank <= 0
        ):
            raise HarnessError(f"rerun results line {line_number} contains an invalid rank")
        projects.append(RankedProject(rank=rank, project=project))
    return projects


def load_projects(
    project: str | None,
    ranking_url: str,
    limit: int,
    timeout_seconds: float,
    run_dir: Path,
    rerun_failures: Path | None = None,
) -> list[RankedProject]:
    if project is not None:
        report_stage("selection", f"selected PyPI project {project}")
        return [RankedProject(rank=None, project=project)]

    if rerun_failures is not None:
        report_stage("selection", f"loading failed outcomes from {rerun_failures}")
        try:
            contents = rerun_failures.read_bytes()
            projects = parse_failed_projects(contents)
            (run_dir / "rerun-results.jsonl").write_bytes(contents)
        except OSError as error:
            raise HarnessError(f"failed to load rerun results: {error}") from error
        report_stage("selection", f"selected {len(projects)} failed projects")
        return projects

    report_stage("ranking", f"fetching project ranking from {ranking_url}")
    try:
        ranking = request_bytes(ranking_url, timeout_seconds)
        projects = parse_ranking(ranking, limit)
    except Exception as error:
        raise HarnessError(f"failed to fetch ranking: {error}") from error
    (run_dir / "ranking.json").write_bytes(ranking)
    report_stage("ranking", f"selected {len(projects)} ranked projects")
    return projects


def fetch_project_files(project: str, timeout_seconds: float) -> list[dict[str, Any]]:
    quoted_project = urllib.parse.quote(project, safe="")
    contents = request_bytes(
        PYPI_SIMPLE_URL.format(project=quoted_project),
        timeout_seconds,
        accept=PYPI_SIMPLE_ACCEPT,
    )
    payload = json.loads(contents)
    files = payload.get("files")
    if not isinstance(files, list):
        raise HarnessError("PyPI response does not contain a files list")
    return [file for file in files if isinstance(file, dict)]


def select_newest_sdist(files: list[dict[str, Any]]) -> dict[str, Any] | None:
    candidates = [
        file
        for file in files
        if isinstance(file.get("filename"), str)
        and file["filename"].endswith(".tar.gz")
        and not file.get("yanked", False)
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda file: (
            file.get("upload-time") if isinstance(file.get("upload-time"), str) else "",
            file["filename"],
        ),
    )


def valid_sha256(value: object) -> bool:
    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256(path: Path, expected: str) -> bool:
    return sha256_file(path) == expected


def download_to_path(url: str, destination: Path, timeout_seconds: float) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    with (
        urllib.request.urlopen(request, timeout=timeout_seconds) as response,
        destination.open("xb") as output,
    ):
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
            output.write(chunk)
    return digest.hexdigest()


def ensure_cached_archive(
    file: dict[str, Any], cache_dir: Path, timeout_seconds: float
) -> Path:
    hashes = file.get("hashes")
    sha256 = hashes.get("sha256") if isinstance(hashes, dict) else None
    if not valid_sha256(sha256):
        raise HarnessError("selected sdist does not advertise a valid SHA-256 digest")
    url = file.get("url")
    if not isinstance(url, str) or not url:
        raise HarnessError("selected sdist does not contain a download URL")

    archive = cache_dir / sha256[:2] / f"{sha256}.tar.gz"
    if archive.exists():
        if verify_sha256(archive, sha256):
            return archive
        archive.unlink()

    archive.parent.mkdir(parents=True, exist_ok=True)
    partial = archive.with_name(f"{archive.name}.{uuid.uuid4().hex}.part")
    try:
        actual = download_to_path(url, partial, timeout_seconds)
        if actual != sha256:
            raise ChecksumError(f"expected SHA-256 {sha256}, downloaded {actual}")
        os.replace(partial, archive)
    finally:
        partial.unlink(missing_ok=True)
    return archive


def sandbox_profile(task_root: Path) -> str:
    canonical_root = task_root.resolve(strict=True)
    encoded_root = json.dumps(os.fspath(canonical_root))
    return "\n".join(
        [
            "(version 1)",
            "(allow default)",
            f"(deny file-write* (require-not (subpath {encoded_root})))",
        ]
    )


def preflight_sandbox(sandbox_exec: str, tasks_dir: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="sandbox-preflight-", dir=tasks_dir) as temporary:
        task_root = Path(temporary).resolve()
        allowed = task_root / "allowed"
        allowed.mkdir()
        profile = sandbox_profile(allowed)
        inside = subprocess.run(
            [sandbox_exec, "-p", profile, "/usr/bin/touch", os.fspath(allowed / "inside")],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if inside.returncode != 0:
            raise SandboxError(f"sandbox denied an in-root write: {inside.stderr.strip()}")
        outside = subprocess.run(
            [sandbox_exec, "-p", profile, "/usr/bin/touch", os.fspath(task_root / "outside")],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if outside.returncode == 0:
            raise SandboxError("sandbox permitted an out-of-root write")


def configure_sandbox(no_sandbox: bool, tasks_dir: Path) -> str | None:
    if no_sandbox:
        return None
    if sys.platform != "darwin":
        raise HarnessError("OS sandboxing is only supported on macOS; pass --no-sandbox to opt out")
    sandbox_exec = shutil.which("sandbox-exec")
    if sandbox_exec is None:
        raise HarnessError("sandbox-exec was not found; pass --no-sandbox to opt out")
    try:
        preflight_sandbox(sandbox_exec, tasks_dir)
    except (OSError, subprocess.TimeoutExpired, SandboxError) as error:
        raise HarnessError(f"sandbox-exec preflight failed: {error}") from error
    return sandbox_exec


def run_extraction(config: HarnessConfig, archive: Path) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="extract-", dir=config.tasks_dir) as temporary:
        task_root = Path(temporary).resolve()
        destination = task_root / "out"
        command = [os.fspath(config.tarpit), "extract", os.fspath(archive), os.fspath(destination)]
        if config.sandbox_exec is not None:
            command = [
                config.sandbox_exec,
                "-p",
                sandbox_profile(task_root),
                *command,
            ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            return "failed_extract", f"extraction timed out after {error.timeout} seconds"
        except OSError as error:
            outcome = "failed_sandbox" if config.sandbox_exec is not None else "failed_extract"
            return outcome, str(error)

        stderr = result.stderr.strip()
        if result.returncode == 0:
            return "passed", stderr
        if config.sandbox_exec is not None and "sandbox-exec: sandbox_apply:" in stderr:
            return "failed_sandbox", stderr
        return "failed_extract", stderr


def result_record(project: RankedProject) -> dict[str, Any]:
    return {
        "rank": project.rank,
        "project": project.project,
        "filename": None,
        "url": None,
        "sha256": None,
        "elapsed_seconds": None,
        "outcome": None,
        "stderr": "",
    }


def finish_result(
    record: dict[str, Any], started: float, outcome: str, stderr: str = ""
) -> dict[str, Any]:
    record["elapsed_seconds"] = round(time.monotonic() - started, 3)
    record["outcome"] = outcome
    record["stderr"] = stderr
    return record


def process_project(project: RankedProject, config: HarnessConfig) -> dict[str, Any]:
    started = time.monotonic()
    record = result_record(project)
    try:
        files = fetch_project_files(project.project, config.timeout_seconds)
    except Exception as error:  # noqa: BLE001 - failures belong in the corpus report
        return finish_result(record, started, "failed_metadata", str(error))

    sdist = select_newest_sdist(files)
    if sdist is None:
        return finish_result(record, started, "skipped_no_sdist")

    record["filename"] = sdist.get("filename")
    record["url"] = sdist.get("url")
    hashes = sdist.get("hashes")
    record["sha256"] = hashes.get("sha256") if isinstance(hashes, dict) else None
    try:
        archive = ensure_cached_archive(sdist, config.cache_dir, config.timeout_seconds)
    except ChecksumError as error:
        return finish_result(record, started, "failed_checksum", str(error))
    except HarnessError as error:
        return finish_result(record, started, "failed_metadata", str(error))
    except Exception as error:  # noqa: BLE001 - failures belong in the corpus report
        return finish_result(record, started, "failed_download", str(error))

    outcome, stderr = run_extraction(config, archive)
    return finish_result(record, started, outcome, stderr)


def serialize_result(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True) + "\n"


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def resolve_from_repo(path: Path, repo_root: Path) -> Path:
    if path.is_absolute():
        return path.resolve()
    return (repo_root / path).resolve()


def locate_tarpit(repo_root: Path, supplied: Path | None) -> Path:
    if supplied is None:
        try:
            subprocess.run(["cargo", "build", "-p", "tarpit"], cwd=repo_root, check=True)
        except (OSError, subprocess.CalledProcessError) as error:
            raise HarnessError(f"failed to build tarpit: {error}") from error
        tarpit = repo_root / "target" / "debug" / "tarpit"
    else:
        tarpit = resolve_from_repo(supplied, Path.cwd())
    if not tarpit.is_file():
        raise HarnessError(f"tarpit executable does not exist: {tarpit}")
    return tarpit.resolve()


def create_run_dir(work_dir: Path) -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = work_dir / "runs" / timestamp
    if run_dir.exists():
        run_dir = run_dir.with_name(f"{run_dir.name}-{uuid.uuid4().hex[:8]}")
    run_dir.mkdir(parents=True)
    return run_dir


def find_stale_task_roots(tasks_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in tasks_dir.iterdir()
        if path.is_dir() and path.name.startswith(("extract-", "sandbox-preflight-"))
    )


def format_stale_task_warnings(task_roots: list[Path]) -> list[str]:
    if not task_roots:
        return []
    warnings = [
        f"warning: found {len(task_roots)} stale task directories from interrupted runs; "
        "leaving them in place"
    ]
    warnings.extend(f"warning: stale task directory: {path}" for path in task_roots)
    return warnings


def run(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    work_dir = resolve_from_repo(args.work_dir, repo_root)
    rerun_failures = (
        resolve_from_repo(args.rerun_failures, repo_root)
        if args.rerun_failures is not None
        else None
    )
    ranked_selection = args.project is None and rerun_failures is None
    cache_dir = work_dir / "cache"
    tasks_dir = work_dir / "tasks"
    report_stage("setup", f"preparing work directory at {work_dir}")
    tasks_dir.mkdir(parents=True, exist_ok=True)
    for warning in format_stale_task_warnings(find_stale_task_roots(tasks_dir)):
        report_stage("setup", warning)
    run_dir = create_run_dir(work_dir)

    report_stage("setup", "locating debug tarpit executable")
    tarpit = locate_tarpit(repo_root, args.tarpit)
    sandbox_description = "disabled by explicit --no-sandbox"
    if not args.no_sandbox:
        report_stage("setup", "checking macOS sandbox-exec containment")
    sandbox_exec = configure_sandbox(args.no_sandbox, tasks_dir)
    if sandbox_exec is not None:
        sandbox_description = sandbox_exec
    report_stage("setup", f"extraction sandbox: {sandbox_description}")
    manifest = {
        "cache_dir": os.fspath(cache_dir),
        "jobs": args.jobs,
        "limit": args.limit if ranked_selection else None,
        "project": args.project,
        "ranking_url": args.ranking_url if ranked_selection else None,
        "rerun_failures": os.fspath(rerun_failures) if rerun_failures is not None else None,
        "run_dir": os.fspath(run_dir),
        "sandbox_exec": sandbox_exec,
        "started_at": datetime.now(UTC).isoformat(),
        "tarpit": os.fspath(tarpit),
        "timeout_seconds": args.timeout_seconds,
    }
    write_json(run_dir / "manifest.json", manifest)

    projects = load_projects(
        args.project,
        args.ranking_url,
        args.limit,
        args.timeout_seconds,
        run_dir,
        rerun_failures,
    )

    config = HarnessConfig(
        cache_dir=cache_dir,
        jobs=args.jobs,
        sandbox_exec=sandbox_exec,
        tarpit=tarpit,
        tasks_dir=tasks_dir,
        timeout_seconds=args.timeout_seconds,
    )
    counts: Counter[str] = Counter()
    progress = ProgressReporter(total=len(projects))
    results_path = run_dir / "results.jsonl"
    report_stage("run", f"processing projects with {config.jobs} workers")
    with (
        results_path.open("w") as results,
        ThreadPoolExecutor(max_workers=config.jobs) as executor,
    ):
        futures = {
            executor.submit(process_project, project, config): project for project in projects
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            project = futures[future]
            try:
                result = future.result()
            except Exception as error:  # noqa: BLE001 - preserve unexpected worker failures
                result = finish_result(
                    result_record(project), time.monotonic(), "failed_metadata", str(error)
                )
            results.write(serialize_result(result))
            results.flush()
            counts[result["outcome"]] += 1
            progress.update(completed, counts, result)
    progress.finish()

    failed = sum(count for outcome, count in counts.items() if outcome.startswith("failed_"))
    summary = {
        "completed_at": datetime.now(UTC).isoformat(),
        "counts": dict(sorted(counts.items())),
        "failed": failed,
        "total_projects": len(projects),
        "total_ranked": len(projects) if ranked_selection else None,
    }
    write_json(run_dir / "summary.json", summary)
    manifest["completed_at"] = summary["completed_at"]
    write_json(run_dir / "manifest.json", manifest)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"artifacts: {run_dir}")
    report_stage("done", f"wrote run artifacts to {run_dir}")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run(parse_args(argv))
    except HarnessError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
