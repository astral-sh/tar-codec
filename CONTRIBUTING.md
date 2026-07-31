# CONTRIBUTING

## Architecture

There are a few important architectural divisions/separations of concerns
to be aware of when making changes.

Archive reading has four abstraction layers, from lowest to highest:

- tar-framing: the _physical_ layer turns an asynchronous input source into a
  stream of tar blocks according to the pax or GNU tar state machine.
  This is the lowest level of abstraction.
- tar-framing: the _logical_ layer turns a stream of blocks from the physical layer
  into a stream of _assembled members_, i.e. tar entries along with
  their relevant pax or GNU metadata.
- tar-codec: the _decode_ layer validates tar-specific policy and projects
  assembled tar members into the format-neutral archive member model.
- archive-trait: the _extract_ layer turns format-neutral archive members into
  files, directories, links, and other destination state on disk.

Archive building follows the same separation in reverse:

- archive-trait: the _build_ layer wraps format writers in a stateful engine
  that owns entry addition, name validation, collision tracking, recursive
  filesystem traversal, source streaming, and poisoning semantics.
- tar-codec: the _encode_ layer implements the format-writer hooks that project
  generic build operations into pax members and owns tar framing, padding,
  sequence numbers, and terminators.
- tar-framing: the _physical_ write layer serializes individual pax members.

These layers/concerns should be preserved when making changes.
For example, any change that affects framing (which blocks are considered
headers, extensions, data, etc.) should occur in the physical layer, while a
change to source traversal, path containment, or filesystem behavior belongs in
`archive-trait`.

## Formatting and linting

Linting and formatting:

```shell
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

Run tests:

```shell
cargo test
```

In general, integration tests are preferred over unit tests. Unit tests
should be used primarily for small, pure private helpers.

## Benchmarking

Run the headline public API comparison benchmarks with:

```shell
cargo bench -p tar-codec --bench comparison
```

The benchmarks compare `tar-codec` against `tar` and `astral-tokio-tar` for
uncompressed encoding and extraction.

Run the larger filesystem extraction diagnostic matrix separately with:

```shell
cargo bench -p tar-codec --bench extraction_filesystem
```

Run both targets when refreshing the benchmark snapshot in [BENCHMARKS](./BENCHMARKS.md)

## Torture testing

Run `tar-codec` against the newest non-yanked `.tar.gz` source distribution
for each of the top 10,000 PyPI projects:

```shell
python3 scripts/torture_pypi_sdists.py
```

The harness builds the debug `tarpit` binary, caches verified archives, writes
reports beneath `target/tarpit-pypi`, shows live progress on the terminal, and
uses `sandbox-exec` on macOS to restrict extraction writes to a fresh temporary
directory. It reports stale task directories left by interrupted runs without
deleting them. On other platforms, or when running inside an existing sandbox
that cannot nest `sandbox-exec`, pass `--no-sandbox` to explicitly rely on the
temporary directory and `tar-codec` capability checks alone. Use `--limit` for
a smaller smoke test, or `--project logging` to reproduce one PyPI project
without fetching the ranking dump.

To recheck only failures from an earlier run, pass its JSONL report:

```shell
python3 scripts/torture_pypi_sdists.py \
  --rerun-failures target/tarpit-pypi/runs/<timestamp>/results.jsonl
```

This skips the ranking download, reruns every `failed_*` outcome, and saves a
snapshot of the input report in the new run directory.
