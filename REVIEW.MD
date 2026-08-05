# Branch review: Python bindings and archive correctness

Reviewed branch: `ww/py`, commit `875d29a`, against `origin/main`, commit
`6ed04c2`.

This is a temporary working document for tracking review findings. Delete it
before finalizing the branch unless there is a reason to retain it.

## P1: Aligned payload reads are not cancellation-safe

- [x] Resolved with a single cancellation-safe direct poll and existing
  partial-block buffering.
- Location: `crates/tar-framing/src/stream.rs:626`.
- Related public APIs: `crates/tar-framing/src/logical.rs:575` and
  `crates/tar-codec/src/decode.rs:533`.
- Python caller: `crates/tar-codec-python/src/codec.rs:873`.

`read_member_aligned_inner` stores partial progress in local variables owned by
the future. If the underlying reader produces some bytes and then returns
`Pending`, cancelling the future discards that progress while leaving the
underlying reader advanced. The parser's recorded position and remaining payload
length no longer match the actual stream.

Confirmed reproduction:

1. Construct an archive with a 1,024-byte file followed by another member.
2. Arrange for the reader to return `Pending` after 73 payload bytes.
3. Poll `read_aligned` until it returns `Pending`, then drop the future.
4. Resume with the existing `next_chunk` API.

The resumed payload starts at byte 73, and decoding the following member fails:

```text
aligned read before cancellation: Pending
resumed payload result: Ok(true)
resumed payload first byte: Some(73)
next member after cancelled aligned read: at byte 1536: invalid tar identity
```

The preexisting chunk and block APIs retain progress across cancellation, but
using `next_chunk` alone adds a buffer-to-Python copy for streaming payloads.
An optimized A/B benchmark with 31 alternating paired samples measured:

| Workload | Current aligned read | Existing `next_chunk` | Slowdown |
| --- | ---: | ---: | ---: |
| 16 MiB, `readinto` stream | 0.614 ms | 1.102 ms | 78% |
| 16 MiB, `read` stream | 0.570 ms | 1.059 ms | 86% |
| Mixed-size streaming members | 0.264 ms | 0.672 ms | 156% |
| 1,024 streaming 1 KiB members | 1.139 ms | 1.190 ms | 6% |
| 16 MiB, filesystem path | 1.079 ms | 1.547 ms | 46% |
| 16 MiB, immutable `bytes` or exact `BytesIO` | Unchanged | Unchanged | 0% |

The immutable sources are unaffected because they already use direct payload
views and never enter the streaming aligned-read path. Removing the direct-read
path entirely would therefore cause a significant regression for streams and
filesystem-backed archives.

A smaller cancellation-safe prototype preserved performance by polling the
underlying reader only once, committing complete 512-byte blocks immediately,
and storing at most 511 trailing bytes in the parser's existing `block` and
`block_len` fields. The existing cancellation-safe chunk reader then finishes any
partial block. Because there is no second await after bytes are consumed, the
future cannot suspend with progress stored only in local variables.

Measured prototype timings were 0.610 ms for a 16 MiB `readinto` stream,
0.553 ms for a `read` stream, 0.271 ms for mixed members, and 1.026 ms for a
filesystem path: effectively unchanged from the current direct-read path. The
prototype also removed 11 lines from the existing framing implementation,
preserved every payload byte in the cancellation reproduction, decoded the
following member successfully, and passed all 19 Python tests.

**Recommendation:** retain a direct-read fast path, replace its multi-read loop
with one poll, and reuse the existing partial-block storage and chunk reader.
Do not replace the entire path with `next_chunk` unless the measured streaming
regressions are acceptable.

Add coverage at the framing layer alongside the existing cancellation tests, and
cover any public API contract affected by the chosen fix.

## P1: Malformed in-memory archives control Python allocation size

- [x] Resolved by bounding fallback allocations to the available in-memory archive bytes.
- Location: `crates/tar-codec-python/src/codec.rs:1302`.

When a supposedly direct in-memory payload does not fit in the backing archive,
the binding falls back to the streaming path. `MemberPayload.read()` then
allocates a Python `bytes` object using the untrusted declared member size before
checking whether the archive actually contains that many bytes.

A 512-byte tar header claiming a 64 MiB member causes approximately 64 MiB of
allocation before reporting truncation:

```python
import tar_codec
import tarfile
import tracemalloc

metadata = tarfile.TarInfo("truncated")
metadata.size = 64 * 1024 * 1024
payload = next(
    tar_codec.TarArchive(metadata.tobuf(format=tarfile.GNU_FORMAT))
).payload
assert payload is not None

tracemalloc.start()
try:
    payload.read()
except tar_codec.DecodeError:
    pass

print(tracemalloc.get_traced_memory()[1])
```

Observed peak: `67,109,170` bytes. A header claiming `sys.maxsize` produces
`OverflowError: byte string is too large` instead of a decoding error.

For known in-memory archives, validate the declared payload and padding against
the available backing bytes before allocating. Add a focused Python API test
using a truncated header with an obviously impossible declared size.

## P2: Fused archives still expose stale payload handles

- [x] Resolved by making fused framing readers return no payload handle.
- Location: `crates/tar-codec/src/decode.rs:62`.
- Existing incomplete coverage: `crates/tar-codec/tests/members.rs:402`.

After a payload read fails, the underlying framing parser becomes fused, but
`TarArchive` remains in `ArchiveState::PayloadActive` until another
`next_member` call. Consequently, `archive.payload()` still returns `Some` after
the failure, even though the parser is no longer usable.

Confirmed reproduction:

```text
payload read failed: true
payload exposed after parser fused: true
next member exhausted after fusion: true
payload exposed after extra next call: false
```

The Python API consequently permits a second payload read, which reports a
different and misleading error about unexpected parser state.

The existing Rust tests assert that the payload disappears only after advancing
the archive. Add an assertion immediately after the failed payload read and make
payload availability reflect the framing parser's actual fused state.

## P2: Terminal decoding errors retain caller-owned streams

- [x] Resolved by releasing archive resources when terminal decoding errors are delivered.
- Location: `crates/tar-codec-python/src/codec.rs:739`.
- Related iterator path: `crates/tar-codec-python/src/codec.rs:1133`.

The normal end-of-archive branch drops the native archive, and the iterator
releases the caller-owned stream when it returns `StopIteration`. The decoding
error branch only queues an exception. That exception then propagates before the
stream-release path executes.

For both `io.BytesIO` and `io.BufferedReader`, a weak reference confirms that a
stream remains alive after a terminal `DecodeError`. It is released only after
calling `close()` or performing an otherwise unnecessary additional `next()`.

```text
stream retained after terminal decode error: True
stream retained after extra next call: False
```

Release terminal archive resources when the decoding error is delivered while
preserving any earlier pending member snapshots. Extend the existing stream
lifetime test with a failed-decoding case.

## P2: Immutable memoryviews are unnecessarily copied

- [x] Resolved by reusing contiguous full-span views backed by immutable bytes.
- Location: `crates/tar-codec-python/src/io.rs:157`.

`parse_bytes` calls `memoryview.tobytes()` unconditionally. This copies even a
contiguous, read-only memoryview backed by immutable `bytes`, where snapshotting
is unnecessary.

For an approximately 8 MiB archive:

```text
bytes constructor_peak_bytes: 64
immutable-memoryview constructor_peak_bytes: 8396897
```

Retain the immutable backing buffer directly whenever its ownership, contiguity,
and offset make that safe. Continue copying mutable sources and views whose
underlying storage can change; the existing snapshotting behavior must remain
intact.

Add a focused public API test that checks source identity or another direct
zero-copy property for an immutable contiguous view.

## P2: Closed payload exceptions depend on archive source type

- [x] Resolved by checking archive closure before streaming payload invalidation.
- Location: `crates/tar-codec-python/src/codec.rs:849`.
- Direct-payload comparison: `crates/tar-codec-python/src/codec.rs:615`.

After closing an archive, direct payloads check the archive's `closed` flag and
raise `RuntimeError("the archive is closed")`. Streaming payloads check only
their generation and instead raise `InvalidatedPayloadError`, incorrectly saying
that the archive cursor advanced.

```text
closed payload direct: RuntimeError the archive is closed
closed payload stream: InvalidatedPayloadError the member payload is no
longer active because the archive cursor advanced
```

Check the closed state before generation validation in the streaming path. Cover
both direct and streaming sources in a single existing payload-lifecycle test.

## P2: The public typing stub omits `DecodeError.position`

- [x] Resolved by removing the unnecessary Python-only `position` attribute.
- Location: `crates/tar-codec-python/python/tar_codec/_tar_codec.pyi:26`.
- Runtime implementation: `crates/tar-codec-python/src/codec.rs:1350`.

`map_decode_error` attaches an integer `position` attribute to decoding
exceptions, but the public stub declares `DecodeError` as an empty exception
class. This valid runtime code fails static checking:

```python
try:
    next(tar_codec.TarArchive(b"broken"))
except tar_codec.DecodeError as error:
    print(error.position)
```

Observed diagnostic:

```text
error[unresolved-attribute]: Object of type `DecodeError` has no attribute `position`
```

Declare `position: int` on the exception in the stub and include a focused
public API assertion that checks the actual position.

## P3: Python repeats the Rust PAX vendor-policy matrix

- [ ] Simplify.
- Python location: `crates/tar-codec-python/tests/test_codec.py:166`.
- Existing Rust coverage: `crates/tar-codec/tests/metadata.rs:278`.

The approximately 45-line Python test repeats exact-keyword matching, empty
allowlists, rejection, permissive policies, and both local and global PAX
scopes. These semantic combinations are already tested at the Rust integration
layer, which owns the behavior.

Keep the exhaustive matrix in Rust. Replace the Python matrix with a small
binding-focused test demonstrating that representative rejection and allowlist
policies are passed through correctly, including a dynamically owned keyword if
needed.

## P3: A standalone payload-invalidation test duplicates nearby coverage

- [ ] Simplify.
- Location: `crates/tar-codec-python/tests/test_codec.py:313`.
- Existing advance coverage: `crates/tar-codec-python/tests/test_codec.py:274`.
- Existing close coverage: `crates/tar-codec-python/tests/test_codec.py:476`.

The standalone test repeats advancement invalidation already covered across five
source types. Its close case also repeats the archive context-manager test. It
does not detect the actual direct-versus-streaming exception inconsistency.

Delete it or fold any useful assertions into the existing source-matrix test,
adding both source types when fixing the closed-payload exception behavior.

## Inherited issue: extraction writes can continue after cancellation

- [ ] Decide whether to fix in this branch or follow up separately.
- Branch location: `crates/archive-trait/src/extract/filesystem.rs:78`.
- Existing incomplete test:
  `crates/archive-trait/tests/extract.rs:476`.

Cancelling an extraction can leave a queued blocking file write detached. Once
the blocking worker becomes available, the write still mutates the destination
after the extraction task has already reported cancellation.

This is **not newly introduced by the branch**. It was reproduced separately
against both the branch and `origin/main`:

```text
origin/main: file size immediately after cancellation: 0
origin/main: file size after detached writer runs: 2097152

branch: file size immediately after cancellation: 0
branch: file size after detached writer runs: 4194304
```

The branch doubles the maximum demonstrated late write from 2 MiB to 4 MiB.
The existing cancellation test covers buffered small files but does not cover
streamed large payloads. If addressed, add the regression test at the
`archive-trait` extraction integration layer.

## Checks performed during review

These checks passed against the reviewed branch:

```text
uv run --no-sync python -m unittest discover crates/tar-codec-python/tests
cargo test -p tar-codec --test members
cargo test -p tar-framing resumes_cancelled_member_payload_chunk_with_either_read_api
cargo test -p archive-trait --test extract extracts_common_members_and_streams_payload_sizes
cargo test -p archive-trait --test extract cancelling_extraction_stops_pending_buffered_files
cargo test -p tar-codec --test metadata vendor_pax_allowlist_requires_exact_keywords_in_both_scopes
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
uv run --no-sync ruff check crates/tar-codec-python
uv run --no-sync ruff format --check crates/tar-codec-python
uv run --no-sync ty check
```

The Python suite contained 19 passing tests. The existing project-wide type
check passes because none of the checked source files currently accesses
`DecodeError.position`; a focused external typing reproduction fails as described
above.
