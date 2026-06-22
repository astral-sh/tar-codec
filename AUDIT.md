# Security audit findings

Date: 2026-06-22  
Reviewed commit: `92963bb`  
Scope: all workspace crates except the developer-only `tarpit` crate

This review uses [SECURITY.md](SECURITY.md) as its security contract and the
[POSIX.1-2024 Issue 8 pax specification](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/pax.html)
as its conformance baseline.

## Summary

| ID | Severity | Area | Finding | Status |
| --- | --- | --- | --- | --- |
| AUDIT-01 | High | Extraction | Deep paths cause quadratic time and memory | Fixed |
| AUDIT-02 | High | Encoding | Deep manual builder paths cause quadratic time and memory | Fixed |
| AUDIT-03 | Medium | Extraction | Directory-to-file replacement is quadratic | Fixed with AUDIT-01 |
| AUDIT-04 | Medium | Decoding policy | Global pax policy can be bypassed after a recoverable error | Fixed |
| AUDIT-05 | Medium | Pax decoding | Empty ustar `name` loses the separator after `prefix` | Fixed |
| AUDIT-06 | Low | Pax encoding | Encoded `devmajor` and `devminor` fields are invalid | Fixed |
| AUDIT-07 | Medium | Pax decoding | Ordinary ustar headers are incompletely validated | Open |
| AUDIT-08 | Medium | Pax decoding | Retaining a prior `PaxState` makes global updates quadratic | Open |
| AUDIT-09 | Medium | Encoding | Repeated `add_directory()` calls clone collision state quadratically | Open |

## Confirmed findings

### AUDIT-01: Deep extraction paths cause quadratic time and memory

Severity: **High**  
Security property: decoding must remain linear in time and memory

Status: **Fixed.** Extraction now keeps normalized archive paths in UTF-8 and
uses a component tree with stable node IDs, storing each path component once.
Full native paths are attached only to errors that are returned. A deep
ambient-path integration test exercises the expected create-error path without
relying on platform `PATH_MAX` limits.

Affected code:

- [`crates/archive-trait/src/extract/root.rs`](crates/archive-trait/src/extract/root.rs), especially `ensure_parents()` and `ensure_directory()` around lines 596-666

`ensure_parents()` constructs every complete ancestor prefix, and
`ensure_directory()` hashes and stores each complete `PathBuf`. A single valid
path of the form `a/a/.../a/file`, with encoded length L, therefore retains and
hashes a total of Θ(L²) path bytes.

There is no pathname-depth limit. Capability-relative traversal also avoids the
usual full-path `PATH_MAX` protection: a 5,004-byte, 2,500-component path
successfully extracted during testing.

Observed timings:

| Components | Time |
| ---: | ---: |
| 100 | 0.012 s |
| 200 | 0.029 s |
| 400 | 0.086 s |
| 800 | 0.430 s |
| 1,600 | 3.270 s |

Suggested direction: represent directory ancestry structurally rather than by
retaining every textual prefix, or enforce a defensible path-work budget.

Regression test: extract one increasingly deep member and assert that retained
path-state bytes or counted path work remain O(L).

### AUDIT-02: Deep manual builder paths cause quadratic time and memory

Severity: **High**  
Security property: encoding must remain linear in time and memory

Status: **Fixed.** Builder collision state now uses the component tree shared
with extraction, while preserving literal `/`-separated archive path identity.
Manual entries preflight without mutation and commit their component nodes only
after the format hook succeeds. Whole-state cloning by `add_directory()` remains
tracked separately as AUDIT-09.

Affected code:

- [`crates/archive-trait/src/builder.rs`](crates/archive-trait/src/builder.rs), especially `add_entry()` around lines 348-363 and `preflight_regular_entry()` around lines 797-813

For `a/a/.../a/file`, `preflight_regular_entry()` copies every textual ancestor
prefix. A successful write then permanently inserts all of those prefixes into
the collision map. A path of length L therefore retains Θ(L²) bytes before
encoding a single archive member. Default validation imposes no length or depth
bound.

A roughly 64 KiB path made from `a/` components requests about 1 GiB of prefix
string storage before allocator overhead.

Observed timings:

| Components | Time |
| ---: | ---: |
| 1,000 | 0.0063 s |
| 2,000 | 0.0256 s |
| 4,000 | 0.1032 s |
| 8,000 | 0.3903 s |

Suggested direction: use component-oriented collision state or another
representation that does not own every prefix of a single entry.

Regression test: add one deep entry through a no-op `ArchiveBuilder` and assert
linear collision-state storage and work.

### AUDIT-03: Directory-to-file replacement is quadratic

Severity: **Medium**  
Security property: extraction must remain linear in time

Status: **Fixed with AUDIT-01.** Each tree node maintains its number of active
direct children, so replacement eligibility is constant-time and tombstoned
children do not block later replacements.

Affected code:

- [`crates/archive-trait/src/extract/root.rs`](crates/archive-trait/src/extract/root.rs), especially `queue_buffered_file()` around lines 475-524 and `can_replace()` around lines 692-708

For a tracked directory, `can_replace()` scans every entry looking for a
descendant. The following valid default-policy archive therefore requires
Θ(N²) entry checks:

1. N distinct empty directory members.
2. N zero-byte regular members replacing those same paths.

Each replacement has no descendants, so every scan exhausts the N-entry map.
Buffered-file batch limits do not bound this scan.

Observed timings:

| Entries per phase | Time |
| ---: | ---: |
| 4,000 | 3.15 s |
| 8,000 | 10.84 s |

Suggested direction: maintain indexed child/descendant counts or hierarchical
state so emptiness can be decided without scanning unrelated entries.

Regression test: instrument descendant checks for the two-phase archive above
and require O(N) aggregate work.

### AUDIT-04: Global pax policy can be bypassed after an error

Severity: **Medium**  
Security property: rejected or ambiguous metadata must not become effective

Status: **Fixed.** `TarArchive` member iteration is now fused after the first
framing, policy, or projection error. Later calls return end-of-archive, so
global state applied by the lower framing layer cannot become observable after
the decode policy rejects its originating extension. An integration regression
test covers the forbidden-global-path sequence below.

Affected code:

- [`crates/tar-codec/src/decode.rs`](crates/tar-codec/src/decode.rs), especially `check_member()` around lines 129-167 and `next_member()` around lines 419-426
- [`crates/tar-framing/src/logical.rs`](crates/tar-framing/src/logical.rs), around lines 339-346
- [`crates/tar-framing/src/stream.rs`](crates/tar-framing/src/stream.rs), around lines 761-770

A global extension is applied to persistent `global_pax_records` before
`TarArchive` applies `DecodePolicy`. The positioned extension is attached only
to the first following member and removed with `mem::take()`.

If a direct member consumer handles the first policy error and calls
`Members::next()` again, later members inherit the forbidden global state but
have no newly encountered extension for `check_member()` to inspect. This
affects:

- `allow_global_pax_extensions(false)`
- the default ban on global `path`, `linkpath`, and `size`
- forbidden global vendor records
- duplicate-record policy for global headers

Minimal behavior:

```rust
let mut archive = ArchiveBuilder::new();
archive
    .pax(b'g', &pax_record(PaxKeyword::Path, "forbidden"))
    .posix("first", b'0', b"", "", 0o644)
    .posix("second", b'0', b"payload", "", 0o644);

let bytes = archive.finish();
let mut members = TarArchive::new(bytes.as_slice()).members();

assert!(matches!(
    members.next().await,
    Err(DecodeError::PolicyViolation { .. })
));

assert!(matches!(
    members.next().await,
    Ok(Some(Member::File { metadata, .. })) if metadata.path == "forbidden"
));
```

Default `extract_in()` stops at the first error, so exploitation requires a
direct consumer that continues after an error. No current API contract states
that policy errors are terminal.

Suggested direction: fuse or poison `TarArchive` after upper-layer validation
errors, or validate active global state on every member.

### AUDIT-05: Empty ustar `name` loses the separator after `prefix`

Severity: **Medium**  
Security property: ambiguous or malformed pax streams must be rejected instead of reinterpreted

Status: **Fixed.** Ustar path reconstruction now appends the required `/`
whenever `prefix` is nonempty, including when `name` is empty. Prefix-only
directory members remain accepted as required by POSIX, while the extraction
policy rejects the resulting directory-required suffix for regular files and
other non-directory members. Regression tests cover both outcomes.

Affected code:

- [`crates/tar-framing/src/stream.rs`](crates/tar-framing/src/stream.rs), `HeaderFrame::copy_header_path_into()` around lines 161-177
- [`crates/archive-trait/src/extract/path.rs`](crates/archive-trait/src/extract/path.rs), the bypassed directory-suffix check around lines 24-37

POSIX forms the pathname from every nonempty prefix as
`prefix + "/" + name`. The implementation appends `/` only when `name` is
nonempty. Thus `prefix="victim"` and an empty `name` represents `victim/`
under POSIX but is exposed as `victim`.

For a regular file or link, this erases the directory-required suffix and
bypasses the deliberate rejection of non-directory members ending in `/`. A
checksum-correct header can therefore create or replace `victim` instead of
being rejected.

Suggested direction: append `/` whenever `prefix` is nonempty, then let the
existing effective-path policy reject incompatible member kinds.

### AUDIT-06: Encoded `devmajor` and `devminor` fields are invalid

Severity: **Low**
Security property: encoding must always produce valid, unambiguous pax

Status: **Fixed.** Every emitted pax extension and ordinary member header now
encodes numeric zero in `devmajor` and `devminor`. Decoding remains deliberately
tolerant of all-NUL unused device fields, which are ignored by tar-codec and
emitted by GNU tar for non-device members.

Affected code:

- [`crates/tar-framing/src/write.rs`](crates/tar-framing/src/write.rs), `build_header_into()` around lines 317-348

`build_header_into()` encodes `mode`, `uid`, `gid`, `size`, and `mtime`, but
leaves `devmajor` and `devminor` as eight NUL bytes in every ordinary header.
POSIX classifies these as numeric fields and requires a leading-zero-filled
octal number followed by one or more NUL or space terminators. Eight NUL bytes
contain no octal number.

This affects every encoded regular, directory, and symbolic-link member. The
device-specific latitude for typeflags 3 and 4 does not apply because the
encoder does not emit those kinds.

Suggested direction: define the device field ranges alongside the other header
ranges and encode zero with the same strict octal helper.

Regression test: validate every numeric field in both the generated `x` header
and ordinary member header using the decoder's strict numeric parser.

### AUDIT-07: Ordinary ustar headers are incompletely validated

Severity: **Medium**  
Security property: malformed pax streams must be rejected

Affected code:

- [`crates/tar-framing/src/stream.rs`](crates/tar-framing/src/stream.rs), `ParsedHeader::try_from_framed()` around lines 1173-1209
- [`crates/tar-framing/src/logical.rs`](crates/tar-framing/src/logical.rs), lazy mode parsing around lines 72-80
- [`crates/tar-codec/src/decode.rs`](crates/tar-codec/src/decode.rs), mode projection around lines 433-437

Ordinary POSIX headers validate identity, checksum, and size, with mode parsed
later. They do not validate:

- `uid`, `gid`, or `mtime`
- `devmajor` or `devminor`
- required NUL termination of `uname` and `gname`
- the POSIX 12-bit domain of `mode`

A checksum-correct bare member with `uid = b"not-octal"` is currently accepted
and extracted. A mode such as `7777777\0` is also accepted, with the codec only
testing its executable bits.

Validation must account for pax precedence: an overridden header field may be
ignored. The concrete reproductions use bare, unoverridden ordinary headers.

The existing test header builders also leave several numeric fields all-NUL,
which currently hides this gap and will need correction alongside stricter
validation.

Suggested direction: centralize ordinary-header field validation and validate
all non-overridden fields before emitting a member frame.

### AUDIT-08: Retaining a prior `PaxState` makes global updates quadratic

Severity: **Medium**  
Security property: consumer-facing decoding APIs must remain linear

Affected code:

- [`crates/tar-framing/src/pax.rs`](crates/tar-framing/src/pax.rs), global state around lines 146-165, snapshots around lines 215-235, and `Arc::make_mut()` around lines 594-597
- [`crates/tar-framing/src/logical.rs`](crates/tar-framing/src/logical.rs), member snapshot construction around lines 339-346
- [`crates/tar-framing/src/stream.rs`](crates/tar-framing/src/stream.rs), cumulative-limit reset around lines 1011-1013

A direct `TarReader` consumer can retain the preceding member's owned
`PaxState` while requesting the next member. Every new global update then calls
`Arc::make_mut()` while the state is shared, cloning the complete accumulated
record vector and index.

The repro repeated a valid global `realtime.kN=value` record followed by an
empty ordinary member while retaining only the immediately preceding state:

| Members | Drop states | Retain previous state |
| ---: | ---: | ---: |
| 1,000 | 8.85 ms | 47.86 ms |
| 2,000 | 17.92 ms | 171.47 ms |
| 4,000 | 40.42 ms | 686.26 ms |
| 8,000 | 69.99 ms | 2.774 s |

Retained-state time approaches 4× per doubling while the baseline remains near
2×. Retaining all returned states also causes quadratic memory usage.

Suggested direction: use a persistent/structurally shared map for active global
state, or otherwise prevent each snapshot update from cloning all prior state.

### AUDIT-09: Repeated `add_directory()` calls clone collision state quadratically

Severity: **Medium**  
Security property: encoding must remain linear in time

Affected code:

- [`crates/archive-trait/src/builder.rs`](crates/archive-trait/src/builder.rs), `add_directory()` around lines 374-415

Every call clones the complete collision map before recursive traversal and
replaces the original map on success. Calling `add_directory()` N times for N
distinct empty roots copies `0 + 1 + ... + N-1` entries, producing Θ(N²) work
for Θ(N) aggregate source entries. Peak memory remains linear.

Observed timings:

| Calls | Time |
| ---: | ---: |
| 8,000 | 2.05 s |
| 16,000 | 7.24 s |

Suggested direction: use an undo log or staged mutations rather than cloning
all prior collision state for each transaction.

## Conditional and policy notes

### Global member metadata amplification

When `allow_global_pax_member_metadata(true)` is enabled, one M-byte global
`path` or `linkpath` is copied into a new `String` for each of N member headers
in [`crates/tar-codec/src/decode.rs`](crates/tar-codec/src/decode.rs), around
lines 437-452. This produces Θ(NM) projection work from Θ(N*512 + M) physical
archive bytes.

The default policy forbids this metadata and the default extension-size limit
bounds the amplification factor. Treat this as an additional medium finding if
the linearity guarantee is intended to cover non-default, unbounded policy
settings; otherwise it is a documented-policy hardening concern.

### Legacy `ctime` compatibility

[`crates/tar-framing/src/pax.rs`](crates/tar-framing/src/pax.rs) intentionally
accepts the pre-Issue-8 bare `ctime` keyword. POSIX.1-2024 omits it and reserves
the lowercase namespace for future standardization, but also allows
implementation extensions. The value does not affect high-level extraction.

This was not classified as a SECURITY vulnerability. If project policy means
"only currently standardized bare keywords", `ctime` should be removed or
placed behind an explicit legacy-compatibility policy.

### Intentional N log N traversal sorting

`WalkDir::sort_by_file_name()` makes a flat directory traversal N log N. This
was not classified as a finding because deterministic ordering is intentional
and the stated performance target permits behavior "close to" linear.

## Areas reviewed without additional findings

- Extraction-root containment and capability-relative filesystem access
- Absolute paths, parent traversal, platform prefixes, and backslash handling
- Deferred symbolic-link creation, cycle detection, and resolution work limits
- Default hard-link prohibition and archive-owned target requirements
- No-follow replacement and refusal to recursively remove nonempty directories
- Builder poisoning and rollback after cancellation or partial output
- Blocking traversal/channel ownership and deadlock behavior
- Payload, extension, and traversal lookahead bounds outside the findings above
- Pax/GNU family locking and extension ordering
- Effective-size framing, payload draining, truncation, and two-block termination
- Cancellation across partial blocks, chunks, automatic drains, and extension assembly
- Pax record length parsing, precedence, deletion, duplicate handling, and arithmetic

No extraction-root escape, cancellation-state corruption, or deadlock issue was
identified.

## Validation performed

- `cargo test --workspace --exclude tarpit`: 151 tests passed
- `cargo clippy --workspace --exclude tarpit --all-targets -- -D warnings`: passed
- `cargo fmt --all --check`: passed
- `cargo audit`: 172 locked dependencies scanned; no advisories reported
- Focused out-of-tree timing and behavior repros for the complexity and policy findings

No source files other than this temporary audit report were changed.
