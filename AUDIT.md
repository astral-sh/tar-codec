# tar-codec PAX correctness and extraction security audit

Date: 2026-06-11  
Reviewed revision: `f347ec54f40d` (`main`)  
Primary reference: local POSIX.1-2024 `pax` specification at `~/Downloads/specs/pax.html`

## Executive summary

The implementation has a strong security-oriented structure. It separates physical framing, logical member assembly, and extraction; validates effective PAX names rather than the fallback ustar names; rejects mixed PAX/GNU framing; defers archive-created symlinks until all ordinary payload writes are complete; and does not follow existing destination symlinks while creating files or directories. I did not find a path by which archive payload bytes are written outside the extraction root under the documented no-concurrent-mutation assumption.

The audit did find three high-priority issues, all of which have since been remediated:

1. PAX extension payloads are buffered without a byte or record limit, allowing allocator exhaustion before extraction policy can inspect the records.
2. Applying global PAX state is quadratic in the number of records, with additional allocation for namespaced keywords, allowing disproportionate CPU consumption on the async executor thread.
3. Default extraction can create a symlink whose text is lexically contained but whose actual filesystem resolution escapes through a symlink already present inside the destination. This does not write archive payload outside the root during extraction, but it leaves an attacker-created path that resolves outside the root and can expose outside content to a subsequent consumer.

The remaining findings are correctness, interoperability, platform-hardening, or operational issues. Several are deliberate fail-closed choices already documented by the crate. They are still recorded because the stated goals include POSIX correctness and avoidance of parser differentials. AUD-04 and AUD-05 are retained as out-of-scope observations under the project's exclusion for purely OS/filesystem-specific behavior. AUD-06, AUD-07, AUD-09, and AUD-11 are likewise out of scope because they describe deliberate compatibility or precision boundaries documented by `tar-framing` rather than unintended behavior. The status column tracks work after the reviewed revision; the detailed findings retain the original analysis.

| ID | Severity | Status | Area | Summary |
| --- | --- | --- | --- | --- |
| AUD-01 | High | Remediated | Availability / PAX | Extension payloads are buffered without resource limits |
| AUD-02 | High | Remediated | Availability / PAX | Global PAX state updates have quadratic behavior |
| AUD-03 | High | Remediated | Extraction | Ambient destination symlinks can redirect an emitted symlink outside the root |
| AUD-04 | Medium | Out of scope | Windows extraction | NTFS interprets colon-containing names as alternate data streams |
| AUD-05 | Medium | Out of scope | Platform correctness | Symlink graph identity differs from case/normalization-insensitive filesystem identity |
| AUD-06 | Medium | Out of scope | Framing compatibility | Unknown POSIX typeflags are intentionally unsupported |
| AUD-07 | Medium | Out of scope | Framing compatibility | Metadata-only sizes on payload-free entries are intentionally rejected |
| AUD-08 | Medium | Remediated | PAX encoding | The encoder can emit a regular member that its decoder rejects as ambiguous |
| AUD-09 | Medium | Out of scope | PAX metadata | Timestamp precision is intentionally limited to nonnegative whole seconds |
| AUD-10 | Low | Remediated | PAX interoperability | Mixed-case vendor namespaces are rejected in the physical layer |
| AUD-11 | Low | Out of scope | PAX compatibility | Unsupported `hdrcharset` records are intentionally rejected even when overridden |
| AUD-12 | Low | Open | Operational safety | Extraction errors leave earlier output and overwrites in place |

Severity reflects the impact assessed against the reviewed revision when processing an untrusted archive in a service or developer-tool context. Status records the current disposition independently of that original severity.

## Scope and methodology

The review covered:

- PAX record grammar, typing, character-set handling, deletion, precedence, and global state in `crates/tar-framing/src/pax.rs`.
- Physical framing and format locking in `crates/tar-framing/src/stream.rs` and `header.rs`.
- Logical PAX/GNU assembly in `crates/tar-framing/src/logical.rs`.
- PAX encoding in `crates/tar-framing/src/write.rs` and `crates/tar-codec/src/encode.rs`.
- Effective-name decoding, policy enforcement, path normalization, link resolution, and filesystem extraction in `crates/tar-codec/src/decode.rs` and `decode/extract.rs`.
- The integration and unit tests under `crates/tar-codec/tests` and `crates/tar-framing/src`.

The normative comparison used the offline POSIX.1-2024 sections “pax Interchange Format,” “pax Header Block,” “pax Extended Header,” “pax Extended Header Keyword Precedence,” “pax Extended Header File Times,” and “ustar Interchange Format.” Findings were cross-checked against the documented threat model in `SECURITY.md`.

Validation included the complete `tar-framing` test suite, targeted extraction/link/metadata tests, and an independent local reproduction of AUD-03 using a PAX `linkpath` record. No fuzzing campaign, Windows runtime testing, or concurrent-mutation testing was performed. Concurrent mutation is outside the stated threat model.

## Findings

### AUD-01 — Extension payloads are buffered without resource limits

Severity: High  
Class: availability / memory exhaustion

`TarStream` accepts any nonzero PAX extension size parsed from the ustar header and initializes an unbounded `Vec<u8>` (`stream.rs:754-778`). Every payload block is appended to that vector, and parsing begins only after the entire declared payload has arrived (`stream.rs:563-581`). The parser then allocates owned values while the raw payload is still live (`pax.rs:230-405`).

The higher logical layer cannot enforce a policy before this happens: `TarReader::read_pax_extension` must wait for the completed parsed record set (`logical.rs:282-306`). A trailing global header is also fully buffered and parsed even though no ordinary member is ever returned for policy checking. GNU `L` and `K` metadata are subject to the same unbounded buffering in `logical.rs:309-346`.

An attacker can provide a valid `x` or `g` header with a multi-gigabyte size and stream that many bytes. The body need not be valid PAX syntax because validation happens at completion. If the archive is compressed, repeated metadata bytes can create substantial compressed-input-to-memory amplification. Rust allocation failure commonly aborts the process rather than returning a recoverable `FrameError`.

Recommended remediation:

- Add configurable limits for an individual extension's bytes, record count, keyword length, value length, cumulative active global metadata, and consecutive unattached global extensions.
- Reject an over-limit declaration when its header is read, before consuming or allocating its payload.
- Use fallible allocation (`try_reserve`) for permitted growth.
- Parse incrementally if supporting very large PAX headers is a requirement.
- Apply equivalent limits to GNU long-name and long-link metadata.

Tests should cover exactly-at-limit and one-byte-over-limit `x`, `g`, `L`, and `K` headers; fragmented multi-block records; cumulative limits across many global headers; and rejection before an over-limit body is consumed.

### AUD-02 — Global PAX state updates have quadratic behavior

Severity: High  
Class: availability / CPU exhaustion

The first global header calls `records_have_unique_keywords`, which compares each record with every predecessor (`pax.rs:522-530`, `549-555`). Updates to existing global state call `retain` over the active vector for every incoming record (`pax.rs:541-546`). For `realtime.*`, `security.*`, and vendor records, every `keyword()` comparison formats a new owned string (`pax.rs:206-226`). Effective lookups then reverse-scan this vector (`pax.rs:534-539`).

A valid global header containing `ACME.k0`, `ACME.k1`, …, `ACME.kN` therefore causes roughly `N²/2` comparisons. Repeated global updates cause a similar active-set-by-update product. This work occurs synchronously while processing the final extension block, so it can monopolize an async executor thread. The attack does not need a following member; a trailing global header is sufficient.

Recommended remediation:

- Give every parsed record a stable, non-allocating keyword key.
- Resolve duplicates and active global values with an indexed representation such as an insertion-ordered map or a vector plus key-to-slot map.
- Preserve source-order records separately where the public API requires them.
- Enforce a record-count limit independently of byte limits.

Tests should preserve last-record-wins and local-over-global semantics after the refactor. A non-wall-clock complexity test or benchmark should show approximately linear scaling when the record count doubles.

### AUD-03 — Ambient destination symlinks can redirect an emitted symlink outside the root

Severity: High  
Class: post-extraction containment / confused-deputy risk

Effective PAX `linkpath` is correctly selected before validation (`decode.rs:580-592`), but `normalize_symlink_target` proves only lexical containment (`decode.rs:672-730`). During installation, `resolve_terminal` consults only archive-maintained `entries` and `symlink_indices` maps (`decode/extract.rs:406-436`). An existing filesystem object not represented in those maps is classified as dangling. Dangling targets are allowed by default (`decode.rs:71-81`, `94-100`; `decode/extract.rs:380-401`). No existing target component is inspected for symlinks or reparse points.

Reproduction:

1. Before extraction, create `dest/redirect -> /outside` and `/outside/secret`.
2. Extract a symbolic-link member `alias` with a local PAX record `linkpath=redirect/secret`.
3. Default extraction succeeds and creates `dest/alias -> redirect/secret`.
4. Resolving or reading `dest/alias` reaches `/outside/secret`.

This was reproduced on the reviewed revision. No concurrent mutation was involved. The extraction operation itself did not write archive payload bytes outside `dest`; the issue is that it successfully created an attacker-controlled path whose actual resolution escapes the root. That distinction matters, but the result is unsafe for callers that consume extracted paths under the assumption that they remain contained.

`allow_symlinks(false)` and, for this sequence, `allow_dangling_symlinks(false)` mitigate the issue.

Recommended remediation:

- Prefer making “target is the extraction root or an archive-created entry” the default symlink policy.
- If ambient/dangling targets remain supported, walk all existing target components beneath a root directory handle without following symlinks/reparse points, and reject any link-valued component.
- Use root-handle-relative operations where platform APIs permit; string/canonical-path checks alone remain race-prone if the threat model is later expanded.

Add integration tests with both an intermediate and leaf ambient symlink, using PAX `linkpath`, and add Windows junction/reparse-point coverage.

### AUD-04 — NTFS interprets colon-containing names as alternate data streams

Disposition: Out of scope

Class: Windows-specific extraction hardening

The default name validator permits interior colons (`name.rs:11-16`). Extraction rejects backslashes, leading `/`, and platform prefixes, but otherwise accepts normal components (`decode.rs:616-649`, `733-757`). On Windows, `victim:payload` is not a drive prefix; it names an NTFS alternate data stream on `victim`.

`create_file` attempts `create_new` on `root.join(path)` before collision handling (`decode/extract.rs:200-223`, `469-489`). Consequently, an archive PAX path `victim:payload` can create a hidden stream attached to an existing ambient `victim`. It can do so without replacing the base file, including when `allow_overwrites(false)` is intended to prevent archive collisions with ambient state.

This finding is code-confirmed but was not runtime-tested on Windows. The repository's colon-path extraction test is Unix-only and therefore does not cover NTFS semantics.

This behavior does not escape the extraction root: it is a filesystem-specific interpretation of an otherwise valid archive pathname. `SECURITY.md` expressly excludes differentials caused purely by OS or filesystem behavior, and the default name validator is not intended to impose a portable filename subset or encode every destination filesystem's naming rules. Rejecting `:` unconditionally would also reject ordinary filenames supported by non-Windows filesystems.

No library remediation is planned. Applications that require portable names or Windows-specific restrictions can supply a custom name validator, which is applied to member paths and link targets.

### AUD-05 — Filesystem name equivalence differs from symlink graph identity

Disposition: Out of scope

Class: platform-specific correctness / link-cycle detection

The extraction graph keys `entries`, `symlink_indices`, and the visited set by exact `PathBuf` equality (`decode/extract.rs:60-67`, `406-435`). On a case-insensitive filesystem, the archive paths `A` and `B` can be distinct map keys even though link targets `a` and `b` resolve to those same filesystem objects.

This was reproduced on the reviewed revision on a case-insensitive macOS filesystem with PAX symlinks `A -> b` and `B -> a`. The graph classified both targets as dangling, installed the links, and produced a real filesystem cycle whose resolution fails with `ELOOP`. Canonically equivalent Unicode spellings create the same class on normalization-insensitive filesystems.

The AUD-03 remediation subsequently made `ArchiveOnly` the default symbolic-link target policy. Under that policy, a filesystem-equivalent target missed by exact `PathBuf` lookup is treated as unowned and rejected before links are installed. The default therefore fails closed rather than creating the cycle. `AllowAmbientAndMissing` may still install such a cycle, but that non-default policy explicitly permits targets outside the archive-created graph.

`SECURITY.md` expressly excludes filesystem-specific coalescing caused by case or Unicode normalization, and also excludes fail-closed differentials. Making graph identity reflect the destination filesystem would require platform-specific file identities and materializing or otherwise representing pending symlinks in the filesystem; simple Unicode lowercasing would not cover normalization, Windows aliases, or volume-specific case rules. That complexity is not justified within the current threat model, so no library remediation is planned.

### AUD-06 — Unknown POSIX typeflags are intentionally unsupported

Disposition: Out of scope

Class: POSIX correctness / fail-closed differential

Every ordinary PAX/ustar member is converted through `MemberKind::try_from_framed`, which accepts only typeflags `0` through `7` (`stream.rs:786-806`, `997-1012`).

The POSIX ustar section says that, for types other than the special payload-free types, `(size+511)/512` data records follow. It also says an unrecognized type with a meaningful data size is to be extracted as a regular file with a diagnostic. `A` through `Z` are expressly reserved for custom implementations. The physical framing of such a member is therefore knowable even when its semantics are not.

A POSIX header with typeflag `A`, size 3, payload `abc`, and a following member is currently rejected rather than framed. This is safe failure, but it prevents the logical/extraction layer from applying a strict policy or the POSIX regular-file fallback.

The `tar-framing` crate-level PAX compatibility notes explicitly document this deviation: undefined typeflags are rejected rather than treated as regular files because the compatibility benefit is marginal. This is a deliberate supported-format boundary, not an accidental parser limitation, and rejection is fail-closed. No remediation is planned.

### AUD-07 — Metadata-only sizes on payload-free entries are intentionally rejected

Disposition: Out of scope

Class: POSIX/PAX correctness / intentional fail-closed differential

PAX `size` deletion is rejected before member-kind handling (`stream.rs:801-805`). `validate_posix_member_size` also rejects every nonzero declared or effective size for directories, FIFOs, character devices, and block devices (`stream.rs:1016-1041`). Tests intentionally lock in these rejections.

POSIX specifies that:

- A directory size is an allocation hint and causes no data records.
- FIFO size is ignored when reading.
- Character/block-device size has unspecified metadata meaning, but no data records are stored.
- A zero-length PAX value deletes the corresponding field.

For those types, a deleted or nonzero `size` does not make physical framing ambiguous under a pedantic POSIX reading: zero payload blocks follow. The current directory rule is documented as an intentional anti-differential choice in `tar-framing/src/lib.rs` because real-world readers disagree about whether the declared size is metadata or physical payload. The implementation applies the same conservative payload-free invariant to FIFOs and device entries.

This is a deliberate framing policy that rejects potentially differential archive shapes before choosing an interpretation. It is documented, tested, and fail-closed, so no remediation is planned.

### AUD-08 — The encoder can emit a regular member that its decoder rejects as ambiguous

Severity: Medium  
Class: PAX encoding correctness / round-trip invariant

`Encoder::add_entry` passes its archive name through configurable character validation but does not reject a trailing separator (`encode.rs:103-125`, `543-560`). The lower PAX writer validates only that the path is nonempty and contains no NUL (`write.rs:186-211`). It therefore successfully emits a typeflag `0` member with a PAX `path` such as `file/`.

The decoder deliberately rejects that exact combination because some consumers interpret the trailing slash as a directory while others use the typeflag and create a regular file (`decode.rs:557-570`). This is the ambiguity the repository's security model says encoding should not produce.

The behavior was reproduced on the reviewed revision: `Encoder::add_entry("file/", b"payload", ...)` and `finish()` both succeeded, while default `Archive::extract` rejected the resulting archive at the ordinary member header with “only a directory may have a trailing separator.”

Reject trailing `/` for every non-directory `PaxMember` in the framing writer, and preferably return a more specific high-level encode error before writing any bytes. Add an integration test that exercises the public encoder and extractor together. Manual archive names that are absolute or contain parent components are an intentional API choice documented by `EncodePolicy`; this finding is narrower and concerns a wire-level member/type ambiguity.

### AUD-09 — Timestamp precision is intentionally limited to nonnegative whole seconds

Disposition: Out of scope

Class: PAX metadata compatibility / precision limitation

`PaxRecord::Atime` and `Mtime` store only `u64` seconds (`pax.rs:147-172`). `parse_time` validates fractional digits and then discards them (`pax.rs:458-489`). Tests explicitly assert that `12.034` becomes `12`, and `tar-framing/src/lib.rs` documents the deviation.

The PAX file-time section defines fractional digits as subsecond precision and requires restoration to the greatest representable time not greater than the archived time. On a nanosecond-capable filesystem, unconditional whole-second truncation is not the greatest representable value. The framing API consequently exposes a deliberately narrower timestamp model than the full PAX representation.

The `tar-framing` crate-level PAX compatibility notes explicitly document both whole-second truncation and rejection of negative or out-of-range timestamps. These are intentional API and compatibility boundaries rather than accidental information loss, so no remediation is planned.

### AUD-10 — Mixed-case vendor namespaces are rejected in the physical layer

Severity: Low  
Class: PAX interoperability / policy layering

`parse_namespaced_record` accepted only current standard keywords, `realtime.*`, `security.*`, or an all-uppercase ASCII namespace followed by a period (`pax.rs:321-379`). Other namespaced implementation extensions, such as `Acme.feature`, were rejected as `InvalidPaxKeyword` before `tar-codec` policy could decide whether unknown semantics were acceptable.

The PAX normative text permits listed keywords or implementation extensions and forbids `=` in the keyword. The uppercase `VENDOR.keyword` form appears in rationale as a suggested convention rather than a casing requirement. Rejecting unknown semantics by default remains prudent, and `PaxDecodePolicy` provides that higher-layer control.

This was remediated by accepting any nonempty namespace before the first period as a vendor identifier while preserving its original case. Standard keywords, `realtime.*`, and `security.*` retain their specialized representations; other dotted keywords remain vendor records and are still rejected by default extraction policy unless explicitly enabled.

### AUD-11 — Unsupported `hdrcharset` records are intentionally rejected even when overridden

Disposition: Out of scope

Class: PAX charset compatibility / precedence interoperability

`record_hdrcharset` parses every repeated charset and errors immediately on an unsupported value (`pax.rs:415-429`). The later typed-record pass also requires every occurrence to fit the closed enum (`pax.rs:315-318`, `408-413`). Thus `hdrcharset=PRIVATE` followed by `hdrcharset=BINARY` is rejected even though PAX duplicate precedence makes the final, supported value effective.

The PAX specification permits additional charset names by agreement and says the last conflicting local record wins. The `tar-framing` crate-level compatibility notes now explicitly state that this implementation, as the recipient, accepts only UTF-8 and `BINARY` and rejects every other `hdrcharset` record. Rejecting an unsupported occurrence before applying duplicate precedence is therefore a deliberate supported-format boundary rather than unintended behavior. No remediation is planned.

### AUD-12 — Extraction errors leave earlier output and overwrites in place

Severity: Low  
Class: operational safety / API contract

Extraction applies each member immediately (`decode/extract.rs:87-123`). A later framing or policy error returns without rollback. Existing integration tests explicitly assert that earlier files remain after later PAX-policy and framing failures (`tests/metadata.rs`). An attacker can therefore place or overwrite earlier files and deliberately trigger a late error.

This is common for streaming extractors and is not inherently incorrect, but the public `extract` documentation does not prominently state the partial-output contract. Callers may incorrectly treat `Err` as “nothing was extracted.”

Document the behavior and recommend extraction into a newly created staging directory followed by an atomic commit/rename. A transactional convenience API would make the safer pattern easier to use.

## Verified protections and non-findings

The following controls were specifically traced and, where applicable, covered by existing tests:

- PAX record lengths use checked decimal parsing, checked `usize` conversion, checked addition, payload bounds, required newline termination, a nonempty keyword, and an explicit `=` separator (`pax.rs:230-319`). No record-length arithmetic panic was found.
- Empty PAX extension payloads are rejected, matching the specification's “one or more records” requirement.
- Local records override global records, duplicate records use the final value when policy permits them, and deletion tombstones suppress the corresponding ustar fallback.
- `hdrcharset` is determined before decoding `gname`, `linkpath`, `path`, and `uname`, including inherited global state.
- PAX `size` controls regular-file and PAX hard-link payload framing. PAX hard-link data (`linkdata`) is supported and tested.
- Local `x` metadata must be followed immediately by an ordinary ustar member; duplicate/local extension ordering errors fail closed.
- Archive format locks after the first header. Mixed POSIX-PAX and GNU identities are rejected.
- Checksums, truncation, incomplete blocks, payload alignment, and the required two-zero-block end marker are validated. A zero-filled block inside a payload is treated as data rather than an end marker.
- Extraction validates the effective PAX/GNU path and link target, not the ignored fallback header fields.
- Member paths reject absolute paths, platform prefixes, backslashes, and every parent-directory component. Non-directory members cannot normalize to the extraction root, and non-directories with trailing separators are rejected.
- Archive-created symlinks are installed only after regular files, directories, and hard links have been processed. They therefore cannot redirect ordinary archive payload writes.
- Existing destination symlink parents and leaves are replaced without following them. The destination itself must be a real directory and is canonicalized before use.
- Lexically escaping symlink targets and exact-spelling symlink cycles are rejected; growing substitutions are bounded to 256 expansions.
- Hard links are disabled by default. When enabled, they must target a previously extracted in-map regular file; ambient, forward, self, and ancestor targets are rejected. PAX hard-link bodies update the shared inode as expected.
- Character devices, block devices, and FIFOs are never created by the extractor.
- Nonempty directories are not recursively replaced.
- The PAX writer's record-length convergence, header ordering, octal fallback, checksums, padding, and two-block terminator appear correct. No writer-side length or checksum defect was found.

## Remediation progress

- [x] Add PAX metadata resource limits (AUD-01).
- [x] Make global PAX state updates linear (AUD-02).
- [x] Close ambient-target resolution under the default symlink policy (AUD-03).
- [x] Reject encoder inputs that create member/type ambiguity before writing bytes (AUD-08).
- [x] Accept mixed-case vendor namespaces while retaining higher-level policy enforcement (AUD-10).
- [ ] Document partial extraction and offer a staging/transactional workflow (AUD-12).

## Suggested test expansion

After fixes are designed, prefer integration tests in `crates/tar-codec/tests` for whole-archive and filesystem behavior, with focused `tar-framing` unit tests for pure grammar/state helpers:

- Resource-limit boundary archives for PAX `x`/`g` and GNU `L`/`K`.
- Complexity regression coverage for many unique and repeatedly updated global keys.
- Ambient symlink/junction targets using effective PAX `linkpath`.
- Public encoder rejection of trailing-separator regular members, with no partial output.
- Differential fixtures produced by GNU tar, bsdtar/libarchive, Python `tarfile`, and Go's `archive/tar`, especially for duplicates, deletions, global state, binary names, and hard-link data.
