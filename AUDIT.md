# tar-codec extraction differential audit

Date: 2026-06-11  
Reviewed revision: `271392be6d05d8beefbfd91e20190abf766a41bd` (`main`)  
Previous audit: [`AUDIT.md` at `6d4a69d`](https://github.com/astral-sh/tar-codec/blob/6d4a69dfd99b7294b6cc242269f7dec10eeb12a8/AUDIT.md)  
Primary oracle: [POSIX.1-2024 `pax`](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/pax.html)

## Executive summary

This audit compared default `tar-codec` extraction with GNU tar 1.35 and bsdtar/libarchive 3.7.4, concentrating on PAX metadata, precedence, ordering, and the final filesystem tree. It records 20 root-cause-level differentials. Variants of one rule are grouped, and accepted findings from the previous audit are not recycled into the count.

Most differentials are desirable fail-closed behavior. `tar-codec` is safer than the comparison tools for duplicate or unknown PAX records, malformed extension ordering, embedded NULs, deleted required fields, absolute paths, and incomplete end markers. Some results are comparison-tool bugs: libarchive ignores global PAX state and deletion tombstones, while GNU tar mishandles PAX hard-link data.

Six findings need a decision or remediation because default extraction succeeds with a materially different tree or metadata rather than failing closed:

1. Archived modes can widen from `0600` to `0644` or `0700` to `0755`.
2. Symlink text is simplified before installation; `target/` and `target/.` become `target`, turning a dangling link into a live link to a regular file.
3. A later descendant silently replaces an earlier non-directory ancestor with a directory.
4. A regular PAX path ending in `/.` bypasses the trailing-separator ambiguity check.
5. PAX ownership is accepted but ignored, potentially leaving untrusted archive output owned by a privileged extracting identity.
6. PAX access and modification times are accepted but ignored.

The first four are the strongest security-differential results. Mode widening can expose private data. The link and `/.` cases change object reachability or type. Parent promotion discards an earlier archive member and chooses a third filesystem interpretation rather than rejecting an ambiguous sequence.

| ID | Severity | Disposition | Differential |
| --- | --- | --- | --- |
| DIF-01 | High | Needs remediation | Archived modes can be widened |
| DIF-02 | Medium | Needs remediation | Symlink normalization changes installed text and reachability |
| DIF-03 | Medium | Needs remediation | Non-directory archive ancestors are promoted to directories |
| DIF-04 | Medium | Needs remediation | `/.` bypasses regular-file trailing-separator rejection |
| DIF-05 | Medium | Needs decision | PAX ownership is accepted but not applied |
| DIF-06 | Low | Needs decision | PAX timestamps are accepted but not applied |
| DIF-07 | Medium | Documented opt-in risk | Unknown vendor records can hide path/sparse semantics |
| DIF-08 | Informational | Expected fail-closed | Duplicate local PAX records are rejected by default |
| DIF-09 | Informational | Expected fail-closed | Unknown vendor records are rejected by default |
| DIF-10 | Informational | Expected fail-closed | Unknown unnamespaced keywords are rejected structurally |
| DIF-11 | Informational | Fail-closed / libarchive fault | Global PAX metadata splits GNU tar and libarchive |
| DIF-12 | Informational | Expected fail-closed | Interposed PAX extensions are accepted by peers |
| DIF-13 | Informational | Peer permissiveness | Empty PAX extensions are treated as no-ops |
| DIF-14 | Informational | GNU permissiveness | GNU accepts an orphan local PAX header |
| DIF-15 | Informational | Peer fault | Peers truncate PAX paths at embedded NULs |
| DIF-16 | Informational | Peer fault / fail-closed | Peers mishandle PAX deletion tombstones |
| DIF-17 | Informational | GNU fault | GNU mishandles PAX hard-link payload data |
| DIF-18 | Informational | Expected fail-closed | Binary non-UTF-8 PAX names are not extractable |
| DIF-19 | Informational | Expected fail-closed | Absolute and backslash PAX names are handled strictly |
| DIF-20 | Informational | Expected fail-closed | One or zero end blocks are accepted by peers |

## Scope and methodology

The review covered PAX parsing and state in `crates/tar-framing/src/pax.rs`, physical framing in `stream.rs`, effective metadata in `logical.rs`, policy and normalization in `crates/tar-codec/src/decode.rs`, filesystem extraction in `decode/extract.rs`, and existing integration tests.

Fixtures were raw 512-byte ustar/PAX streams with exact checksums and record lengths. Unless malformed input was the subject, archives had correct padding and two zero end blocks. Each was extracted into a new directory with:

```text
target/debug/tarpit extract ARCHIVE TAR_CODEC_OUT
gtar -xf ARCHIVE -C GNU_OUT
bsdtar -xf ARCHIVE -C LIBARCHIVE_OUT
```

Principal versions were GNU tar 1.35, and bsdtar 3.5.3 linked with libarchive 3.7.4 on macOS. Ownership was confirmed as root with GNU tar 1.35 in Debian 13 and libarchive 3.6.2 in Linux containers. Results were inspected by status, type, contents, symlink text, mode, timestamps, and ownership. Selected behavior was corroborated in current GNU tar and libarchive source.

This was directed differential testing, not fuzzing. Windows, ACLs, extended attributes, privileged device creation, concurrent destination mutation, and every GNU sparse revision were not tested. Notation below uses `x{...}` for a local PAX header and `g{...}` for a global one.

## Findings requiring action or a decision

### DIF-01 — Archived modes can be widened

Severity: High  
Class: default fail-open metadata differential

For ordinary members `file("private", 0600)` and `directory("private-dir", 0700)`, GNU tar and libarchive preserve `0600` and `0700`. With umask `022`, `tar-codec` creates `0644` and `0755`.

`decode_member` reduces the entire mode to `mode & 0o111 != 0` (`decode.rs:579-581`). Files are created with `0666` or `0777` (`decode/extract.rs:572-590`), directories use ordinary creation defaults, and no final pass narrows permissions. A private `0600` payload can therefore become readable by other local users.

Carry permission bits through decoding, create payloads with restrictive temporary modes, and apply final file and deferred directory modes after writing. Decide explicitly how set-id, sticky, and unsupported bits are handled. Add Unix integration cases for `0000`, `0600`, `0640`, `0700`, and asymmetric execute bits under a controlled umask.

### DIF-02 — Symlink normalization changes link contents and reachability

Severity: Medium  
Class: default fail-open PAX link differential

Reproduction:

```text
file("target", "X")
x{path=link, linkpath=target/.} -> symlink
```

The same occurs for `linkpath=target/`. GNU tar and libarchive preserve the exact archived link text. Because `target` is regular, their links fail to resolve with directory-required suffixes. `tar-codec` installs `link -> target`, which is live and reads `X`.

`normalize_symlink_target` discards `CurDir`, trailing separators, and cancellable components (`decode.rs:705-763`). `reserve_symlink` stores that rewritten value as `link_contents` (`decode/extract.rs:283-297`), and installation writes it. POSIX defines `linkpath` as the link's contents, not just a lexically similar destination. The transformation is not resolution-preserving: `regular/../other` can likewise erase `ENOTDIR`.

Preserve the original validated relative target for installation and keep a separate normalized root-relative target for containment/graph checks. If the graph cannot model a spelling safely, reject it. Test `target/`, `target/.`, `directory/.`, and `regular/../other`.

### DIF-03 — Non-directory ancestors are silently promoted to directories

Severity: Medium  
Class: default output-tree differential

Reproduction:

```text
file("parent", "OLD")
x{path=parent/child} -> file("raw", "NEW")
```

GNU tar and libarchive retain regular file `parent`, reject the child with `ENOTDIR`, and fail. `tar-codec` succeeds, deletes `parent`, creates a directory, and writes `parent/child`.

`ensure_parents` passes implicit ancestors to `ensure_directory` (`decode/extract.rs:351-360`), which replaces any known non-directory entry (`decode/extract.rs:363-404`). This conflates an explicit directory replacing an exact path with implicit parent synthesis.

A symlink variant is three-way: after `alias -> real`, a later `alias/child` makes GNU write through the link, libarchive retain the link and reject, and `tar-codec` discard its pending link and create a real `alias` directory. GNU's behavior is unsuitable for secure extraction, but `tar-codec` should fail closed like libarchive rather than select a third tree.

Reject implicit parent creation through any earlier non-directory archive entry. Add regular-file, hard-link, and pending-symlink ancestor tests.

### DIF-04 — `/.` bypasses regular-file trailing-separator rejection

Severity: Medium  
Class: default PAX path type differential

For `x{path=thing/.} -> regular("raw", "X")`, `tar-codec` succeeds and creates regular file `thing`. Libarchive 3.7.4 does likewise. GNU tar treats the name as directory-shaped, creates directory `thing`, then fails to open `thing/.` as regular output.

The ambiguity check only tests `path_text.ends_with('/')` (`decode.rs:590-603`). Normalization then discards terminal `Component::CurDir` (`decode.rs:649-682`). This bypasses the same type ambiguity that motivated rejecting `file/`.

Reject non-directory members whose original path has directory-required terminal syntax, including a final `.` component. Test `file/.`, `file//.`, and directory members with the same spellings.

### DIF-05 — PAX ownership is accepted but not applied

Severity: Medium  
Class: metadata differential / possible privilege confusion

For `x{uid=1234, gid=2345} -> file("owned", "X")`, GNU tar and libarchive restore `1234:2345` when privileged. `tar-codec` accepts both records but leaves extractor ownership.

`uid`, `gid`, `uname`, and `gname` are typed (`pax.rs:430-450`) but never enter `DecodedMember`, and extraction performs no ownership operation. In a privileged service, attacker-controlled content can consequently appear service- or root-owned and mislead later ownership-based trust decisions.

Either restore ownership behind an explicit privileged policy, including name-over-numeric precedence, or reject ownership records when they will not be honored. “Extract as caller” should be explicit rather than silent.

### DIF-06 — PAX timestamps are accepted but not applied

Severity: Low  
Class: metadata differential

For `x{mtime=1.25} -> file("timed", "X")`, GNU tar and libarchive restore 1.25 seconds after the Epoch; `tar-codec` leaves extraction time. Ordinary whole-second `mtime`, persistent global `mtime`, and `atime` are also ignored.

This differs from the previous audit's timestamp precision boundary: even values parsed without loss are never applied. Restore supported timestamps after writes, or reject records whose semantics extraction intentionally omits.

### DIF-07 — Unknown vendor opt-in can ignore path and sparse semantics

Severity: Medium  
Class: explicit non-default fail-open policy

With `allow_unknown_pax_vendor_records(true)`, `x{GNU.sparse.name=sparse-name} -> file("raw", "ok")` is extracted as `raw`; libarchive extracts `sparse-name`, and GNU sparse metadata can also alter logical size and payload mapping.

Default extraction rejects this archive, so the default is safe. Policy documentation already warns about exactly this risk. Keep the option visibly dangerous, and consider always rejecting known semantic families such as `GNU.sparse.*` unless their complete versioned semantics are implemented.

## Expected fail-closed differentials and peer faults

### DIF-08 — Duplicate local records are rejected by default

For `x{path=first, path=second} -> file("raw", "X")`, GNU tar and libarchive extract `second` using POSIX last-wins precedence. Default `tar-codec` rejects duplicates (`decode.rs:377-389`). The explicit opt-in selects the last record (`pax.rs:641-645`) and matches peers. This is an intentional anti-differential default.

### DIF-09 — Unknown vendor records are rejected by default

For `x{LIB.test=value}`, GNU tar and libarchive ignore the record and extract. `tar-codec` parses it but rejects it by default (`decode.rs:346-358`). This is sound because unknown vendor records may carry DIF-07-style semantics.

### DIF-10 — Unknown unnamespaced keywords are structurally rejected

For `x{mystery=value}`, peers ignore or warn and extract; `tar-codec` rejects because unknown keywords must have a nonempty namespace and suffix (`pax.rs:454-486`). This safely rejects future standard keywords before policy can see them. A generic unknown record could preserve default rejection while making the framing layer forward-compatible.

### DIF-11 — Global metadata splits GNU tar and libarchive

Fixtures for `g{path=global}`, `g{linkpath=globaltarget}`, and `g{size=1}` show GNU tar applying all three persistent values. Libarchive ignores the global payload and uses ordinary name, linkname, and size. Current libarchive source confirms that `header_pax_global` only consumes the body.

POSIX says each global value affects following files until overridden or replaced, so GNU is the conforming oracle. `tar-codec` framing also applies the state, but default extraction rejects global identity/framing records (`decode.rs:360-375`). With the explicit opt-in it matches GNU and differs from libarchive. The default rejection is a sound response to an ecosystem split.

### DIF-12 — Interposed PAX extensions are accepted by peers

`x{path=first} -> x{path=second} -> member` and `x{path=local} -> g{comment=global} -> member` are rejected because a local header must immediately precede its ustar member (`stream.rs:620-637`). GNU extracts using surviving metadata. Libarchive creates output too, though it reports malformed PAX for `x -> x`. POSIX supports the strict ordering; keep the rejection.

### DIF-13 — Empty PAX extensions are treated as no-ops

A zero-size `x` or `g` is rejected because an extension must contain one or more records (`stream.rs:763-784`; `pax.rs:339-349`). GNU tar and tested libarchive extraction treat them as no-ops. The archive is invalid; keep failing closed.

### DIF-14 — GNU accepts an orphan local header

For `x{path=orphan} -> end marker`, `tar-codec` rejects while awaiting the required ordinary header, libarchive reports damage, and GNU tar 1.35 succeeds with no output. Accepting this hides truncation; the strict behavior is correct.

### DIF-15 — Peers truncate paths at embedded NULs

For `x{path=before\0after}`, GNU tar and libarchive create `before`; `tar-codec` rejects (`logical.rs:105-120`, `497-504`). POSIX says NUL does not delimit a PAX value. Since a filesystem path cannot represent it, rejection is lossless and safe; prefix truncation is a peer fault.

### DIF-16 — Peers mishandle deletion tombstones

Zero-length values delete corresponding PAX, global, and ordinary-header fields. `tar-codec` retains the tombstone and errors if a required field disappears (`logical.rs:521-540`; `stream.rs:815-823`).

- For `path=`, libarchive and GNU 1.35 fall back to the ordinary name, contrary to the rule that the deleted ustar field is ignored.
- For `linkpath=`, libarchive falls back to ordinary linkname; GNU creates an empty-target link on macOS.
- For `size=`, peers create partial output and report damage/malformed size while attempting different resynchronization.

The required-field error is safe and spec-grounded. Peer behavior is nonconforming and internally differential.

### DIF-17 — GNU mishandles PAX hard-link data

With hard links enabled:

```text
file("target", "OLD")
x{path=hard, linkpath=target, size=3} -> hardlink with payload "NEW"
```

PAX permits data blocks on hard-link members. `tar-codec` and libarchive produce two names for one inode containing `NEW`. GNU 1.35 leaves both as `OLD`, reports “Skipping to next header,” and fails. `tar-codec` correctly frames effective PAX size (`stream.rs:1038-1043`) and writes through the link (`decode/extract.rs:302-348`). Default hard-link rejection remains conservative.

### DIF-18 — Binary non-UTF-8 names are not extractable

For `x{hdrcharset=BINARY, path=<non-UTF-8 bytes>}`, framing retains a binary `PaxString`, but extraction requires UTF-8 (`decode.rs:582-587`). On Linux byte-path filesystems, GNU tar and libarchive create the byte name. This is an intentional cross-platform supported-subset boundary and fails closed.

### DIF-19 — Absolute and backslash names are handled strictly

For `x{path=/absolute}`, peers strip the slash and create `absolute`; `tar-codec` rejects. For `x{path=dir\\file}` on Unix, peers create a literal-backslash name while `tar-codec` rejects it as Windows-ambiguous (`decode.rs:766-789`). These portable containment rules should remain.

### DIF-20 — One or zero end blocks are accepted by peers

After extracting preceding members, `tar-codec` errors if EOF follows zero or one zero block. Peers succeed with no end marker; GNU warns but succeeds for a lone zero block. POSIX requires two blocks, so the error correctly detects truncation. Earlier output remains by the documented streaming contract.

## Previously known differentials not recounted

The count excludes prior-audit behavior: unknown typeflags; nonzero sizes on directory/FIFO/device entries; negative/out-of-range timestamps and fractional truncation; unsupported `hdrcharset` values; plain `file/` regular members; default rejection of ambient/missing symlink targets; and the 1 MiB PAX-extension limit. They remain observable but are not new coverage.

## Recommended remediation order

1. Preserve installed symlink text while separately normalizing its graph target (DIF-02).
2. Prevent permission widening (DIF-01).
3. Reject implicit parent creation through earlier non-directories (DIF-03).
4. Close the `/.` path ambiguity (DIF-04).
5. Decide whether ownership/timestamps are restored or rejected (DIF-05/06).
6. Keep the remaining strict defaults; they are useful responses to real parser splits.

The first four fixes should receive focused integration tests under `crates/tar-codec/tests`, asserting both the result and final object type/content/link text so partial-error extraction cannot masquerade as a match.
