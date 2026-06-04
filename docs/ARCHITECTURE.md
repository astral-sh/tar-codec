# Architecture

`tar-codec` is built above `tar-framing`:

```text
AsyncRead bytes -> tar-framing -> tar-codec -> extracted filesystem entries
filesystem entries -> tar-codec -> tar-framing -> AsyncWrite bytes
```

## `tar-framing`

`tar-framing` validates archive structure without interpreting member paths or
performing filesystem operations.

It owns:

- strict selection of one archive family per stream: POSIX pax/ustar or GNU;
- header identity, checksum, size, ordering, payload, and terminator checks;
- typed PAX record parsing, including UTF-8/binary `hdrcharset` values, and
  PAX size effects on framing;
- byte-oriented member metadata access and PAX/GNU/header precedence;
- mode decoding and GNU long-name/long-link structural validation;
- the physical block API, `stream::TarStream`; and
- the assembled read API, `logical::TarReader`; and
- deterministic POSIX-pax block construction through `write`.

`TarStream` preserves accepted 512-byte source blocks for low-level consumers.
Parsed PAX records remain attached to their final physical payload frame;
ordinary physical headers do not carry assembled PAX state. `TarReader` emits
only ordinary members. Their compact logical headers borrow ordinary path and
link-path fallbacks from reusable reader storage instead of retaining lossless
physical blocks. Each PAX member carries one unified `PaxState` that resolves
active global and local precedence while retaining newly encountered positioned
extensions for policy inspection. The reader resolves effective member
path/link bytes, silently ignores trailing global updates without a following
member, and streams ordinary member payloads.

## `tar-codec`

`tar-codec` interprets logical metadata for secure extraction and provides
filesystem-oriented pure-pax encoding.

It owns:

- legalizing effective member and link bytes as portable UTF-8 paths, then
  normalizing them into typed root-relative paths shared by encoding and
  extraction;
- extraction policy, including `DecodePolicy` and `PaxDecodePolicy`;
- archive-path normalization and policy-controlled last-entry-wins replacement,
  including no-follow leaf removal, reuse of real directories, and rejection of
  non-empty directory removal;
- deferred symbolic-link installation, including bounded graph validation,
  policy-controlled dangling links, and unconditional rejection of escaping
  targets;
- path-based creation beneath a validated destination root, under the contract
  that callers do not concurrently mutate that destination;
- recursive encoding traversal, canonicalization of safe non-normal archive
  paths, source symlink preservation, and async writes.

It relies on `tar-framing` for structural validity and effective payload
sizing; it does not re-parse the tar wire format.

The pax format permits hard-link data blocks, including those required by its
`linkdata` option, but does not record why a particular hard-link body was
included. Its physical size field may be nonzero, and an applicable pax `size`
record overrides that field. `tar-framing` must therefore treat every nonzero
effective pax hard-link size as payload to preserve framing. `tar-codec` owns
the trust decision: extraction rejects all hard links by default, and enabling
them also permits those indistinguishable payloads to update an earlier
extracted target.

The filesystem extraction implementation and its private support types are
isolated in `decode/extract.rs`. The implementation logic is kept under a
550-line budget. Shared private path typestates live in `paths.rs`; policy,
path-error mapping, and public error APIs remain in `decode.rs`.

## Placement Rule

Add wire-format reading, construction, and lossless logical metadata
resolution to `tar-framing`. Add text policy, extraction policy, filesystem
behavior, and async encoding orchestration to `tar-codec`.
