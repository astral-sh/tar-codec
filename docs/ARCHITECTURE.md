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
`TarReader` groups local PAX or GNU extension metadata with its member, emits
global PAX updates separately, resolves effective member path/link bytes, and
streams ordinary member payloads.

## `tar-codec`

`tar-codec` interprets logical metadata for secure extraction and provides
filesystem-oriented pure-pax encoding.

It owns:

- applying UTF-8 extraction policy to effective member path and link bytes;
- extraction policy, including `ExtractPolicy` and `PaxExtractPolicy`;
- archive-path normalization and collision handling, including unconditional
  regular-file replacement and reuse of real directories;
- deferred symbolic-link installation, including bounded graph validation,
  policy-controlled dangling links, and unconditional rejection of escaping
  targets; and
- capability-relative creation of files, directories, and permitted links;
- recursive encoding traversal, source symlink preservation, and async writes.

It relies on `tar-framing` for structural validity and effective payload
sizing; it does not re-parse the tar wire format.

## Placement Rule

Add wire-format reading, construction, and lossless logical metadata
resolution to `tar-framing`. Add text policy, extraction policy, filesystem
behavior, and async encoding orchestration to `tar-codec`.
