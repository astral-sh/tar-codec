# Architecture

`tar-codec` is built above `tar-framing`:

```text
AsyncRead bytes -> tar-framing -> tar-codec -> extracted filesystem entries
```

## `tar-framing`

`tar-framing` validates archive structure without interpreting member paths or
performing filesystem operations.

It owns:

- strict selection of one archive family per stream: POSIX pax/ustar or GNU;
- header identity, checksum, size, ordering, payload, and terminator checks;
- typed PAX record parsing and PAX size effects on framing;
- the physical block API, `stream::TarStream`; and
- the assembled read API, `logical::TarReader`.

`TarStream` preserves accepted 512-byte source blocks for low-level consumers.
`TarReader` groups local PAX or GNU extension metadata with its member, emits
global PAX updates separately, and streams ordinary member payloads.

## `tar-codec`

`tar-codec` consumes `logical::TarReader` output and interprets metadata for
secure extraction.

It owns:

- interpreting ustar fields, PAX `path` / `linkpath`, and GNU long-name /
  long-link values;
- extraction policy, including `ExtractPolicy` and `PaxExtractPolicy`;
- archive-path normalization and collision handling; and
- capability-relative creation of files, directories, and permitted links.

It relies on `tar-framing` for structural validity and effective payload
sizing; it does not re-parse the tar wire format.

## Placement Rule

Add syntax and framing validation to `tar-framing`. Add metadata semantics,
extraction policy, and filesystem behavior to `tar-codec`.
