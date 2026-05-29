# tar-framing

Low-level strict tar stream framing for either POSIX pax/ustar or GNU archives.

This is a dependency of `tar-codec`. Most users should not use this crate's APIs directly.

This crate provides two views over an asynchronous I/O source:

- `stream::TarStream` emits physical 512-byte header and data frames for lossless inspection and debugging.
- `logical::TarReader` emits logical global-pax updates and members, resolves byte-oriented member path/link metadata according to PAX/GNU precedence, and streams member payload blocks through a borrowing cursor.

It also provides `write` helpers for constructing deterministic POSIX-pax
member blocks without performing I/O.

Each stream is "locked" to one archive family: POSIX pax/ustar or GNU, never a mixture.

The POSIX pax subset parses standard extended-header records into typed values,
accepts reserved `realtime.*` and `security.*` records plus uppercase
`VENDOR.keyword` extensions, and rejects unknown unnamespaced keywords.
`hdrcharset` records accept POSIX UTF-8 and `BINARY` (or deletion
tombstones). Values of `gname`, `linkpath`, `path`, and `uname` are preserved
as typed UTF-8 strings or unencoded bytes accordingly.

Logical metadata access remains lossless bytes; consumers such as
`tar-codec` decide how filenames and link targets may be decoded and used.
