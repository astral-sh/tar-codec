# tar-framing

Low-level strict tar stream framing for either POSIX pax/ustar or GNU archives.

This is a dependency of `tar-codec`. Most users should not use this crate's APIs directly.

This crate provides two views over an asynchronous I/O source:

- `physical::TarStream` emits physical 512-byte header and data frames for lossless inspection and debugging.
- `logical::TarReader` emits logical global-pax updates and members, retaining only the pax records or GNU payload values needed to interpret each member while streaming member payload blocks through a borrowing cursor.

Each stream is locked to one archive family: POSIX pax/ustar or GNU, never a mixture.

The POSIX pax subset parses standard extended-header records into typed values,
accepts reserved `realtime.*` and `security.*` records plus uppercase
`VENDOR.keyword` extensions, and rejects unknown unnamespaced keywords.
`hdrcharset` records are accepted only for POSIX UTF-8 (or as deletion
tombstones); other declared header-text encodings are intentionally out of
scope for this UTF-8-only layer.
