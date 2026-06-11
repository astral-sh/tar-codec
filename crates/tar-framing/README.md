# tar-framing

Low-level strict tar stream framing for either POSIX pax/ustar or GNU archives.

This is a dependency of `tar-codec`. Most users should not use this crate's APIs directly.

This crate provides two views over an asynchronous I/O source:

- `stream::TarStream` emits physical 512-byte header and data frames for lossless inspection and debugging. Parsed PAX records are available on the final physical PAX payload frame.
- `logical::TarReader` emits ordinary members with extension metadata attached, exposes a compact logical header borrowing reusable ordinary path/link storage, resolves byte-oriented member path/link metadata according to PAX/GNU precedence, and streams member payload blocks through a borrowing cursor.

For PAX members, one `PaxState` provides standards-consistent effective values
while preserving each positioned global or local extension newly encountered
for that member. Trailing global extensions without a following member are
consumed and ignored. Use `TarStream` when standalone physical extension
headers must be inspected losslessly.

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

Each local or global PAX extension is limited to 1 MiB by default and is
rejected from its header before any payload is consumed when it exceeds that
limit. `TarStream` and `TarReader` provide constructors for configuring the
limit.

## Benchmarking

Run the internal framing benchmarks with:

```shell
cargo bench -p tar-framing --bench framing
```

`encode_pax_framing` measures reusable pure-pax framing without payload reads.
`decode_payload` compares lossless block iteration, validated chunk reads, and
payload skipping over in-memory archives.
