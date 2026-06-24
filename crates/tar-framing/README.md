# tar-framing

Low-level strict tar stream framing for either POSIX pax/ustar or GNU archives.

This crate is a component of [tar-codec](https://github.com/astral-sh/tar-codec).
Most users should not use this crate's APIs directly.

## Reading

This crate provides two views over an asynchronous I/O source:

- `stream::TarStream` emits physical 512-byte header and data frames
  for lossless inspection and debugging. Parsed PAX records are available
  on the final physical PAX payload frame.
- `logical::TarReader` emits ordinary members with extension metadata
  attached, exposes a compact logical header borrowing reusable ordinary
  path/link storage, resolves byte-oriented member path/link metadata
  according to PAX/GNU precedence, and streams member payload blocks through
  a borrowing cursor.

For PAX members, one `PaxState` provides standards-consistent effective values
while preserving each positioned global or local extension newly encountered
for that member. Trailing global extensions without a following member are
consumed and ignored. Use `TarStream` when standalone physical extension
headers must be inspected losslessly.

Each stream is "locked" to one archive family: POSIX pax/ustar or GNU.
Streams that combine pax and GNU members are rejected.

## Writing

tar-framing also provides `write` helpers for constructing pax-conforming member
blocks without performing I/O.

## Benchmarking

Run the internal framing benchmarks with:

```shell
cargo bench -p tar-framing --bench framing
```

`encode_pax_framing` measures reusable pure-pax framing without payload reads.
`decode_payload` compares lossless block iteration, validated chunk reads, and
payload skipping over in-memory archives.
