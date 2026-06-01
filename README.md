# tar-codec

tar-codec is a small, contrained tar encoder and decoder for Rust.

Goals:

- Fast, asynchronous, minimally ambiguous, strict pax-style tar encoding
- Fast, asynchronous tar decoding for distinct POSIX pax/ustar or GNU archive streams

Anti-goals:

- Encoding support for anything other than pax
- Decoding support for legacy (pre-ustar) archives
- Decoding archives that mix POSIX pax/ustar and GNU framing in one stream, for now

## Benchmarking

Run the public API comparison benchmarks with:

```shell
cargo bench -p tar-codec --bench comparison
```

The benchmarks compare `tar-codec` against `tar` and `astral-tokio-tar` for
uncompressed encoding and extraction. Encoder output formats intentionally
differ: `tar-codec` emits pure pax archives, while the comparison builders emit
conventional headers.

`encode_entries_framing` measures in-memory entry framing and bookkeeping with a
sink that does not read payload bytes, so it reports entries per second.
`encode_directory` and `extract` exercise filesystem operations and report both
payload entries and payload bytes per second.
