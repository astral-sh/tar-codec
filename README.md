# tar-codec

tar-codec is a small, contrained tar encoder and decoder for Rust.

Goals:

- Fast, asynchronous, minimally ambiguous, strict pax-style tar encoding
- Fast, asynchronous tar decoding for distinct POSIX pax/ustar or GNU archive streams

Anti-goals:

- Encoding support for anything other than pax
- Decoding support for legacy (pre-ustar) archives
- Decoding archives that mix POSIX pax/ustar and GNU framing in one stream, for now

## Performance

The following elapsed times are a local Criterion snapshot from June 2026.
They measure uncompressed end-to-end filesystem operations, are sensitive to
the machine and filesystem, and are lower-is-better.

| Recursive encoding | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| large: 1 x 16 MiB | 0.93 ms | 1.03 ms | 12.69 ms |
| many-small: 1,024 x 1 KiB | 26.8 ms | 21.7 ms | 59.2 ms |

| Extraction | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| pax large | 1.72 ms | 7.22 ms | 2.85 ms |
| ustar large | 1.78 ms | 7.25 ms | 2.95 ms |
| pax many-small | 129.4 ms | 113.5 ms | 145.3 ms |
| ustar many-small | 130.1 ms | 109.9 ms | 145.3 ms |

`tar-codec` is particularly strong on large payloads and recursive encoding.
The synchronous `tar` crate still leads the many-small filesystem workloads.
The many-small extraction figures are especially filesystem-sensitive and
noisy.
Recursive encoding policies are not identical: `tar-codec` emits pure pax
archives and streams a deterministic sorted traversal, while the comparison
builders emit conventional headers.

## Benchmarking

Run the public API comparison benchmarks with:

```shell
cargo bench -p tar-codec --bench comparison
```

The benchmarks compare `tar-codec` against `tar` and `astral-tokio-tar` for
uncompressed encoding and extraction. Encoder output formats intentionally
differ: `tar-codec` emits pure pax archives, while the comparison builders emit
conventional headers. `tar-codec` validates recursive entries incrementally,
preserves UTF-8 source symbolic-link targets without applying extraction
policy, and may return an error after writing partial output if a late source
entry is invalid.

`encode_entries_framing` measures in-memory entry framing and bookkeeping with a
sink that does not read payload bytes, so it reports entries per second.
`encode_directory` and `extract` exercise filesystem operations and report both
payload entries and payload bytes per second.
