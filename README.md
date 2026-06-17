# tar-codec

tar-codec is a small, fast, constrained tar encoder and decoder for Rust.

Goals:

- Fast, asynchronous, minimally ambiguous, strict pax-style tar encoding
- Fast, asynchronous tar decoding for distinct POSIX pax/ustar or GNU archive streams

Anti-goals:

- Encoding support for anything other than pax
- Decoding support for legacy (pre-ustar) archives
- Decoding archives that mix POSIX pax/ustar and GNU framing in one stream, for now

## Architecture

`tar-framing` parses physical and logical tar structure. `tar-codec` validates
tar-specific policy and projects those logical entries into the common member
model from `archive-trait`. The latter owns path validation, link policy, and
filesystem extraction, so the same extraction engine can support future archive
formats with the same basic member shape.

```rust
use tar_codec::{Archive as _, ExtractPolicy, TarArchive};

TarArchive::new(reader)
    .extract_in("destination", ExtractPolicy::default())
    .await?;
```

Use `TarArchive::with_policy` and `DecodePolicy` for GNU/PAX decoding controls.
Use `ExtractPolicy` for generic name, overwrite, and link behavior.

## Performance

tar-codec aims to be as fast as (or substantially faster than) other
tar libraries for Rust, including [tar] and [astral-tokio-tar].

[tar]: https://crates.io/crates/tar
[astral-tokio-tar]: https://crates.io/crates/astral-tokio-tar

The following elapsed times are Criterion median point estimates from a local
snapshot on June 9, 2026. They measure uncompressed end-to-end filesystem
operations, are sensitive to the machine and filesystem, and are
lower-is-better.

| Recursive encoding | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| large: 1 x 16 MiB | 0.90 ms | 1.03 ms | 12.50 ms |
| many-small: 1,024 x 1 KiB | 27.9 ms | 21.6 ms | 56.2 ms |

| Extraction | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| pax large | 1.62 ms | 7.10 ms | 2.89 ms |
| ustar large | 1.65 ms | 7.12 ms | 2.88 ms |
| pax many-small | 107.7 ms | 109.0 ms | 144.9 ms |
| ustar many-small | 105.2 ms | 110.2 ms | 142.0 ms |

In this snapshot, `tar-codec` has the lowest median in every extraction
workload and is particularly strong on large-payload extraction and large-file
recursive encoding. The synchronous `tar` crate still leads many-small
recursive encoding. The many-small extraction figures are especially
filesystem-sensitive and noisy; the pax results for `tar-codec` and `tar`
differ by less than 1%.
Recursive encoding policies are not identical: `tar-codec` emits pure pax
archives and streams a deterministic sorted traversal, while the comparison
builders emit conventional headers.
