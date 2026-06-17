# tar-codec

tar-codec is a small, fast, constrained tar encoder and decoder for Rust.

Goals:

- Fast, asynchronous, minimally ambiguous, strict pax-style tar encoding
- Fast, asynchronous tar decoding for distinct POSIX pax/ustar or GNU archive streams

Anti-goals:

- Encoding support for anything other than pax
- Decoding support for legacy (pre-ustar, "UNIX v7") archives
- Decoding archives that mix POSIX pax/ustar and GNU framing in one stream

## Usage

Encoding/archive serialization:

```rust
use tar_codec::{ArchiveBuilder as _, EntryMetadata, TarEncoder};

let mut encoder = TarEncoder::new(&mut writer).builder();
encoder
    .add_entry("README.md", b"hello\n", EntryMetadata::default())
    .await?;
encoder.finish().await?;
```

See `ArchiveBuilder::builder_with_policy` for policy knobs that
can be changed during building.

Note that `tar-codec` does **not** perform compression for you.
If you want a compressed tar stream (like a `.tar.gz`) consider
supplying an adapted writer, such as from the [async-compression]
crate.

[async-compression]: https://docs.rs/async-compression/latest/async_compression/

Decoding/extracting:

```rust
use tar_codec::{Archive as _, TarArchive, extract::ExtractPolicy};

TarArchive::new(reader)
    .extract_in("destination", ExtractPolicy::default())
    .await?;
```

Unlike encoding, decoding/extraction has two policy layers:

- Use `TarArchive::new_with_policy` to control various aspects of GNU or pax handling.
- Use `extract::ExtractPolicy` to control various aspects of how archives become
  real paths on the host filesystem.

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
