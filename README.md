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
snapshot on June 17, 2026. They measure uncompressed end-to-end filesystem
operations, are sensitive to the machine and filesystem, and are
lower-is-better.

| Recursive encoding | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| large: 1 x 16 MiB | 0.85 ms | 1.00 ms | 12.07 ms |
| many-small: 1,024 x 1 KiB | 26.4 ms | 20.5 ms | 54.3 ms |

| Extraction | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| pax large | 1.71 ms | 6.98 ms | 2.76 ms |
| ustar large | 1.71 ms | 6.90 ms | 2.78 ms |
| pax many-small | 104.3 ms | 107.4 ms | 139.6 ms |
| ustar many-small | 105.9 ms | 107.5 ms | 141.1 ms |

In this snapshot, `tar-codec` has the lowest median in every extraction
workload and is particularly strong on large-payload extraction and large-file
recursive encoding. The synchronous `tar` crate still leads many-small
recursive encoding. The many-small extraction figures are especially
filesystem-sensitive and noisy; the pax results for `tar-codec` and `tar`
differ by roughly 1-3%.
Recursive encoding policies are not identical: `tar-codec` emits pure pax
archives and streams a deterministic sorted traversal, while the comparison
builders emit conventional headers.
