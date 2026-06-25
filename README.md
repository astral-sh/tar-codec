# tar-codec

tar-codec is a small, fast, constrained tar encoder and decoder for Rust.

> [!IMPORTANT]
>
> This repository is in a **very early** state of development and is **not**
> considered ready for production use. You will encounter bugs, sharp edges,
> etc.

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
use tar_codec::{ArchiveBuilder as _, EntryMetadata, FilePayload, TarEncoder};

let payload = FilePayload::from_path("README.md").await?;
let mut encoder = TarEncoder::new(&mut writer).builder();
encoder
    .add_file("README.md", payload, EntryMetadata::default())
    .await?;
encoder.finish().await?;
```

`FilePayload::new` accepts a declared size and any asynchronous reader, while
`FilePayload::from_path` and `FilePayload::from_file` determine file sizes.
`Builder::add_directory` writes one directory member without filesystem access;
`Builder::add_directory_all` recursively imports a filesystem directory.

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

See [BENCHMARKS] for current benchmarks.

[BENCHMARKS]: ./BENCHMARKS.md
