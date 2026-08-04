# chapter-gzip

Asynchronous gzip compression with independently readable chapters.

Chapter boundaries are represented by empty DEFLATE blocks containing backward
pointers in their dynamic Huffman descriptions. Ordinary gzip implementations
ignore these markers, while chapter-aware readers can build a compressed-offset
index without decompressing chapter contents.

This crate operates on arbitrary bytes. It does not parse tar archives, create
tar members, or insert tar terminators.

## Attribution

This crate is derived from [chapter-tgz] by David Tolnay. Its chapter marker
format, Huffman marker encoding and decoding, backward-linked chapter index, and
gzip boundary handling are adapted from that project's implementation for
asynchronous, tar-independent use.

The upstream project is available under either the MIT license or the Apache
License, Version 2.0. See [NOTICE](NOTICE) for the upstream attribution and MIT
permission notice.

[chapter-tgz]: https://github.com/dtolnay/chapter-tgz

## Writing

```rust,ignore
use chapter_gzip::{ChapteredGzipWriter, Compression};
use tokio::io::AsyncWriteExt;

let mut writer = ChapteredGzipWriter::new(Vec::new(), Compression::fast());

writer.start_chapter().await?;
writer.write_all(b"first chapter").await?;

writer.start_chapter().await?;
writer.write_all(b"second chapter").await?;

let gzip = writer.finish().await?;
```

## Reading

```rust,ignore
use chapter_gzip::ChapteredGzipReader;
use std::io::Cursor;
use tokio::io::AsyncReadExt;

let mut archive = ChapteredGzipReader::open(Cursor::new(gzip)).await?;
let mut chapter = archive.read_chapter(1).await?;
let mut contents = Vec::new();
chapter.read_to_end(&mut contents).await?;
```

An ordinary gzip file without chapter markers is exposed as one chapter. Use
`read_chapter_from` with independently positioned sources when chapters need to
be consumed concurrently. Individual chapter reads do not validate the
archive-wide gzip checksum; validating that checksum requires consuming the
complete gzip stream.
