# tar-codec (for Python)

Python bindings for `tar-codec`.

```python
import io

from tar_codec import Builder, TarArchive

output = io.BytesIO()
with Builder(output) as builder:
    builder.add_file("hello.txt", b"hello from Python\n")
    builder.add_directory("empty-directory")
archive_bytes = output.getvalue()

with TarArchive(io.BytesIO(archive_bytes)) as archive:
    for member in archive:
        print(member.path, member.kind, (payload := member.payload) and payload.read())
with TarArchive(archive_bytes) as archive:
    archive.extract_in("destination")
```

Archives accept bytes, filesystem paths, and binary streams. `DecodePolicy` and
`ExtractPolicy` customize their behavior.

Payload reads return read-only `memoryview` objects without copying `bytes` or
`io.BytesIO` sources. Use `read(size)` for bounded reads or `.tobytes()` to
obtain `bytes`.

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for development instructions.

## Compressed archives

Use Python's standard-library compression wrappers. Write a `.tar.gz` archive
with `gzip.open`:

```python
import gzip

from tar_codec import Builder

with gzip.open("archive.tar.gz", "wb") as compressed:
    with Builder(compressed) as archive:
        archive.add_file("hello.txt", b"hello from a compressed archive\n")
        archive.add_directory_all("project")
```

Read the archive through a decompressed stream:

```python
import gzip

from tar_codec import TarArchive

with gzip.open("archive.tar.gz", "rb") as decompressed:
    with TarArchive(decompressed) as archive:
        for member in archive:
            if (payload := member.payload) is not None:
                print(member.path, payload.read().tobytes())
```

Use `bz2.open` or `lzma.open` for `.tar.bz2` or `.tar.xz` archives.
