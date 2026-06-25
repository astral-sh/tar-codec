# tarpit

A CLI for inspecting and extracting tar streams.

This crate is a component of [tar-codec](https://github.com/astral-sh/tar-codec).

## Inspection

Use `frames` to inspect the lossless physical block stream:

```shell
cargo run -p tarpit -- frames archive.tar
```

Use `logical` to inspect assembled members with their effective paths, attached
PAX or GNU metadata, ordinary header fields, and payload blocks:

```shell
cargo run -p tarpit -- logical archive.tar.gz
```

Archives whose names end in `.tar.gz` are decompressed automatically.

> [!IMPORTANT]
> `tarpit` is **not** suitable for general-purpose use.
> It is a low-level inspection tool that is primarily useful
> for looking at the format of tar streams and for diagnosing
> [tar-codec](https://github.com/astral-sh/tar-codec) itself.
