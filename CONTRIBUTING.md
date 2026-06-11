# CONTRIBUTING

## Architecture

There are a few important architectural divisions/separations of concerns
to be aware of when making changes.

There are three abstraction layers in the tar-codec repository:
two live in the `tar-framing` crate, and one lives in the `tar-codec` crate.
In order of abstraction, lowest to highest:

- tar-framing: the _physical_ layer turns an asynchronous input source into a
  stream of tar blocks according to the pax or GNU tar state machine.
  This is the lowest level of abstraction.
- tar-framing: the _logical_ layer turns a stream of blocks from the physical layer
  into a stream of _assembled members_, i.e. tar entries along with
  their relevant pax or GNU metadata.
- tar-codec: the _decode and extract_ layer turns a stream of _assembled members_
  into an extracted set of files, directories, etc. on disk.

These layers/concerns should be preserved when making changes.
For example, any change that affects framing (which blocks are considered
headers, extensions, data, etc.) should occur in the physical layer.

## Formatting and linting

```shell
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

Run tests:

```shell
cargo test
```

Broad public workflows, including archive construction, encoding, extraction,
policy interaction, and filesystem behavior, belong in crate integration
tests. Keep unit tests beside small pure or private helpers whose behavior is
best expressed through their internal API.

## Benchmarking

Run the public API comparison benchmarks with:

```shell
cargo bench -p tar-codec --bench comparison
```

The benchmarks compare `tar-codec` against `tar` and `astral-tokio-tar` for
uncompressed encoding and extraction.
