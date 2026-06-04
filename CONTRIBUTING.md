# CONTRIBUTING

Run formatting/linting:

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
