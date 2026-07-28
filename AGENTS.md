## General

- Read CONTRIBUTING.md for guidelines on how to run tools
- ALWAYS attempt to add a test case for changed behavior, except benchmarks and the `tarpit` CLI
- AVOID writing duplicate or tautological testcases
- NEVER perform builds with the release profile, unless asked or reproducing performance issues
- PREFER running specific tests over running the entire test suite
- ALWAYS read and copy the style of similar tests when adding new cases
- PREFER top-level imports over local imports or fully qualified names
- AVOID shortening variable names, e.g., use `version` instead of `ver`
- AVOID single-line functions that just call another function
- AVOID single-use bindings, and prefer point-free style

## Rust

- PREFER integration tests (`tar-codec/tests`) over unit tests when changed behavior concerns multiple APIs or whole tar streams
- AVOID using `panic!`, `unreachable!`, `.unwrap()`, unsafe code, and clippy rule ignores
- NEVER use `unsafe` unless explicitly given permission
- PREFER patterns like `if let` to handle fallibility
- PREFER `#[expect()]` over `[allow()]` if clippy must be disabled
- PREFER let chains (`if let` combined with `&&`) over nested `if let` statements
- NEVER update all dependencies in the lockfile and ALWAYS use `cargo update --precise` to make lockfile changes
- NEVER assume clippy warnings are pre-existing, it is very rare that `main` has warnings
- PREFER [`TypeName`] references when writing Rust doc comments

## Python

- ALWAYS write fully type-annotated Python
- AVOID using `type: ignore` and other typing loopholes
- PREFER `match` statements over `if` chains, if applicable
- AVOID making copies across the Python/Rust boundary; public APIs should be as zero-copy as possible