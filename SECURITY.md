# Security policy and model

## Security policy

See our [organization-wide security policy](https://github.com/astral-sh/.github/blob/main/SECURITY.md)
for how to report issues in tar-codec.

## Security model

tar-codec is intended to be resilient to many common differentials when parsing tar streams.
Its format-neutral extraction guarantees are implemented by the workspace's
`archive-trait` crate and shared by every archive implementation using that
extractor.

General properties:

- By default, an attacker should never be able to extract files or other stream contents
  outside of the extraction root. A user must explicitly opt into a non-default extraction
  policy to allow this.
- By default, an attacker should never be able to cause a hang during decoding, such as
  via symlink loops. A user must explicitly opt into a non-default extraction policy
  to allow this.
- If a tar stream is ambiguous (i.e. not well-formed under pax or GNU rules), tar-codec
  should reject it rather than picking an arbitrary interpretation.
- Encoding should always produce a valid, unambiguous, pax-only tar.
- Encoding should always remain linear with respect to input size.

In addition, the following are *never* considered security vulnerabilities
within tar-codec:

- Race conditions during extraction that are caused by concurrent, external
  mutations of the extraction root. tar-codec assumes that it has unique write
  access to the extraction root.
- Differentials where tar-codec fails closed. Failing closed _may_ be a logical
  bug, but it is never a security-relevant differential.
- Differentials where tar-codec picks a different interpretation of a tar stream,
  _if_ that interpretation is supported by the pax or GNU specification. If the
  other implementation fails to follow the relevant specification, the
  security-relevant differential is there instead.
- Differentials that are caused purely by OS- or filesystem-specific behaviors.
  For example, a filesystem that performs unicode path normalization
  may coalesce multiple members into a single path on disk, but this is not a
  concern within tar-codec itself.
