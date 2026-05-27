# tar-framing

Low-level strict tar stream framing for either POSIX pax/ustar or GNU archives.

This is a dependency of `tar-codec`. Most users should not use this crate's APIs directly.

This crate has one primary task: to abstract an asynchronous I/O source into an asynchronous stream of tar "frames," i.e. a well-formed stream of header and data packets.

Each stream is locked to one archive family: POSIX pax/ustar or GNU, never a mixture.

The POSIX pax subset currently accepts UTF-8 extended-header text only; archives using `hdrcharset=BINARY` are intentionally out of scope for now.
