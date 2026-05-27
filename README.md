# tar-codec

tar-codec is a small, contrained tar encoder and decoder for Rust.

Goals:

- Fast, asynchronous, minimally ambiguous pax-style tar encoding
- Fast, asynchronous tar decoding for distinct POSIX pax/ustar or GNU archive streams

Anti-goals:

- Encoding support for anything other than pax
- Decoding support for legacy (pre-ustar) archives
- Decoding archives that mix POSIX pax/ustar and GNU framing in one stream, for now
