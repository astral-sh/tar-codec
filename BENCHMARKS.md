# tar-codec benchmarks

> [!NOTE]
> The benchmark results below are **not** a guarantee of performance
> characteristics on end-user systems. Actual performance can vary
> significantly by host OS and filesystem, system load, presence of
> background processes, and so forth.

> [!NOTE]
> The encoding benchmarks are not perfect "apples-to-apples"
> comparisons, since `tar-codec` intentionally only emits
> pax archives while `tar` and `astral-tokio-tar` emit GNU-style
> archives by default.

The following ratios are calculated from Criterion median point estimates in
the Ubuntu job of a
[GitHub Actions snapshot](https://github.com/astral-sh/tar-codec/actions/runs/28186813074)
on June 25, 2026. They measure uncompressed end-to-end filesystem operations.
Each value is elapsed time relative to `tar-codec`, so values below 1.00x are
faster and values above 1.00x are slower.

| Recursive encoding | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| large: 1 x 16 MiB | 1.00x | 1.12x | 41.66x |
| many-small: 1,024 x 1 KiB | 1.00x | 1.72x | 27.18x |

| Extraction | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| pax large | 1.00x | 2.00x | 3.88x |
| ustar large | 1.00x | 1.89x | 3.73x |
| pax many-small | 1.00x | 1.55x | 4.25x |
| ustar many-small | 1.00x | 1.53x | 4.42x |

## Python bindings

See [CONTRIBUTING.md](./CONTRIBUTING.md) to run the Python benchmarks.

Values are `tarfile` time divided by `tar-codec` time; above 1.00x means `tar-codec` is faster.

| Workload | Operation | macOS |
| --- | --- | ---: |
| large: 1 x 16 MiB | encode | 4.96x |
| large: 1 x 16 MiB | decode | 32.83x |
| large: 1 x 16 MiB | decode-bytesio | 28.51x |
| large: 1 x 16 MiB | decode-stream | 2.73x |
| large: 1 x 16 MiB | extract | 1.38x |
| many-small: 1,024 x 1 KiB | encode | 20.27x |
| many-small: 1,024 x 1 KiB | decode | 17.32x |
| many-small: 1,024 x 1 KiB | decode-bytesio | 14.27x |
| many-small: 1,024 x 1 KiB | decode-stream | 14.18x |
| many-small: 1,024 x 1 KiB | extract | 1.79x |
| mixed: 7 x 1 KiB–4 MiB | encode | 1.50x |
| mixed: 7 x 1 KiB–4 MiB | decode | 5.53x |
| mixed: 7 x 1 KiB–4 MiB | decode-bytesio | 5.17x |
| mixed: 7 x 1 KiB–4 MiB | decode-stream | 2.33x |
| mixed: 7 x 1 KiB–4 MiB | extract | 1.64x |
