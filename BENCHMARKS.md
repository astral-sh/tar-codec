# tar-codec benchmarks

> [!NOTE]
> The benchmark results below are **not** a guarantee of performance
> characteristics on end-user systems. Actual performance can vary
> significantly by host OS and filesystem, system load, presence of
> background processes, and so forth.

The following ratios are calculated from Criterion median point estimates in
the Ubuntu job of a
[GitHub Actions snapshot](https://github.com/astral-sh/tar-codec/actions/runs/27961977910)
on June 22, 2026. They measure uncompressed end-to-end filesystem operations.
Each value is elapsed time relative to `tar-codec`, so values below 1.00x are
faster and values above 1.00x are slower.

| Recursive encoding | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| large: 1 x 16 MiB | 1.00x | 1.35x | 54.29x |
| many-small: 1,024 x 1 KiB | 1.00x | 1.68x | 29.60x |

| Extraction | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| pax large | 1.00x | 1.36x | 2.11x |
| ustar large | 1.00x | 1.34x | 2.18x |
| pax many-small | 1.00x | 1.52x | 4.86x |
| ustar many-small | 1.00x | 1.51x | 4.93x |

> [!NOTE]
> The encoding benchmarks are not perfect "apples-to-apples"
> comparisons, since `tar-codec` intentionally only emits
> pax archives while `tar` and `astral-tokio-tar` emit GNU-style
> archives by default.
