# tar-codec benchmarks

> [!NOTE]
> The benchmark results below are **not** a guarantee of performance
> characteristics on end-user systems. Actual performance can vary
> significantly by host OS and filesystem, system load, presence of
> background processes, and so forth.

The following ratios are calculated from Criterion point estimates in a
[GitHub Actions snapshot](https://github.com/astral-sh/tar-codec/actions/runs/27780975150)
on June 18, 2026. They measure uncompressed end-to-end filesystem operations.
Each value is elapsed time relative to `tar-codec`, so values below 1.00x are
faster and values above 1.00x are slower.

| Recursive encoding | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| large: 1 x 16 MiB | 1.00x | 1.03x | 29.89x |
| many-small: 1,024 x 1 KiB | 1.00x | 0.36x | 4.22x |

| Extraction | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| pax large | 1.00x | 1.51x | 1.32x |
| ustar large | 1.00x | 1.56x | 1.31x |
| pax many-small | 1.00x | 1.52x | 3.66x |
| ustar many-small | 1.00x | 1.49x | 3.63x |

> [!NOTE]
> The encoding benchmarks are not perfect "apples-to-apples"
> comparisons, since `tar-codec` intentionally only emits
> pax archives while `tar` and `astral-tokio-tar` emit GNU-style
> archives by default.
