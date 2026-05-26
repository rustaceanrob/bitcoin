# compare-benches

Builds `bench` at a base git ref and at `HEAD`, runs the benchmarks,
and prints a side-by-side delta table.

## Usage

```
cargo run --release -- [OPTIONS]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--filter <PATTERN>` | Substring match against benchmark names | all benchmarks |
| `--base <REF>` | Base git ref (branch, tag, or SHA) | `master` |
| `--build <DIR>` | Build directory, relative to the repo root | `build` |
| `--runs <N>` | Runs per commit; keeps the minimum ns/op | `3` |
| `-h, --help` | Print help | |

The filter is treated as a substring, so `--filter MemPool` matches
`MemPoolAddTransactions`, `MempoolEviction`, etc.

### Examples

```sh
# Compare all benchmarks against master
cargo run --release
```

```sh
# Compare only SHA256 benchmarks against master
cargo run --release -- --filter SHA256
```

```sh
# Compare mempool benchmarks against a specific commit
cargo run --release -- --filter MemPool --base origin/master
```

## Output

```
                                         BENCHMARK COMPARISON
=========================================================================================================
  base : a1b2c3d4  commit subject of base
  head : e5f6a7b8  commit subject of HEAD
=========================================================================================================
  benchmark                            | base (ns)   | head (ns)   | Δ time% | base err% | head err% |        Δ ins |        Δ cyc
  ─────────────────────────────────────────────────────────────────────────────────────────────────────
  SHA256_32b_STANDARD                  |       4.710 |       4.760 |  +1.06% |    0.40% |    0.30% |       +0.050 |       +0.030
  SHA256_32b_AVX2                      |       3.840 |       3.820 |  -0.52% |    0.20% |    0.20% |         N/A |         N/A
```

- **Δ time%** — percent change in ns/op; negative is faster
- **base/head err%** — nanobench measurement noise for each run
- **Δ ins / Δ cyc** — change in instructions and CPU cycles per op (requires
  hardware performance counters; shows `N/A` otherwise)
- Benchmarks flagged as unstable by nanobench are excluded from the table

## Notes

The tool checks out each ref directly into the working tree and uses the
shared build directory (`build` by default, overridable with `--build`).
Your working tree must be clean before running (stash or commit any changes).
The original branch is restored automatically when the run completes.
