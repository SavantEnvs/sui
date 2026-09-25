# Starter seed corpora — how each one was produced

Every target ships a starter corpus at `mayhem/<target>/testsuite/`, wired through the two-entry
`testsuite:` directive in `mayhem/Mayhemfile_<target>` (server-accumulated tar first, then the
local starter set). The two kinds of corpus here are produced very differently, because the two
kinds of target consume their input very differently.

## `deserialize_verify` — 62 real compiled Move modules (`.mv`)

This target feeds raw bytes to `CompiledModule::deserialize_with_defaults`, so a seed is a real
Move binary. They are sui's own committed fixtures: every `*.mv` tracked in the repo
(`git ls-files | grep '\.mv$'` — 81 files, mostly
`external-crates/move/crates/move-decompiler/tests/bytecode/`, which are real published Sui
modules, plus the `move-analyzer` trace-adapter packages), deduplicated by SHA-256, which leaves
**62 distinct modules** totalling ~280 KB and ranging from 77 B to 32 KB. Copied verbatim, renamed
`seed_NNNN.mv` in the tracked-path order.

Measured value: the 62 seeds alone put the target at **12,349 edges at `INITED`**. A cold start
from random bytes reaches essentially none of the verifier, because random bytes never survive the
magic/version/table-offset checks.

A dictionary (`mayhem/deserialize_verify/deserialize_verify.dict`, 31 entries) accompanies them —
see its header for provenance and for the round-trip check against the built binary.

## `code_unit`, `mixed`, `compiled_module` — generated, minimised, sampled

These are sui's own `Arbitrary`-driven targets: the fuzzer's bytes are consumed by
`arbitrary::Arbitrary` to *construct* a module, so there is no natural file format to collect and
no upstream corpus to convert. The seeds were therefore produced from the built binaries
themselves, in three steps:

1. **Generate** — fork-mode run against an empty corpus directory, using the same binaries
   `mayhem/build.sh` ships:

   ```sh
   /mayhem/<t> -fork=4 -ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1 \
               -timeout=10 -rss_limit_mb=2560 -max_total_time=<90|30> \
               -max_len=<512|96> -artifact_prefix=/art/ <corpus-dir>
   ```

   90 s at `max_len=512` for `code_unit` and `mixed`; 30 s at `max_len=96` for `compiled_module`
   (it executes ~60k/s and would otherwise produce an unusably large minimised set). All three runs
   completed with `oom/timeout/crash: 0/0/0`.

2. **Minimise** — `<t> -merge=1 <out> <corpus-dir>`, i.e. libFuzzer's own greedy feature-coverage
   minimisation, so every retained file adds at least one feature.

3. **Sample** — a deterministic `shuf --random-source=<(yes 42) | head -N` over the minimised set
   (N = 400 / 400 / 300), renamed `seed_NNNN.bin`. This step exists only to keep the committed
   corpus a reasonable size: the full minimised sets were 1609 / 2018 / 1431 files. The retained
   fraction was measured, not guessed — the committed samples reach, at `INITED`, 5063 of 5669
   edges (`code_unit`), 5590 of 6562 (`mixed`) and 2758 of 3413 (`compiled_module`), i.e. ~81–89 %
   of the full minimised set for ~25 % of the files. The server-side tar accumulates the rest from
   run one onward.

   Committed sizes: 400 files / 30 KB, 400 files / 25 KB, 300 files / 19 KB.

## Invariants checked before committing

- Every seed replays cleanly: `<bin> -runs=1 <seed>` exits 0 for all of them. A single hanging or
  hard-exiting seed would kill Mayhem's `-runs=5` startup probe on **every** future run, and
  removing it from git afterwards would not help — it would already be in the accumulated tar.
- `<bin> -runs=5 <testsuite-dir>` (literally Mayhem's startup probe) exits 0 per target.
- No crash reproducer is in any `testsuite/`. The one finding recorded during this integration
  lives under `mayhem/code_unit/known-findings/` and `mayhem/mixed/known-findings/`.
