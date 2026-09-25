# `BoundsChecker::check_code` aborts on the deprecated global-storage opcodes (debug builds only)

Same root cause as `mayhem/code_unit/known-findings/bounds-checker-deprecated-global-storage-safe-assert/`
— read that note for the full analysis, the impact assessment ("not a production defect"), and the
measurements behind the `--debug-assertions` decision in `mayhem/build.sh`.

**Status: NOT a production defect.** Recorded so it is not re-filed.

## Reproducer

`repro.bin` — 6 bytes, `17 ff ff ff ff 0a`. Reproduce against a **debug-assertions** build:

```sh
cargo +<nightly> fuzz build --fuzz-dir external-crates/move/crates/bytecode-verifier-libfuzzer \
    -O --debug-assertions mixed
./external-crates/move/target/x86_64-unknown-linux-gnu/release/mixed -runs=1 repro.bin
```

```
thread '<unnamed>' panicked at crates/move-binary-format/src/check_bounds.rs:549:21:
PartialVMError { major_status: UNKNOWN_INVARIANT_VIOLATION_ERROR, ... }
==> libFuzzer: deadly signal
```

Stack tip is identical to the `code_unit` case apart from the harness frame:

```
move_binary_format::check_bounds::BoundsChecker::check_code        check_bounds.rs:549
...
move_bytecode_verifier::verifier::verify_module_unmetered          verifier.rs:41
mixed::__libfuzzer_sys_run                                         fuzz_targets/mixed.rs:96
```

`mixed` reaches it the same way `code_unit` does: its `Arbitrary`-derived `Vec<Bytecode>` may
contain a deprecated global-storage instruction, and the in-memory module never passes through the
deserializer that would otherwise reject it. In a release build the guarded `safe_assert!` returns
`Err(UNKNOWN_INVARIANT_VIOLATION_ERROR)` instead of panicking.
