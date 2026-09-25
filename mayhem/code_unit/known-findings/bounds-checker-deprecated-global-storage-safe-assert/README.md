# `BoundsChecker::check_code` aborts on the deprecated global-storage opcodes (debug builds only)

**Targets affected:** `code_unit` and `mixed` (same root cause; `mixed` has its own copy of this
note and its own reproducer). Not reachable from `deserialize_verify`.

**Status: NOT a production defect.** It is a build-configuration finding, recorded here because it
is what drove the `--debug-assertions` decision in `mayhem/build.sh`, and because anyone re-running
these targets with debug assertions will hit it within seconds and should not re-file it.

## Reproducer

`repro.bin` — 8 bytes, `01 00 c1 c1 a0 fe ff 2b`. Reproduce against a **debug-assertions** build:

```sh
cargo +<nightly> fuzz build --fuzz-dir external-crates/move/crates/bytecode-verifier-libfuzzer \
    -O --debug-assertions code_unit
./external-crates/move/target/x86_64-unknown-linux-gnu/release/code_unit -runs=1 repro.bin
```

## What happens

```
thread '<unnamed>' panicked at crates/move-binary-format/src/check_bounds.rs:549:21:
PartialVMError { major_status: UNKNOWN_INVARIANT_VIOLATION_ERROR, ...
    message: Some("crates/move-binary-format/src/check_bounds.rs:549 (assert)") }
==> libFuzzer: deadly signal
```

Stack (abridged):

```
move_binary_format::check_bounds::BoundsChecker::check_code        check_bounds.rs:549
move_binary_format::check_bounds::BoundsChecker::check_function_def
move_binary_format::check_bounds::BoundsChecker::verify_module
move_bytecode_verifier::verifier::verify_module_unmetered          verifier.rs:41
code_unit::__libfuzzer_sys_run                                     fuzz_targets/code_unit.rs:81
```

## Cause

`check_bounds.rs:521` and `:549` guard the five deprecated global-storage instructions
(`ExistsGenericDeprecated`, `ImmBorrowGlobalGenericDeprecated`, `MutBorrowGlobalGenericDeprecated`,
`MoveFromGenericDeprecated`, `MoveToGenericDeprecated`, and the non-generic pair above them) with

```rust
safe_assert!(!self.deprecate_global_storage_ops);
```

`safe_assert!` (`move-binary-format/src/lib.rs:154`) is explicitly two-faced:

```rust
if cfg!(debug_assertions) { panic!("{:?}", err) } else { return Err(err) }
```

`verify_module_unmetered` runs the bounds checker with `deprecate_global_storage_ops = true`, so a
module whose code stream contains one of those opcodes trips the assert. The three
`Arbitrary`-driven targets build a `CompiledModule` **in memory**, bypassing the deserializer — and
the deserializer is what would normally reject these opcodes — so `Vec<Bytecode>` can contain them
freely. On chain the bytes go through `CompiledModule::deserialize_with_defaults` first, which is
why `deserialize_verify` never reaches this path.

## Impact

None in a shipped build. Sui runs release binaries with `debug_assertions` off, where the same line
returns `Err(UNKNOWN_INVARIANT_VIOLATION_ERROR)` and the module is rejected cleanly — the intended
behaviour. The panic is the macro's deliberate "shout loudly during development" branch.

## Why it mattered for this integration

With `--debug-assertions`, `code_unit` and `mixed` produced **3891 crash artifacts in ~6 minutes**
of fork-mode fuzzing, and a 40-artifact sample grouped onto exactly **two** program counters —
these two asserts. That is the "rediscovering one bug forever and burning the whole budget" shape.
Rebuilt without `--debug-assertions` (but with `-Coverflow-checks=on`, so Rust arithmetic overflow
is still a hard panic), the same two targets ran **7.5M and 4.9M executions** in ~2 minutes each
with **0 crashes / OOMs / timeouts** and **higher** coverage — 5675 and 6360 edges, against 4419
and 2076 under debug assertions. `mayhem/build.sh` therefore builds all four targets with `-O` and
no `--debug-assertions`; the reasoning is repeated there next to the `RUSTFLAGS` line.

No harness was changed, no input is filtered, and no upstream file was touched — the library is
simply built the way it ships.

## Upstream fix, if one is wanted

None is needed for correctness. If sui wants these targets usable under debug assertions, the
narrow change is to have `bytecode-verifier-libfuzzer`'s harnesses drop or remap the deprecated
global-storage opcodes before constructing the module, rather than to weaken `safe_assert!`.
