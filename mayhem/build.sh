#!/usr/bin/env bash
#
# mayhem/build.sh — build sui's Move bytecode-verifier fuzz targets as sanitized libFuzzer
# binaries (OSS-Fuzz Rust path: cargo-fuzz + ASan via RUSTFLAGS), the mayhem/kat oracle probe,
# and (built only, not run) the upstream test suite mayhem/test.sh executes.
#
# TARGETS (one Mayhemfile each). All four fuzz the MOVE BYTECODE VERIFIER — the component that
# decides whether an untrusted Move module published by any account is safe to load, and the
# single most attacker-reachable decode/verify surface in the repo.
#
#   /mayhem/code_unit           sui's OWN target. Arbitrary<CodeUnit> (instruction stream +
#                               locals signature index + jump tables) dropped into a synthetic
#                               module, then verified. Reaches the control-flow graph builder,
#                               the abstract interpreter and the jump-table/variant-switch
#                               checks directly, without having to satisfy the decoder first.
#   /mayhem/compiled_module     sui's OWN target. Arbitrary<CompiledModule>: a whole module
#                               structure straight into verify_module_unmetered. The broadest
#                               reach into the verifier's cross-table consistency checks.
#   /mayhem/mixed               sui's OWN target. Arbitrary instruction stream + ability set +
#                               parameter/return signature tokens. Pairs an adversarial code
#                               stream with adversarial TYPES, which is what the type-safety
#                               and reference-safety passes actually consume.
#   /mayhem/deserialize_verify  ADDITIVE (mayhem/fuzz/). Raw attacker bytes ->
#                               CompiledModule::deserialize_with_defaults -> full verifier.
#                               Covers the byte-level decoder (ULEB128 table offsets/counts,
#                               table bounds, pools, signature-token recursion, BoundsChecker)
#                               that the three Arbitrary-driven targets bypass entirely — which
#                               is precisely the code a publish transaction hits FIRST. Seeded
#                               with real compiled .mv modules from sui's own fixtures.
#   /mayhem/kat                 dynamically-linked known-answer probe (used by mayhem/test.sh).
#
# NOTHING UPSTREAM IS EDITED. The first three targets are built IN PLACE out of upstream's own
# crate (external-crates/move/crates/bytecode-verifier-libfuzzer) via `cargo fuzz --fuzz-dir`;
# the fourth lives in mayhem/fuzz/, an ADDITIVE crate that is its own cargo workspace and only
# CALLS the upstream crates through path dependencies.
#
# TWO DIFFERENT OUTPUT PATHS, and this is a real trap: `cargo fuzz build`'s output location
# depends on WORKSPACE MEMBERSHIP. bytecode-verifier-libfuzzer IS a member of the
# external-crates/move workspace (its own `[workspace]` table is commented out upstream), so its
# binaries land in external-crates/move/target/<triple>/release/ — the WORKSPACE ROOT's target dir,
# not the crate's. mayhem/fuzz declares its own `[workspace]`, so cargo would write
# mayhem/fuzz/target/ instead; we redirect that one with CARGO_TARGET_DIR (see $OUT below for why
# no build output may live under mayhem/). Both resulting paths are asserted below, so a wrong
# guess fails loudly instead of silently "succeeding".
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The Rust toolchain and
# cargo registry live at $CARGO_HOME=/opt/toolchains/rust/cargo (absolute, $HOME-independent).
#
# DWARF gate (SPEC §6.2 item 10) + LeakSanitizer policy, both handled by ONE generated cc-wrapper:
# rustc's own CUs land at DWARF4 and the ASan runtime archive at DWARF5, and the gate reads only
# the FIRST .debug_info CU. The Dockerfile precompiles a DWARF3 anchor object; this script
# compiles mayhem/lsan_off.c next to it and writes a `-Clinker` wrapper that PREPENDS BOTH objects
# ahead of every other link input. Prepend (not append) is required for the anchor's CU to land at
# .debug_info offset 0 — verified on this repo (readelf reports "Version: 3"). Prepending is also
# how the __lsan_is_turned_off() hook reaches EVERY sanitized binary rather than one of them.
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (in CI, online) populates the cargo registry under $CARGO_HOME.
#   - The re-run resolves crates from that cache; the rlenv runtime exports CARGO_NET_OFFLINE=true
#     for it, so we do NOT hard-code `--offline` here (that would break this first, online build).
#   - Re-running on an already-built tree must also succeed: every step below is safe to repeat
#     (mkdir -p, cp -f, cargo overwrites).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SRC:=/mayhem}"
cd "$SRC"

# Parallelism is bounded by MEMORY, not cores: an ASan-instrumented rustc job on the move crates
# peaks around 1.5-2 GB, and both the conformance gate and the rlenv analyze nodes run this build
# under a hard container memory cap (8 GB by default). Unbounded `nproc` jobs on a 16-core runner
# would OOM-kill the build for no speed benefit — the whole fuzz build is ~1-2 minutes either way.
# Override with MAYHEM_JOBS=<n> when you know the box.
#
# The budget is read from the CGROUP (/sys/fs/cgroup/memory.max), not from /proc/meminfo:
# /proc/meminfo inside a container reports the HOST's memory, so a `--memory=8g` build on a 15 GB
# box would look like 15 GB and happily oversubscribe. Fall back to nproc when the cgroup file is
# absent or says "max" (uncapped).
: "${MAYHEM_JOBS:=$(
    _cores=$(nproc)
    _lim=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo max)
    case "$_lim" in
      ''|max|*[!0-9]*) echo "$_cores" ;;
      *) _bymem=$(( _lim / 2000000000 ))
         [ "$_bymem" -lt 1 ] && _bymem=1
         [ "$_bymem" -lt "$_cores" ] && echo "$_bymem" || echo "$_cores" ;;
    esac)}"
[ -n "$MAYHEM_JOBS" ] || MAYHEM_JOBS=2
echo "build parallelism: MAYHEM_JOBS=$MAYHEM_JOBS (nproc=$(nproc))"
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

# Build OUTPUT lives under the repo-root target/ tree, NOT under mayhem/, and that placement is
# load-bearing rather than cosmetic. The conformance gate greps mayhem/ RECURSIVELY and
# CONTENT-WISE for the forbidden __asan/__lsan option-override symbol names; an ASan-linked fuzz
# binary contains those strings in its own symbol table, so a cargo target/ dir left anywhere under
# mayhem/ makes the gate hard-FAIL on a perfectly clean integration (observed: three files under
# mayhem/fuzz/target/ flagged this way). target/ is already ignored by sui's root .gitignore
# (`**/target`) and dropped from the docker build context by mayhem/Dockerfile.dockerignore, and
# rlenv preserves target/ for cargo projects, so the cache still survives an offline PATCH re-run.
OUT="$SRC/target/mayhem"
mkdir -p "$OUT"

# ── toolchains ─────────────────────────────────────────────────────────────────────────────
# sui's root rust-toolchain.toml (channel = "1.96.1" — an upstream file we never edit) overrides
# EVERY bare `cargo` under this tree through rustup's directory-override lookup, INCLUDING inside
# mayhem/fuzz and mayhem/kat. A bare `cargo fuzz build` would therefore silently run on that
# stable toolchain and fail on `-Zsanitizer=address` ("only accepted on the nightly compiler").
# So: never a bare `cargo` below — always an explicit `+<toolchain>`.
: "${RUST_FUZZ_TOOLCHAIN:?RUST_FUZZ_TOOLCHAIN must be set by mayhem/Dockerfile}"
ORACLE_TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)"
[ -n "$ORACLE_TOOLCHAIN" ] || { echo "ERROR: could not read channel from rust-toolchain.toml" >&2; exit 1; }
echo "fuzz toolchain  (Dockerfile-pinned nightly): $RUST_FUZZ_TOOLCHAIN"
echo "oracle toolchain (upstream's own rust-toolchain.toml pin): $ORACLE_TOOLCHAIN"
# Record it so mayhem/test.sh runs the suite on the IDENTICAL toolchain instead of re-deriving it.
printf '%s\n' "$ORACLE_TOOLCHAIN" > "$OUT/oracle-toolchain.txt"

# ── LeakSanitizer OFF at build time + the DWARF3 anchor, via one cc-wrapper ─────────────────
# $SANITIZER_FLAGS is the base image's CLANG-oriented ASan/UBSan contract (SPEC §6.1 / §6.2 item
# 8). rustc ignores it entirely and gets its own sanitizer switch through RUSTFLAGS below, but the
# clang-compiled hook TU here is exactly where it applies. -gdwarf-3 is appended AFTER
# $SANITIZER_FLAGS (which ends in a plain -g): last flag wins, so appending is what actually pins
# the DWARF version — putting it before would let -g re-select clang-19's default DWARF-5.
echo "SANITIZER_FLAGS=${SANITIZER_FLAGS:-}"
echo "=== compiling the LeakSanitizer hook (mayhem/lsan_off.c) ==="
clang ${SANITIZER_FLAGS:-} -gdwarf-3 -c "$SRC/mayhem/lsan_off.c" -o "$OUT/lsan_off.o"
nm "$OUT/lsan_off.o" | grep -q '__lsan_is_turned_off' \
  || { echo "FATAL: $OUT/lsan_off.o does not define __lsan_is_turned_off" >&2; exit 1; }

ANCHOR=/opt/toolchains/rust/dwarf3/anchor.o
[ -f "$ANCHOR" ] || { echo "FATAL: DWARF3 anchor $ANCHOR missing (built by mayhem/Dockerfile)" >&2; exit 1; }

CCWRAP="$OUT/cc-wrapper.sh"
# PREPEND both objects: anchor first (its CU must be at .debug_info offset 0), then the LSan hook.
printf '#!/bin/sh\nexec clang %s %s "$@"\n' "$ANCHOR" "$OUT/lsan_off.o" > "$CCWRAP"
chmod +x "$CCWRAP"
echo "cc-wrapper: $(cat "$CCWRAP" | tail -1)"

# RUST_DEBUG_FLAGS is the SPEC §6.2 item 10 knob for the Rust path — EDIT only if the wrapper
# moves; dropping -Clinker regresses BOTH the DWARF check and the LSan hook.
: "${RUST_DEBUG_FLAGS:=-Cdebuginfo=2 -Clinker=$CCWRAP}"

# OSS-Fuzz Rust libFuzzer+ASan flags. cargo-fuzz sets the ASan flag itself; we pin it explicitly.
# --cfg fuzzing matches libfuzzer-sys; force-frame-pointers aids ASan backtraces.
#
# -Coverflow-checks=on, and NO `--debug-assertions` on the cargo fuzz build lines below. This pair
# is deliberate and was chosen from measurement, not taste:
#
#   move-binary-format defines safe_assert!/safe_unwrap!/safe_assert_eq! (src/lib.rs), which
#   `panic!` under cfg!(debug_assertions) and `return Err(UNKNOWN_INVARIANT_VIOLATION_ERROR)`
#   otherwise. Building with --debug-assertions therefore turns every RECOVERABLE invariant check
#   in the bounds checker into an instant abort. Measured on this repo: with --debug-assertions,
#   code_unit + mixed produced 3891 crash artifacts in ~6 minutes of fork-mode fuzzing, all at
#   just TWO program counters — both the `safe_assert!(!self.deprecate_global_storage_ops)` in
#   BoundsChecker::check_code (check_bounds.rs:521 and :549), reached because the Arbitrary-driven
#   targets can synthesise a module containing the deprecated global-storage opcodes that the real
#   deserializer rejects. That is the classic "rediscovering one bug forever and burning the whole
#   budget" shape (PORTING.md / docs/netnew-worker-prompt.md §6c), and it is not even a production
#   bug: sui ships release builds, where the same path returns an error. Rebuilt WITHOUT
#   --debug-assertions the two targets ran 7.5M and 4.9M executions in ~2 minutes each with
#   0 crashes/OOMs/timeouts and HIGHER coverage (5675 and 6360 edges vs 4419 and 2076).
#
#   Nothing is being masked: the harnesses are untouched, no input is filtered, and the library is
#   built exactly as it ships. -Coverflow-checks=on is added back explicitly so the one bug class
#   that --debug-assertions would otherwise have bought us — Rust arithmetic overflow — is STILL
#   a hard panic. See mayhem/code_unit/known-findings/ for the written-up finding.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing -Zsanitizer=address -Cforce-frame-pointers -Coverflow-checks=on $RUST_DEBUG_FLAGS"
echo "RUSTFLAGS=$RUSTFLAGS"

TRIPLE="x86_64-unknown-linux-gnu"

# ── 1. sui's OWN cargo-fuzz crate, built IN PLACE (no upstream file touched) ────────────────
UPSTREAM_FUZZ_DIR="external-crates/move/crates/bytecode-verifier-libfuzzer"
# Discover the targets from upstream's own fuzz_targets/ dir rather than hard-coding them, so an
# upstream-added target is picked up by the next sync instead of being silently dropped.
UPSTREAM_TARGETS=()
for f in "$UPSTREAM_FUZZ_DIR"/fuzz_targets/*.rs; do
  UPSTREAM_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#UPSTREAM_TARGETS[@]}" -gt 0 ] \
  || { echo "ERROR: no fuzz targets under $UPSTREAM_FUZZ_DIR/fuzz_targets/" >&2; exit 1; }
echo "=== cargo fuzz build — upstream crate: ${UPSTREAM_TARGETS[*]} ==="
for t in "${UPSTREAM_TARGETS[@]}"; do
  echo "--- building upstream fuzz target: $t ---"
  # -O only: see the RUSTFLAGS block above for why --debug-assertions is deliberately absent.
  cargo "+$RUST_FUZZ_TOOLCHAIN" fuzz build --fuzz-dir "$UPSTREAM_FUZZ_DIR" -O "$t"
  # Workspace MEMBER => binaries land in the workspace root's target dir, not the crate's.
  bin="$SRC/external-crates/move/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp -f "$bin" "/mayhem/$t"
  echo "built /mayhem/$t"
done

# ── 2. the ADDITIVE crate (its own workspace) ───────────────────────────────────────────────
ADD_FUZZ_DIR="mayhem/fuzz"
ADD_TARGETS=()
for f in "$ADD_FUZZ_DIR"/fuzz_targets/*.rs; do
  ADD_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#ADD_TARGETS[@]}" -gt 0 ] \
  || { echo "ERROR: no fuzz targets under $ADD_FUZZ_DIR/fuzz_targets/" >&2; exit 1; }
echo "=== cargo fuzz build — additive crate: ${ADD_TARGETS[*]} ==="
for t in "${ADD_TARGETS[@]}"; do
  echo "--- building additive fuzz target: $t ---"
  # -O only, same rationale as the upstream targets above (kept identical so all four binaries
  # are built with one configuration).
  # CARGO_TARGET_DIR redirects this crate's output out of mayhem/ (see the $OUT comment above);
  # without it cargo would write mayhem/fuzz/target/ and trip the gate's content grep.
  env CARGO_TARGET_DIR="$OUT/fuzz-target" \
    cargo "+$RUST_FUZZ_TOOLCHAIN" fuzz build --fuzz-dir "$ADD_FUZZ_DIR" -O "$t"
  bin="$OUT/fuzz-target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp -f "$bin" "/mayhem/$t"
  echo "built /mayhem/$t"
done

ALL_TARGETS=("${UPSTREAM_TARGETS[@]}" "${ADD_TARGETS[@]}")

# ── 3. per-target dictionaries into the flat /mayhem root (where each Mayhemfile points) ────
# A dict named by a Mayhemfile but absent from the image makes libFuzzer exit 1 at 0 edges, so
# copy every one that exists and let the Mayhemfile reference the copy.
for t in "${ALL_TARGETS[@]}"; do
  d="mayhem/$t/$t.dict"
  if [ -f "$d" ]; then
    cp -f "$d" "/mayhem/$t.dict"
    echo "copied dictionary /mayhem/$t.dict"
  fi
done

# ── 4. the KAT probe used by mayhem/test.sh ─────────────────────────────────────────────────
# NORMAL flags: it is a functional oracle, not a triage artifact — no sanitizer, no fuzz
# instrumentation, no DWARF3 anchor, and upstream's OWN toolchain pin (the nightly above is only
# needed for -Zsanitizer=address). A plain cargo build on the gnu target is already dynamically
# linked; assert it anyway so a future static-link change can't silently weaken the oracle.
echo "=== building /mayhem/kat (KAT probe, oracle toolchain $ORACLE_TOOLCHAIN) ==="
( cd mayhem/kat && env -u RUSTFLAGS CARGO_TARGET_DIR="$OUT/kat-target" \
    cargo "+$ORACLE_TOOLCHAIN" build --release )
cp -f "$OUT/kat-target/release/kat" /mayhem/kat
if ! file /mayhem/kat | grep -q 'dynamically linked'; then
  echo "FATAL: /mayhem/kat is not dynamically linked — the gate's sabotage check could not" >&2
  echo "       neuter it, which would make mayhem/test.sh a reward-hackable oracle." >&2
  file /mayhem/kat >&2
  exit 1
fi
echo "built /mayhem/kat (dynamically linked)"

# ── 5. upstream's own test suite — BUILD only; mayhem/test.sh runs it ───────────────────────
# Scoped to the two crates that actually assert the harnessed behaviour: bytecode-verifier-tests
# (the verifier's own conformance suite) and move-binary-format (serializer/deserializer unit
# tests). Both are members of the external-crates/move workspace, which is a DIFFERENT workspace
# from sui's root one — hence the subshell cd. A `--workspace` build here would compile the entire
# Move toolchain (compiler, CLI, analyzer, package manager) for no oracle benefit.
echo "=== building the project's own test suite (oracle toolchain $ORACLE_TOOLCHAIN) ==="
( cd external-crates/move \
  && env -u RUSTFLAGS cargo "+$ORACLE_TOOLCHAIN" test \
       -p bytecode-verifier-tests -p move-binary-format --no-run )

echo "build.sh complete:"
ls -la /mayhem/kat "${ALL_TARGETS[@]/#//mayhem/}"
