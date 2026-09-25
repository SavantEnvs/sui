#!/usr/bin/env bash
#
# mayhem/test.sh — RUN sui's own Move bytecode-verifier / binary-format test suites plus a
# known-answer probe, and emit a CTRF summary. Exit 0 iff nothing failed.
#
# PATCH-grade oracle (SPEC §6.3). Two parts, and the SECOND is the load-bearing one:
#
#  1) `cargo test -p bytecode-verifier-tests -p move-binary-format` (in the external-crates/move
#     workspace) — sui's real conformance suite for exactly the code the fuzz targets hit:
#     ~104 #[test]s asserting which malformed modules the verifier must REJECT and with which
#     StatusCode, plus move-binary-format's own ~68 serializer/deserializer tests. These assert
#     exact error variants and exact decoded values, not merely "didn't panic". Scoped to those
#     two crates because a `--workspace` run would compile and exercise the whole Move toolchain
#     (compiler, CLI, analyzer, package manager) for no oracle benefit.
#
#  2) The KAT probe /mayhem/kat. `cargo test` ALONE is explicitly not an acceptable oracle: its
#     libtest harness runs every #[test] in-process from one entrypoint, so an early process-wide
#     _exit(0) is indistinguishable from "the test binary produced no output" — easy to
#     reward-hack around. /mayhem/kat is a tiny, separate, DYNAMICALLY LINKED binary that decodes
#     one FIXED, real, on-chain Move module (embedded at compile time — no runtime file I/O) and
#     prints exact computed values. Neutered, it prints nothing and every assertion below fails;
#     a patch that stubs the deserializer or the verifier to dodge a crash cannot reproduce these
#     numbers either. That is what makes this a value-asserting, sabotage-detecting oracle.
#
# This script only RUNS things — mayhem/build.sh built the fuzz targets, pre-built the test
# suite, and built /mayhem/kat.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

export PATH="/opt/toolchains/rust/cargo/bin:$PATH"
export CARGO_HOME="${CARGO_HOME:-/opt/toolchains/rust/cargo}"
: "${SRC:=/mayhem}"
cd "$SRC"

# sui's own rust-toolchain.toml hijacks any BARE `cargo` under this tree via rustup's
# directory-override lookup (see mayhem/build.sh / mayhem/Dockerfile). build.sh already resolved
# and RECORDED which toolchain it used for the oracle build; read that back rather than
# re-deriving, so the suite can never silently rebuild under a different compiler at test time.
ORACLE_TOOLCHAIN="$(cat "$SRC/target/mayhem/oracle-toolchain.txt" 2>/dev/null || true)"
if [ -z "$ORACLE_TOOLCHAIN" ]; then
  echo "FAIL: target/mayhem/oracle-toolchain.txt missing — mayhem/build.sh did not run" >&2
  exit 2
fi
echo "oracle toolchain (recorded by build.sh): $ORACLE_TOOLCHAIN"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PASSED=0; FAILED=0; SKIPPED=0

# ── 1) sui's own test suites (NORMAL flags, upstream's own toolchain pin) ────────────────────
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not available — cannot run the test suite" >&2
  emit_ctrf "cargo-test+kat" 0 1 0; exit 2
fi

mkdir -p "$SRC/target/mayhem"
TESTLOG="$SRC/target/mayhem/cargo-test.log"
TESTERR="$SRC/target/mayhem/cargo-test.err"
echo "=== running: cargo +$ORACLE_TOOLCHAIN test -p bytecode-verifier-tests -p move-binary-format ==="
( cd external-crates/move \
  && env -u RUSTFLAGS cargo "+$ORACLE_TOOLCHAIN" test \
       -p bytecode-verifier-tests -p move-binary-format --no-fail-fast ) \
  > "$TESTLOG" 2>"$TESTERR"
rc=$?
tail -40 "$TESTLOG" || true
[ -s "$TESTERR" ] && { echo "--- stderr (tail) ---"; tail -20 "$TESTERR"; }

# Plain-text libtest summary lines: "test result: ok. 104 passed; 0 failed; 0 ignored; ..."
# (one per test binary + doctests). Sum them all.
PASSED=$(grep -oE '[0-9]+ passed'  "$TESTLOG" | awk '{s+=$1} END{print s+0}')
FAILED=$(grep -oE '[0-9]+ failed'  "$TESTLOG" | awk '{s+=$1} END{print s+0}')
SKIPPED=$(grep -oE '[0-9]+ ignored' "$TESTLOG" | awk '{s+=$1} END{print s+0}')
: "${PASSED:=0}" "${FAILED:=0}" "${SKIPPED:=0}"

# A suite that produced NO parseable result did not run at all (build error, or the binaries were
# neutered). That is a FAILURE, not a reason to stop: fall through so the KAT probe below still
# runs and reports independently — two failing signals localise the problem better than one.
if [ "$(( PASSED + FAILED + SKIPPED ))" -eq 0 ]; then
  echo "FAIL: no test results parsed — the suite did not run (cargo exit $rc)" >&2
  FAILED=$(( FAILED + 1 ))
fi
# A non-zero cargo exit with zero counted failures means a build/harness error: stay honest.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=$(( FAILED + 1 )); fi

# ── 2) the KAT probe (sabotage-detecting; see header) ────────────────────────────────────────
# UNCONDITIONAL by design: a missing binary is a FAILURE, never a skip. A `[ -f ... ]` guard here
# is how a probe silently stops running and the oracle quietly degrades to the (weaker)
# cargo-test-only case.
echo "=== KAT probe: /mayhem/kat (decodes a fixed real on-chain Move module; asserts parsed VALUES) ==="
KAT_OUT="$(/mayhem/kat 2>&1)"; kat_rc=$?
echo "$KAT_OUT"

# Expected values — computed directly against this build from the embedded fixture, a byte-exact
# copy of external-crates/move/crates/move-decompiler/tests/bytecode/cat_nft.mv (1280 bytes, a
# real published Sui module). Every line is a decoded structural fact about that module, plus the
# four rejection cases that prove the decoder refuses damaged input rather than repairing it.
kat_expect() {
  local label="$1" line="$2"
  if printf '%s\n' "$KAT_OUT" | grep -qxF "$line"; then
    echo "KAT PASS: $label"
    PASSED=$(( PASSED + 1 ))
  else
    echo "KAT FAIL: $label — expected exact line: $line" >&2
    FAILED=$(( FAILED + 1 ))
  fi
}

if [ "$kat_rc" -ne 0 ]; then
  echo "KAT FAIL: /mayhem/kat exited $kat_rc (neutered, missing, or broken)" >&2
  FAILED=$(( FAILED + 1 ))
fi
kat_expect "fixture size"                    'KAT_BYTES=1280'
kat_expect "decoded file-format version"     'KAT_VERSION=6'
kat_expect "decoded self module name"        'KAT_SELF_NAME=cat_nft'
kat_expect "module handle pool size"         'KAT_MODULE_HANDLES=9'
kat_expect "datatype handle pool size"       'KAT_DATATYPE_HANDLES=10'
kat_expect "function handle pool size"       'KAT_FUNCTION_HANDLES=20'
kat_expect "function definition count"       'KAT_FUNCTION_DEFS=9'
kat_expect "struct definition count"         'KAT_STRUCT_DEFS=3'
kat_expect "identifier pool size"            'KAT_IDENTIFIERS=40'
kat_expect "signature pool size"             'KAT_SIGNATURES=32'
kat_expect "constant pool size"              'KAT_CONSTANTS=12'
kat_expect "verifier accepts the module"     'KAT_VERIFY=ok'
kat_expect "serializer round-trips byte-exact" 'KAT_ROUNDTRIP=exact'
kat_expect "truncated input rejected"        'KAT_TRUNCATED=rejected'
kat_expect "corrupted magic rejected"        'KAT_BAD_MAGIC=rejected:BAD_MAGIC'
kat_expect "extraneous trailing byte rejected" 'KAT_TRAILING_BYTE=rejected'
kat_expect "empty input rejected"            'KAT_EMPTY=rejected'

emit_ctrf "cargo-test+kat" "$PASSED" "$FAILED" "$SKIPPED"
