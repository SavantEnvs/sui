// deserialize_verify — feed the Move binary-format DESERIALIZER raw attacker-controlled bytes,
// then run the full bytecode verifier over whatever module comes out.
//
// WHY THIS TARGET EXISTS (it is not a duplicate of sui's own three).
// sui ships three cargo-fuzz targets over the same verifier
// (external-crates/move/crates/bytecode-verifier-libfuzzer): `code_unit`, `compiled_module` and
// `mixed`. All three build their `CompiledModule` through `arbitrary::Arbitrary`, i.e. they
// CONSTRUCT an in-memory module directly and hand it to the verifier. That is excellent for
// reaching deep verifier states, but it means the byte-level decoder is never executed at all.
//
// On chain the order is the other way round: a publish transaction carries a module as BYTES, and
// `CompiledModule::deserialize_with_defaults` — ULEB128 table offsets/counts, table bounds, the
// identifier/address/constant pools, signature-token recursion, and the BoundsChecker it calls
// internally — is the first untrusted-input code an attacker reaches. This target covers exactly
// that path and then chains into `verify_module_unmetered`, so a module that decodes successfully
// is still pushed through the whole verifier pipeline.
//
// No file I/O, no timers, no watchdogs: the harness consumes only the fuzzer's bytes (Mayhem and
// rlenv own the per-exec timeout; the Mayhemfile sets it). Starter seeds are the real compiled
// `.mv` modules sui already ships as test fixtures — see mayhem/deserialize_verify/testsuite/.
#![no_main]

use libfuzzer_sys::{Corpus, fuzz_target};
use move_binary_format::file_format::CompiledModule;

fuzz_target!(|data: &[u8]| -> Corpus {
    match CompiledModule::deserialize_with_defaults(data) {
        Ok(module) => {
            // The verifier is the thing under test; its Err is an ordinary "module rejected"
            // result, not a finding. A panic/UB/OOM inside it is what we are hunting.
            let _ = move_bytecode_verifier::verify_module_unmetered(&module);
            Corpus::Keep
        }
        // Reject, never repair: bytes that are not a Move module at all teach the corpus nothing,
        // so tell libFuzzer not to keep them (https://llvm.org/docs/LibFuzzer.html#rejecting-unwanted-inputs).
        Err(_) => Corpus::Reject,
    }
});
