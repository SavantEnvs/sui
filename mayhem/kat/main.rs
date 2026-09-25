//! kat — a known-answer probe over the exact code path the fuzz targets exercise.
//!
//! WHY IT EXISTS (SPEC §6.3, anti-reward-hacking). `cargo test` alone is not an acceptable
//! oracle: libtest runs every `#[test]` in-process from one entrypoint, so a process-wide
//! `_exit(0)` looks indistinguishable from "the test binary produced no output". This probe is a
//! tiny, separate, DYNAMICALLY LINKED binary whose whole job is to decode one FIXED, real,
//! on-chain Move module and print exact computed values. Neuter it and it prints nothing, so
//! every exact-line assertion in mayhem/test.sh fails; stub out the deserializer or the verifier
//! to dodge a crash and the printed values change. Either way the oracle notices.
//!
//! The fixture is embedded at COMPILE time via `include_bytes!`, so the probe does no runtime
//! file I/O at all (SPEC §6.2 item 13). It is a byte-for-byte copy of
//! external-crates/move/crates/move-decompiler/tests/bytecode/cat_nft.mv — one of the real
//! compiled Move modules sui ships as a decompiler fixture — copied rather than referenced
//! across the tree so the probe cannot break when upstream reorganises its test data.

use move_binary_format::file_format::CompiledModule;

const MODULE: &[u8] = include_bytes!("fixture_module.mv");

fn main() {
    // ── 1. decode the real module ────────────────────────────────────────────────────────────
    let m = match CompiledModule::deserialize_with_defaults(MODULE) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("KAT_FATAL: fixture failed to deserialize: {e:?}");
            std::process::exit(1);
        }
    };

    println!("KAT_BYTES={}", MODULE.len());
    println!("KAT_VERSION={}", m.version);
    println!(
        "KAT_SELF_NAME={}",
        m.identifier_at(m.self_handle().name).as_str()
    );
    println!("KAT_MODULE_HANDLES={}", m.module_handles.len());
    println!("KAT_DATATYPE_HANDLES={}", m.datatype_handles.len());
    println!("KAT_FUNCTION_HANDLES={}", m.function_handles.len());
    println!("KAT_FUNCTION_DEFS={}", m.function_defs.len());
    println!("KAT_STRUCT_DEFS={}", m.struct_defs.len());
    println!("KAT_IDENTIFIERS={}", m.identifiers.len());
    println!("KAT_SIGNATURES={}", m.signatures.len());
    println!("KAT_CONSTANTS={}", m.constant_pool.len());

    // ── 2. the verifier accepts this (real, published) module ────────────────────────────────
    println!(
        "KAT_VERIFY={}",
        match move_bytecode_verifier::verify_module_unmetered(&m) {
            Ok(()) => "ok",
            Err(_) => "err",
        }
    );

    // ── 3. serializer/deserializer round-trip is byte-exact ──────────────────────────────────
    // NB: the plain `serialize()` helper is `#[cfg(feature = "fuzzing")]` upstream, so this probe
    // (which deliberately does NOT enable that feature) goes through the always-available
    // `serialize_with_version`, re-encoding at the module's OWN decoded version.
    let mut out = Vec::new();
    let roundtrip = match m.serialize_with_version(m.version, &mut out) {
        Ok(()) => out.as_slice() == MODULE,
        Err(_) => false,
    };
    println!("KAT_ROUNDTRIP={}", if roundtrip { "exact" } else { "differs" });

    // ── 4. negative cases: the decoder must REJECT damaged input, not repair it ───────────────
    let truncated = &MODULE[..MODULE.len() / 2];
    println!(
        "KAT_TRUNCATED={}",
        match CompiledModule::deserialize_with_defaults(truncated) {
            Ok(_) => "accepted",
            Err(_) => "rejected",
        }
    );

    let mut bad_magic = MODULE.to_vec();
    bad_magic[0] ^= 0xff;
    println!(
        "KAT_BAD_MAGIC={}",
        match CompiledModule::deserialize_with_defaults(&bad_magic) {
            Ok(_) => "accepted".to_string(),
            Err(e) => format!("rejected:{:?}", e.major_status()),
        }
    );

    // A trailing byte must be rejected too: deserialize_with_defaults asks for
    // check_no_extraneous_bytes, and that check is load-bearing for publish safety.
    let mut trailing = MODULE.to_vec();
    trailing.push(0x00);
    println!(
        "KAT_TRAILING_BYTE={}",
        match CompiledModule::deserialize_with_defaults(&trailing) {
            Ok(_) => "accepted",
            Err(_) => "rejected",
        }
    );

    println!(
        "KAT_EMPTY={}",
        match CompiledModule::deserialize_with_defaults(&[]) {
            Ok(_) => "accepted",
            Err(_) => "rejected",
        }
    );
}
