//! Real KZG proof (SHPLONK / Keccak-BE) → host verifier → Mollusk 3-tx CU bench.
mod common;

use private_claim_circuit::{prover::*, *};

fn srs() -> Option<String> {
    let p = default_srs_path();
    if std::path::Path::new(&p).exists() { Some(p) } else { eprintln!("SRS {p} missing → insecure setup"); None }
}

#[test]
fn kzg_proof_host_verify_and_mollusk_3tx() {
    let srs = srs();
    let params = load_params(K, srs.as_deref()).unwrap();
    let keys = keygen(&params).unwrap();
    // VK determinism: a second keygen from a fresh SRS load gives identical bytes.
    let keys2 = keygen(&load_params(K, srs.as_deref()).unwrap()).unwrap();
    assert_eq!(keys.vk_bytes, keys2.vk_bytes, "VK not deterministic");

    let (_, w) = common::sample();
    let p = generate_claim_proof(&params, &keys, &w).unwrap();
    eprintln!("k={K} vk={}B proof={}B vk_hash={} instance_hash={}", p.vk_bytes.len(), p.proof_bytes.len(),
        hex::encode(p.vk_hash()), hex::encode(p.instance_hash()));

    let ok = halo2_solana_verifier::verify(&p.vk_bytes, &p.proof_bytes, &p.public_inputs_be, &p.kzg_vk);
    assert!(matches!(ok, Ok(true)), "host verifier: {ok:?}");
    for row in 0..NUM_INSTANCES {
        let mut bad = p.public_inputs_be.clone();
        bad[row][31] ^= 1;
        let r = halo2_solana_verifier::verify(&p.vk_bytes, &p.proof_bytes, &bad, &p.kzg_vk);
        assert!(!matches!(r, Ok(true)), "tampered instance row {row} accepted");
    }
    let mut badp = p.proof_bytes.clone();
    badp[100] ^= 1;
    assert!(!matches!(halo2_solana_verifier::verify(&p.vk_bytes, &badp, &p.public_inputs_be, &p.kzg_vk), Ok(true)));

    mollusk_3tx(&p);
}

fn mollusk_3tx(p: &ClaimProof) {
    use mollusk_svm::{result::ProgramResult, Mollusk};
    use solana_account::Account;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_pubkey::Pubkey;

    let deploy = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy");
    if !std::path::Path::new(deploy).join("halo2_solana_verifier_program.so").exists() {
        panic!("build the program first: cargo build-sbf --manifest-path programs/verifier-program/Cargo.toml --features bpf-entrypoint");
    }
    std::env::set_var("SBF_OUT_DIR", deploy);

    let mut payload = p.golden();
    payload[..8].copy_from_slice(b"GLDN0001");
    let nonce: u64 = 0x4242_4242_4242_4242;
    let (program_id, data_pk, s1_pk, s2_pk, signer_pk) =
        (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
    let mut data_acc = Account::new(100_000_000, payload.len(), &program_id);
    data_acc.data = payload;
    let mut accs = vec![
        (data_pk, data_acc),
        (s1_pk, Account::new(100_000_000, 4096, &program_id)),
        (s2_pk, Account::new(100_000_000, 8192, &program_id)),
        (signer_pk, Account::new(100_000_000, 0, &Pubkey::default())),
    ];
    let mut mollusk = Mollusk::new(&program_id, "halo2_solana_verifier_program");
    mollusk.compute_budget.compute_unit_limit = 1_400_000;
    mollusk.compute_budget.heap_size = 256 * 1024;

    let ixd = |tag: u8| { let mut d = vec![tag]; d.extend_from_slice(&nonce.to_le_bytes()); d };
    let stages = [
        ("STAGE1", Instruction { program_id, data: ixd(0x02), accounts: vec![
            AccountMeta::new_readonly(data_pk, false), AccountMeta::new(s1_pk, false), AccountMeta::new_readonly(signer_pk, true)] }),
        ("STAGE2A", Instruction { program_id, data: ixd(0x04), accounts: vec![
            AccountMeta::new_readonly(data_pk, false), AccountMeta::new_readonly(s1_pk, false), AccountMeta::new(s2_pk, false),
            AccountMeta::new_readonly(signer_pk, true)] }),
        ("STAGE3", Instruction { program_id, data: ixd(0x05), accounts: vec![
            AccountMeta::new(s2_pk, false), AccountMeta::new_readonly(signer_pk, true)] }),
    ];
    let mut total = 0;
    for (label, ix) in &stages {
        let r = mollusk.process_instruction(ix, &accs);
        eprintln!("[claim 3-tx] {label:7} CU = {} | {:?}", r.compute_units_consumed, r.program_result);
        assert!(matches!(r.program_result, ProgramResult::Success), "{label} failed (1.4M cap): {:?}", r.program_result);
        assert!(r.compute_units_consumed < 1_400_000);
        total += r.compute_units_consumed;
        for (pk, acc) in &r.resulting_accounts {
            if let Some(slot) = accs.iter_mut().find(|(q, _)| q == pk) { slot.1 = acc.clone(); }
        }
    }
    eprintln!("[claim 3-tx] TOTAL   CU = {total}");
    let rec = &accs.iter().find(|(q, _)| *q == s2_pk).unwrap().1.data;
    assert_eq!(&rec[..8], b"HALO2OK1");
    assert_eq!(&rec[8..40], &p.vk_hash());
    assert_eq!(&rec[40..72], &p.proof_hash());
    assert_eq!(&rec[72..104], &p.instance_hash());
    assert_eq!(&rec[104..136], signer_pk.as_ref());
    eprintln!("[claim 3-tx] VerifiedRecord matches vk_hash/proof_hash/instance_hash/payer");
}
