//! With the verifier built `--features pinned-srs`, a proof made under a different SRS
//! (here the insecure test setup, whose tau is public) must be refused at STAGE1 with
//! SRS_NOT_PINNED (0x104), while the real-SRS proof still verifies (tests/kzg.rs).
//! Run only against a pinned build: PINNED_SRS=1 cargo test --release -p private-claim-circuit --test pinned
mod common;

use private_claim_circuit::{prover::*, *};

#[test]
fn foreign_srs_is_refused_by_pinned_verifier() {
    if std::env::var("PINNED_SRS").is_err() {
        eprintln!("skipped: set PINNED_SRS=1 with a pinned-srs verifier build");
        return;
    }
    use mollusk_svm::Mollusk;
    use solana_account::Account;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_pubkey::Pubkey;

    let params = load_params(K, None).unwrap(); // insecure setup: a tau the attacker knows
    let keys = keygen(&params).unwrap();
    let (_, w) = common::sample();
    let p = generate_claim_proof(&params, &keys, &w).unwrap();
    assert!(matches!(halo2_solana_verifier::verify(&p.vk_bytes, &p.proof_bytes, &p.public_inputs_be, &p.kzg_vk), Ok(true)),
        "the foreign-SRS proof verifies against its own (caller-supplied) points");

    let deploy = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy");
    std::env::set_var("SBF_OUT_DIR", deploy);
    let mut payload = p.golden();
    payload[..8].copy_from_slice(b"GLDN0001");
    let nonce: u64 = 7;
    let (program_id, data_pk, s1_pk, signer_pk) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
    let mut data_acc = Account::new(100_000_000, payload.len(), &program_id);
    data_acc.data = payload;
    let accs = vec![
        (data_pk, data_acc),
        (s1_pk, Account::new(100_000_000, 4096, &program_id)),
        (signer_pk, Account::new(100_000_000, 0, &Pubkey::default())),
    ];
    let mut mollusk = Mollusk::new(&program_id, "halo2_solana_verifier_program");
    mollusk.compute_budget.compute_unit_limit = 1_400_000;
    mollusk.compute_budget.heap_size = 256 * 1024;
    let mut d = vec![0x02u8];
    d.extend_from_slice(&nonce.to_le_bytes());
    let ix = Instruction { program_id, data: d, accounts: vec![
        AccountMeta::new_readonly(data_pk, false), AccountMeta::new(s1_pk, false), AccountMeta::new_readonly(signer_pk, true)] };
    let r = mollusk.process_instruction(&ix, &accs);
    eprintln!("[pinned] STAGE1 with foreign SRS → {:?}", r.program_result);
    // SRS_NOT_PINNED = 0x104 = 260
    assert!(format!("{:?}", r.program_result).contains("Custom(260)"),
        "pinned verifier must refuse a foreign SRS, got {:?}", r.program_result);
}
