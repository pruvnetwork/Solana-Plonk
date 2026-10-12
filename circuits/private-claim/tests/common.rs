#![allow(dead_code)]
use halo2curves::bn256::Fr;
use private_claim_circuit::*;

/// 5 leaves, ours at index 3.
pub fn sample() -> (Vec<Fr>, ClaimWitness) {
    let round_id = 42u64;
    let secret = Fr::from(0xdead_beef_u64) * Fr::from(1_000_003u64);
    let mut leaves: Vec<Fr> = (0..5u64).map(|i| leaf_commitment(Fr::from(1000 + i), round_id)).collect();
    leaves[3] = leaf_commitment(secret, round_id);
    let (siblings, bits) = merkle_path(&leaves, 3);
    let seed = hash_two(Fr::from(7u64), Fr::from(8u64));
    let mut pk = [0u8; 32];
    for (i, b) in pk.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(37).wrapping_add(11); }
    let recipient = field_from_le_bytes(&pk);
    (leaves, ClaimWitness { secret, round_id, seed, recipient, siblings, bits })
}
