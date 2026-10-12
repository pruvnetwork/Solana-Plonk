mod common;

use halo2_proofs::dev::MockProver;
use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;
use private_claim_circuit::{circuit::*, *};

fn run(w: &ClaimWitness, inst: &[Fr]) -> Result<(), Vec<halo2_proofs::dev::VerifyFailure>> {
    let c = ClaimCircuit { witness: Some(w.clone()) };
    MockProver::run(K, &c, vec![inst.to_vec()]).unwrap().verify()
}

#[test]
fn valid_witness_passes() {
    let (leaves, w) = common::sample();
    let inst = w.instances();
    assert_eq!(inst[ROW_ROOT], merkle_root(&leaves));
    run(&w, &inst).expect("valid witness");
}

#[test]
fn bad_instances_fail() {
    let (_, w) = common::sample();
    let good = w.instances();
    for (row, name) in [(ROW_ROOT, "root"), (ROW_SEED, "seed"), (ROW_SCORE, "score"), (ROW_NULLIFIER, "nullifier"),
                        (ROW_ROUND, "round_id"), (ROW_RECIPIENT, "recipient"), (ROW_ZERO, "zero")] {
        let mut inst = good;
        inst[row] += Fr::one();
        assert!(run(&w, &inst).is_err(), "wrong {name} accepted");
    }
}

#[test]
fn swapped_sibling_order_fails() {
    let (_, w) = common::sample();
    let inst = w.instances();
    for lvl in [0, 1, 5, DEPTH - 1] {
        let mut bad = w.clone();
        bad.bits[lvl] = !bad.bits[lvl];
        assert!(run(&bad, &inst).is_err(), "flipped bit at level {lvl} accepted");
    }
    let mut bad = w.clone();
    bad.siblings.swap(0, 1);
    assert!(run(&bad, &inst).is_err(), "permuted siblings accepted");
}

#[test]
fn wrong_secret_fails() {
    let (_, w) = common::sample();
    let inst = w.instances();
    let mut bad = w.clone();
    bad.secret += Fr::one();
    assert!(run(&bad, &inst).is_err());
}

#[test]
fn every_index_and_tree_size() {
    // Edge cases: first, last, single leaf, odd sizes.
    for n in [1usize, 2, 3, 8, 9] {
        for idx in [0, n - 1] {
            let round_id = 9u64;
            let secret = Fr::from(77u64 + idx as u64);
            let mut leaves: Vec<Fr> = (0..n as u64).map(|i| Fr::from(i + 1)).collect();
            leaves[idx] = leaf_commitment(secret, round_id);
            let (siblings, bits) = merkle_path(&leaves, idx);
            let w = ClaimWitness { secret, round_id, seed: Fr::from(5u64), recipient: Fr::from(6u64), siblings, bits };
            let inst = w.instances();
            assert_eq!(inst[0], merkle_root(&leaves));
            run(&w, &inst).unwrap_or_else(|e| panic!("n={n} idx={idx}: {e:?}"));
        }
    }
}

#[test]
fn native_matches_light_poseidon_and_ladder() {
    use light_poseidon::{Poseidon, PoseidonHasher};
    // Circom reference vector: poseidon([1, 2]).
    let expect = "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";
    let h = hash_two(Fr::from(1u64), Fr::from(2u64));
    assert_eq!(hex::encode(fr_to_bytes_be(&h)), expect);
    // Direct comparison with light_poseidon on arbitrary inputs.
    let to_ark = |f: Fr| { use ark_ff_04::PrimeField; ark_bn254_04::Fr::from_le_bytes_mod_order(f.to_repr().as_ref()) };
    let (a, b) = (Fr::from(123456789u64) * Fr::from(987654321u64), -Fr::from(3u64));
    let mut lp = Poseidon::<ark_bn254_04::Fr>::new_circom(2).unwrap();
    let r = lp.hash(&[to_ark(a), to_ark(b)]).unwrap();
    assert_eq!(to_ark(hash_two(a, b)), r);
    // Ladder + empty tree.
    let z = zeros();
    assert_eq!(z[0], Fr::zero());
    for i in 0..DEPTH { assert_eq!(z[i + 1], hash_two(z[i], z[i])); }
    assert_eq!(merkle_root(&[]), z[DEPTH]);
    assert_eq!(merkle_root(&[Fr::zero()]), z[DEPTH]);
    // Full padding equivalence.
    let leaves: Vec<Fr> = (1..=5u64).map(Fr::from).collect();
    let mut padded = leaves.clone();
    padded.resize(NUM_LEAVES, Fr::zero());
    let mut lvl = padded;
    while lvl.len() > 1 { lvl = lvl.chunks(2).map(|c| hash_two(c[0], c[1])).collect(); }
    assert_eq!(lvl[0], merkle_root(&leaves));
    eprintln!("poseidon(1,2) BE = {expect}");
    eprintln!("zeros[DEPTH] (empty root) LE = {}", hex::encode(fr_to_bytes_le(&z[DEPTH])));
    eprintln!("root(1..=5) LE = {}", hex::encode(fr_to_bytes_le(&merkle_root(&leaves))));
}

#[test]
fn row_count() {
    // Report the actual used rows.
    let (_, w) = common::sample();
    let c = ClaimCircuit { witness: Some(w.clone()) };
    let mut cs = halo2_proofs::plonk::ConstraintSystem::<Fr>::default();
    let _ = <ClaimCircuit as halo2_proofs::plonk::Circuit<Fr>>::configure(&mut cs);
    eprintln!("blinding_factors={} minimum_rows={} usable={}", cs.blinding_factors(), cs.minimum_rows(), (1usize << K) - cs.minimum_rows());
    let _ = c;
}
