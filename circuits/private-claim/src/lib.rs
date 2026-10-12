//! Sealed-score private lottery claim circuit for native on-chain verification.
//!
//! Public inputs (one instance column, rows in this order):
//!   0 root       Poseidon Merkle root (DEPTH = 10, 1024 leaves)
//!   1 seed       draw seed
//!   2 score      = H(secret, seed)
//!   3 nullifier  = H(secret, leaf)
//!   4 round_id   u64 as a field element
//!   5 recipient  keccak256(payout pubkey), little-endian, byte 31 cleared — see `recipient_field`
//!                (hashing binds all 32 pubkey bytes; masking the raw key would let a front-runner
//!                swap byte 31 and redirect the payout)
//!   6 zero       constant 0 every Poseidon capacity lane is pinned to
//!
//! Private witness: secret, DEPTH index bits (LSB first), DEPTH siblings.
//!
//! Constraints:
//!   leaf = H(secret, round_id)
//!   cur = leaf; for i in 0..DEPTH: cur = bit_i ? H(sib_i, cur) : H(cur, sib_i); cur == root
//!   score = H(secret, seed); nullifier = H(secret, leaf)
//!   recipient copied into a gate (r^2 witnessed and checked).
//!
//! `H` = width-3 Circom Poseidon (`light_poseidon::Poseidon::new_circom(2)`,
//! identical to `sol_poseidon(Parameters::Bn254X5, LittleEndian, [a, b])`).

pub mod circuit;
pub mod prover;

pub use code_integrity_circuit::{field_from_le_bytes, fr_to_bytes_le, poseidon::hash_two};
pub use prover::{generate_claim_proof, keygen, load_params, ClaimProof, DEFAULT_SRS, K};

use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;

pub const DEPTH: usize = 10;
pub const NUM_LEAVES: usize = 1 << DEPTH;
/// Number of instance rows (6 public values + trailing zero).
pub const NUM_INSTANCES: usize = 7;

/// `zeros[0] = 0`, `zeros[i+1] = H(zeros[i], zeros[i])`; `zeros[DEPTH]` is the empty root.
pub fn zeros() -> [Fr; DEPTH + 1] {
    let mut z = [Fr::zero(); DEPTH + 1];
    for i in 0..DEPTH {
        z[i + 1] = hash_two(z[i], z[i]);
    }
    z
}

pub fn leaf_commitment(secret: Fr, round_id: u64) -> Fr {
    hash_two(secret, Fr::from(round_id))
}
pub fn score(secret: Fr, seed: Fr) -> Fr {
    hash_two(secret, seed)
}
pub fn nullifier(secret: Fr, leaf: Fr) -> Fr {
    hash_two(secret, leaf)
}

/// All tree levels: `levels[0]` = leaves (unpadded), `levels[DEPTH]` = [root].
/// Missing right-hand nodes at level i are `zeros[i]`, which equals padding the
/// leaves with zeros to 2^DEPTH.
fn levels(leaves: &[Fr]) -> Vec<Vec<Fr>> {
    assert!(leaves.len() <= NUM_LEAVES, "more than 2^DEPTH leaves");
    let z = zeros();
    let mut out = vec![leaves.to_vec()];
    for i in 0..DEPTH {
        let cur = &out[i];
        let n = (cur.len() + 1) / 2;
        let next: Vec<Fr> = (0..n)
            .map(|j| {
                let l = cur[2 * j];
                let r = cur.get(2 * j + 1).copied().unwrap_or(z[i]);
                hash_two(l, r)
            })
            .collect();
        out.push(next);
    }
    out
}

pub fn merkle_root(leaves: &[Fr]) -> Fr {
    levels(leaves)[DEPTH].first().copied().unwrap_or(zeros()[DEPTH])
}

/// Siblings bottom-up and index bits LSB-first (bit_i = 1 ⇔ current node is a right child).
pub fn merkle_path(leaves: &[Fr], index: usize) -> ([Fr; DEPTH], [bool; DEPTH]) {
    assert!(index < leaves.len(), "index out of range");
    let z = zeros();
    let lv = levels(leaves);
    let mut sibs = [Fr::zero(); DEPTH];
    let mut bits = [false; DEPTH];
    let mut idx = index;
    for i in 0..DEPTH {
        bits[i] = idx & 1 == 1;
        sibs[i] = lv[i].get(idx ^ 1).copied().unwrap_or(z[i]);
        idx >>= 1;
    }
    (sibs, bits)
}

/// Recompute the root from a leaf and a path (native mirror of the circuit).
pub fn root_from_path(leaf: Fr, sibs: &[Fr; DEPTH], bits: &[bool; DEPTH]) -> Fr {
    let mut cur = leaf;
    for i in 0..DEPTH {
        cur = if bits[i] { hash_two(sibs[i], cur) } else { hash_two(cur, sibs[i]) };
    }
    cur
}

/// Everything the prover needs.
#[derive(Clone, Debug)]
pub struct ClaimWitness {
    pub secret: Fr,
    pub round_id: u64,
    pub seed: Fr,
    pub recipient: Fr,
    pub siblings: [Fr; DEPTH],
    pub bits: [bool; DEPTH],
}

impl ClaimWitness {
    pub fn leaf(&self) -> Fr {
        leaf_commitment(self.secret, self.round_id)
    }
    /// Instance column in row order: root, seed, score, nullifier, round_id, recipient, 0.
    pub fn instances(&self) -> [Fr; NUM_INSTANCES] {
        let leaf = self.leaf();
        [
            root_from_path(leaf, &self.siblings, &self.bits),
            self.seed,
            score(self.secret, self.seed),
            nullifier(self.secret, leaf),
            Fr::from(self.round_id),
            self.recipient,
            Fr::zero(),
        ]
    }
}

/// Canonical LE 32 bytes → Fr (rejects values ≥ r).
pub fn fr_from_le_canonical(b: &[u8; 32]) -> Option<Fr> {
    Option::from(Fr::from_repr(*b))
}

/// 32-byte big-endian encoding (what the verifier's instance hash is computed over).
pub fn fr_to_bytes_be(f: &Fr) -> [u8; 32] {
    let mut b = fr_to_bytes_le(f);
    b.reverse();
    b
}

/// Public-input encoding of a payout address: keccak256(pubkey) read little-endian with
/// byte 31 cleared. The on-chain program recomputes it the same way.
pub fn recipient_field(pubkey: &[u8; 32]) -> Fr {
    use sha3::{Digest, Keccak256};
    let h: [u8; 32] = Keccak256::digest(pubkey).into();
    field_from_le_bytes(&h)
}
