use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

use code_integrity_circuit::poseidon::{PoseidonChip, PoseidonConfig};

use crate::{ClaimWitness, DEPTH};

/// Instance rows.
pub const ROW_ROOT: usize = 0;
pub const ROW_SEED: usize = 1;
pub const ROW_SCORE: usize = 2;
pub const ROW_NULLIFIER: usize = 3;
pub const ROW_ROUND: usize = 4;
pub const ROW_RECIPIENT: usize = 5;
pub const ROW_ZERO: usize = 6;

/// Reuses the Poseidon chip's 3 state + 3 S-box advice columns; the two extra
/// gates only add selectors.
#[derive(Clone, Debug)]
pub struct ClaimConfig {
    pub instance: Column<Instance>,
    pub poseidon: PoseidonConfig,
    /// Merkle conditional swap. Row r: state = [cur, sib, bit]; row r+1 is the
    /// first row of the level's permutation, state = [0, left, right].
    pub q_swap: Selector,
    /// Recipient binding: state[0] = recipient, state[1] = recipient².
    pub q_sq: Selector,
}

#[derive(Clone, Default)]
pub struct ClaimCircuit {
    pub witness: Option<ClaimWitness>,
}

type Cell = AssignedCell<Fr, Fr>;

impl Circuit<Fr> for ClaimCircuit {
    type Config = ClaimConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { witness: None }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let poseidon = PoseidonChip::configure(meta);
        let q_swap = meta.selector();
        let q_sq = meta.selector();
        let st = poseidon.state;

        meta.create_gate("merkle_swap", |meta| {
            let q = meta.query_selector(q_swap);
            let cur = meta.query_advice(st[0], Rotation::cur());
            let sib = meta.query_advice(st[1], Rotation::cur());
            let bit = meta.query_advice(st[2], Rotation::cur());
            let left = meta.query_advice(st[1], Rotation::next());
            let right = meta.query_advice(st[2], Rotation::next());
            let one = Expression::Constant(Fr::one());
            vec![
                // bit ∈ {0,1}
                q.clone() * bit.clone() * (one - bit.clone()),
                // left = cur + bit·(sib − cur)
                q.clone() * (left - cur.clone() - bit.clone() * (sib.clone() - cur.clone())),
                // right = sib + bit·(cur − sib)
                q * (right - sib.clone() - bit * (cur - sib)),
            ]
        });

        meta.create_gate("recipient_square", |meta| {
            let q = meta.query_selector(q_sq);
            let r = meta.query_advice(st[0], Rotation::cur());
            let r2 = meta.query_advice(st[1], Rotation::cur());
            vec![q * (r2 - r.clone() * r)]
        });

        ClaimConfig { instance, poseidon, q_swap, q_sq }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let w = self.witness.as_ref();
        let kv = |f: Option<Fr>| f.map(Value::known).unwrap_or(Value::unknown());
        let secret_v = kv(w.map(|w| w.secret));
        let round_v = kv(w.map(|w| Fr::from(w.round_id)));
        let seed_v = kv(w.map(|w| w.seed));
        let recip_v = kv(w.map(|w| w.recipient));

        let chip = PoseidonChip::new(config.poseidon.clone());
        let st = config.poseidon.state;
        let mut caps: Vec<Cell> = Vec::new();

        // leaf = H(secret, round_id)
        let (cap, secret_cell, round_cell, leaf) =
            layouter.assign_region(|| "leaf", |mut region| chip.assign_permutation(&mut region, 0, secret_v, round_v))?;
        caps.push(cap);
        let leaf_v = leaf.value().copied();

        // score = H(secret, seed)
        let (cap, seed_cell, score_cell) = layouter.assign_region(
            || "score",
            |mut region| {
                let (cap, a, b, out) = chip.assign_permutation(&mut region, 0, secret_v, seed_v)?;
                region.constrain_equal(secret_cell.cell(), a.cell())?;
                Ok((cap, b, out))
            },
        )?;
        caps.push(cap);

        // nullifier = H(secret, leaf)
        let (cap, null_cell) = layouter.assign_region(
            || "nullifier",
            |mut region| {
                let (cap, a, b, out) = chip.assign_permutation(&mut region, 0, secret_v, leaf_v)?;
                region.constrain_equal(secret_cell.cell(), a.cell())?;
                region.constrain_equal(leaf.cell(), b.cell())?;
                Ok((cap, out))
            },
        )?;
        caps.push(cap);

        // Merkle path.
        let mut cur = leaf.clone();
        for i in 0..DEPTH {
            let sib_v = kv(w.map(|w| w.siblings[i]));
            let bit_b = w.map(|w| w.bits[i]);
            let bit_v = kv(bit_b.map(|b| if b { Fr::one() } else { Fr::zero() }));
            let cur_v = cur.value().copied();
            let (left_v, right_v) = match bit_b {
                Some(b) => {
                    let (l, r) = (cur_v, sib_v);
                    if b { (r, l) } else { (l, r) }
                }
                None => (Value::unknown(), Value::unknown()),
            };
            let (cap, out) = layouter.assign_region(
                || format!("merkle-{i}"),
                |mut region| {
                    config.q_swap.enable(&mut region, 0)?;
                    let c = region.assign_advice(|| "cur", st[0], 0, || cur_v)?;
                    region.constrain_equal(cur.cell(), c.cell())?;
                    region.assign_advice(|| "sib", st[1], 0, || sib_v)?;
                    region.assign_advice(|| "bit", st[2], 0, || bit_v)?;
                    let (cap, _l, _r, out) = chip.assign_permutation(&mut region, 1, left_v, right_v)?;
                    Ok((cap, out))
                },
            )?;
            caps.push(cap);
            cur = out;
        }

        // Recipient binding.
        let recip_cell = layouter.assign_region(
            || "recipient",
            |mut region| {
                config.q_sq.enable(&mut region, 0)?;
                let r = region.assign_advice(|| "recipient", st[0], 0, || recip_v)?;
                region.assign_advice(|| "recipient^2", st[1], 0, || recip_v.map(|r| r * r))?;
                Ok(r)
            },
        )?;

        let inst = config.instance;
        layouter.constrain_instance(cur.cell(), inst, crate::circuit::ROW_ROOT)?;
        layouter.constrain_instance(seed_cell.cell(), inst, ROW_SEED)?;
        layouter.constrain_instance(score_cell.cell(), inst, ROW_SCORE)?;
        layouter.constrain_instance(null_cell.cell(), inst, ROW_NULLIFIER)?;
        layouter.constrain_instance(round_cell.cell(), inst, ROW_ROUND)?;
        layouter.constrain_instance(recip_cell.cell(), inst, ROW_RECIPIENT)?;
        for c in &caps {
            layouter.constrain_instance(c.cell(), inst, ROW_ZERO)?;
        }
        Ok(())
    }
}
