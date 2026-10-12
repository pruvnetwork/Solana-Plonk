//! Prover pipeline: SHPLONK + Keccak-BE transcript (what the on-chain verifier
//! reads). Same SRS loading as code-integrity: a BN254 powers-of-tau file
//! readable by `ParamsKZG::read`, downsized to `K`.

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine, G2Affine};
use rand::rngs::{OsRng, StdRng};
use rand_core::SeedableRng;

use halo2_solana_verifier::kzg::KzgVk;
use halo2_solana_vk_host::{compile_vk, encode::g1_affine_to_bytes_be};
use standard_plonk_circuit::keccak_be_transcript::{KeccakBeRead, KeccakBeWrite};

use crate::{circuit::ClaimCircuit, fr_to_bytes_be, ClaimWitness, NUM_INSTANCES};

/// Circuit size: 13 Poseidon permutations × 66 rows + 10 swap rows + 1 recipient row = 869 rows.
pub const K: u32 = 10;

/// Default SRS (same file code-integrity's goldens are produced with), relative to $HOME.
pub const DEFAULT_SRS: &str = "Desktop/PRUV/srs/kzg_bn254_14.srs";

pub fn default_srs_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/{DEFAULT_SRS}")
}

/// `srs_path = None` → INSECURE seeded setup (tests only; tau is derivable from the seed).
pub fn load_params(k: u32, srs_path: Option<&str>) -> Result<ParamsKZG<Bn256>, anyhow::Error> {
    Ok(match srs_path {
        Some(p) => {
            let f = std::fs::File::open(p).map_err(|e| anyhow::anyhow!("open SRS {p}: {e}"))?;
            let mut r = std::io::BufReader::new(f);
            let mut params = ParamsKZG::<Bn256>::read(&mut r).map_err(|e| anyhow::anyhow!("read SRS: {e}"))?;
            anyhow::ensure!(params.k() >= k, "SRS k={} < circuit k={k}", params.k());
            if params.k() > k {
                params.downsize(k);
            }
            params
        }
        None => ParamsKZG::<Bn256>::setup(k, &mut StdRng::from_seed([7u8; 32])),
    })
}

pub struct Keys {
    pub vk: VerifyingKey<G1Affine>,
    pub pk: ProvingKey<G1Affine>,
    /// Flat on-chain VK bytes (`compile_vk`); `vk_hash = keccak256(vk_bytes)`.
    pub vk_bytes: Vec<u8>,
}

pub fn keygen(params: &ParamsKZG<Bn256>) -> Result<Keys, anyhow::Error> {
    let circuit = ClaimCircuit::default();
    let vk = keygen_vk(params, &circuit).map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk = keygen_pk(params, vk.clone(), &circuit).map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;
    let vk_bytes = compile_vk(params, &vk).map_err(|e| anyhow::anyhow!("compile_vk: {e:?}"))?;
    Ok(Keys { vk, pk, vk_bytes })
}

pub fn kzg_vk(params: &ParamsKZG<Bn256>) -> KzgVk {
    KzgVk {
        g1_one: halo2_solana_verifier::curve::G1(g1_affine_to_bytes_be(&params.get_g()[0])),
        g2_one: halo2_solana_verifier::curve::G2(g2_affine_to_bytes_be(&params.g2())),
        g2_tau: halo2_solana_verifier::curve::G2(g2_affine_to_bytes_be(&params.s_g2())),
    }
}

pub struct ClaimProof {
    pub vk_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub kzg_vk: KzgVk,
    pub instances: [Fr; NUM_INSTANCES],
    /// Big-endian 32-byte encodings in instance-row order (what the verifier hashes).
    pub public_inputs_be: Vec<[u8; 32]>,
}

pub fn keccak(b: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(b).into()
}

impl ClaimProof {
    pub fn vk_hash(&self) -> [u8; 32] {
        keccak(&self.vk_bytes)
    }
    pub fn proof_hash(&self) -> [u8; 32] {
        keccak(&self.proof_bytes)
    }
    /// keccak256(pi_0_be ‖ … ‖ pi_6_be) — `compute_replay_hashes`' instance_hash.
    pub fn instance_hash(&self) -> [u8; 32] {
        keccak(&self.public_inputs_be.concat())
    }
    /// GLDN0002 blob (what `devnet-send --golden` and the Mollusk benches load).
    pub fn golden(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"GLDN0002");
        buf.extend_from_slice(&(self.vk_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.vk_bytes);
        buf.extend_from_slice(&(self.proof_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.proof_bytes);
        buf.extend_from_slice(&self.kzg_vk.g1_one.0);
        buf.extend_from_slice(&self.kzg_vk.g2_one.0);
        buf.extend_from_slice(&self.kzg_vk.g2_tau.0);
        buf.extend_from_slice(&(self.public_inputs_be.len() as u32).to_le_bytes());
        for pi in &self.public_inputs_be {
            buf.extend_from_slice(pi);
        }
        buf
    }
}

/// Keygen + prove + halo2 self-verify. Proof randomness is from OsRng (the VK is deterministic).
pub fn generate_claim_proof(params: &ParamsKZG<Bn256>, keys: &Keys, witness: &ClaimWitness) -> Result<ClaimProof, anyhow::Error> {
    let instances = witness.instances();
    let circuit = ClaimCircuit { witness: Some(witness.clone()) };
    let instance_col: Vec<Fr> = instances.to_vec();

    let mut proof_bytes: Vec<u8> = Vec::new();
    {
        let mut transcript: KeccakBeWrite<&mut Vec<u8>, _, _> = KeccakBeWrite::init(&mut proof_bytes);
        let inst: &[&[Fr]] = &[&instance_col];
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
            params, &keys.pk, &[circuit], &[inst], OsRng, &mut transcript,
        )
        .map_err(|e| anyhow::anyhow!("create_proof: {e:?}"))?;
        let _: &mut Vec<u8> = transcript.finalize();
    }
    {
        let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
        let mut tr: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof_bytes.as_slice());
        let inst: &[&[Fr]] = &[&instance_col];
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &pv, &keys.vk, SingleStrategy::new(&pv), &[inst], &mut tr,
        )
        .map_err(|e| anyhow::anyhow!("halo2 self-verify: {e:?}"))?;
    }

    Ok(ClaimProof {
        vk_bytes: keys.vk_bytes.clone(),
        proof_bytes,
        kzg_vk: kzg_vk(params),
        instances,
        public_inputs_be: instance_col.iter().map(fr_to_bytes_be).collect(),
    })
}

fn g2_affine_to_bytes_be(p: &G2Affine) -> [u8; 128] {
    use halo2curves::ff::PrimeField;
    use halo2curves::group::prime::PrimeCurveAffine;
    let mut out = [0u8; 128];
    if bool::from(p.is_identity()) {
        return out;
    }
    let mut x1 = p.x.c1.to_repr();
    x1.as_mut().reverse();
    let mut x0 = p.x.c0.to_repr();
    x0.as_mut().reverse();
    let mut y1 = p.y.c1.to_repr();
    y1.as_mut().reverse();
    let mut y0 = p.y.c0.to_repr();
    y0.as_mut().reverse();
    out[..32].copy_from_slice(x1.as_ref());
    out[32..64].copy_from_slice(x0.as_ref());
    out[64..96].copy_from_slice(y1.as_ref());
    out[96..].copy_from_slice(y0.as_ref());
    out
}
