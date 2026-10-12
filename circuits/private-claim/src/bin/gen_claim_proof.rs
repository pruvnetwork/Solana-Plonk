//! Private-claim proof tooling.
//!
//!   gen-claim-proof commitment --secret <hex32 LE> --round <u64>
//!   gen-claim-proof prove --secret <hex32 LE> --round <u64> --seed <hex32 LE> \
//!       --recipient <base58 pubkey> --leaves <file: one hex32 LE leaf per line> \
//!       --index <u> --out <dir> [--srs <file> | --insecure-srs]
//!   gen-claim-proof vk --out <file> [--srs <file> | --insecure-srs]
//!
//! SRS defaults to $HOME/Desktop/PRUV/srs/kzg_bn254_14.srs (downsized to k=10),
//! the same file code-integrity is proven with. JSON goes to stdout, logs to stderr.
use private_claim_circuit::{
    recipient_field, fr_from_le_canonical, fr_to_bytes_be, fr_to_bytes_le, generate_claim_proof, keygen,
    leaf_commitment, load_params, merkle_path, merkle_root, prover::{default_srs_path, keccak}, ClaimWitness, K,
};
use halo2curves::bn256::Fr;
use std::path::PathBuf;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}
fn req(name: &str) -> Result<String, anyhow::Error> {
    arg(name).ok_or_else(|| anyhow::anyhow!("missing {name}"))
}
fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

fn hex32(s: &str) -> Result<[u8; 32], anyhow::Error> {
    let s = s.trim().trim_start_matches("0x");
    let v = hex::decode(s)?;
    v.as_slice().try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes hex, got {} bytes", v.len()))
}
fn fr_le(s: &str, what: &str) -> Result<Fr, anyhow::Error> {
    fr_from_le_canonical(&hex32(s)?).ok_or_else(|| anyhow::anyhow!("{what} is not a canonical BN254 field element (LE)"))
}

fn srs() -> Option<String> {
    if flag("--insecure-srs") {
        eprintln!("WARNING: insecure seeded SRS (tau derivable) — tests only");
        None
    } else {
        Some(arg("--srs").unwrap_or_else(default_srs_path))
    }
}

fn fe_json(name: &str, f: &Fr) -> String {
    format!("\"{name}_be\":\"{}\",\"{name}_le\":\"{}\"", hex::encode(fr_to_bytes_be(f)), hex::encode(fr_to_bytes_le(f)))
}

fn main() -> Result<(), anyhow::Error> {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "commitment" => {
            let secret = fr_le(&req("--secret")?, "secret")?;
            let round: u64 = req("--round")?.parse()?;
            println!("{}", hex::encode(fr_to_bytes_le(&leaf_commitment(secret, round))));
            Ok(())
        }
        "vk" => {
            let out = PathBuf::from(req("--out")?);
            let srs = srs();
            let params = load_params(K, srs.as_deref())?;
            let keys = keygen(&params)?;
            if let Some(p) = out.parent() {
                if !p.as_os_str().is_empty() {
                    std::fs::create_dir_all(p)?;
                }
            }
            std::fs::write(&out, &keys.vk_bytes)?;
            println!(
                "{{\"vk_hash\":\"{}\",\"vk_len\":{},\"k\":{K},\"srs\":\"{}\",\"out\":\"{}\"}}",
                hex::encode(keccak(&keys.vk_bytes)),
                keys.vk_bytes.len(),
                srs.as_deref().unwrap_or("INSECURE"),
                out.display()
            );
            Ok(())
        }
        "prove" => prove(),
        _ => {
            eprintln!("usage: gen-claim-proof <commitment|prove|vk> … (see source header)");
            std::process::exit(2);
        }
    }
}

fn prove() -> Result<(), anyhow::Error> {
    let secret = fr_le(&req("--secret")?, "secret")?;
    let round_id: u64 = req("--round")?.parse()?;
    let seed = fr_le(&req("--seed")?, "seed")?;
    let recipient_s = req("--recipient")?;
    let recipient_bytes: [u8; 32] = bs58::decode(&recipient_s)
        .into_vec()?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("recipient must be a 32-byte base58 pubkey"))?;
    let recipient = recipient_field(&recipient_bytes);
    let index: usize = req("--index")?.parse()?;
    let out = PathBuf::from(req("--out")?);

    let leaves_txt = std::fs::read_to_string(req("--leaves")?)?;
    let leaves: Vec<Fr> = leaves_txt
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
        .map(|(i, l)| fr_le(l, &format!("leaf {i}")))
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(leaves.len() <= private_claim_circuit::NUM_LEAVES, "more than 2^DEPTH leaves");
    anyhow::ensure!(index < leaves.len(), "index {index} out of range ({} leaves)", leaves.len());
    let leaf = leaf_commitment(secret, round_id);
    anyhow::ensure!(
        leaves[index] == leaf,
        "leaves[{index}] != leaf_commitment(secret, round) = {}",
        hex::encode(fr_to_bytes_le(&leaf))
    );
    let (siblings, bits) = merkle_path(&leaves, index);
    let witness = ClaimWitness { secret, round_id, seed, recipient, siblings, bits };
    let root = merkle_root(&leaves);
    anyhow::ensure!(witness.instances()[0] == root, "path root mismatch (internal)");

    let srs = srs();
    eprintln!("[1/3] params k={K} srs={} ; keygen…", srs.as_deref().unwrap_or("INSECURE"));
    let params = load_params(K, srs.as_deref())?;
    let keys = keygen(&params)?;
    eprintln!("[2/3] prove + halo2 self-verify…");
    let p = generate_claim_proof(&params, &keys, &witness)?;
    eprintln!("[3/3] halo2_solana_verifier::verify (host)…");
    let res = halo2_solana_verifier::verify(&p.vk_bytes, &p.proof_bytes, &p.public_inputs_be, &p.kzg_vk);
    anyhow::ensure!(matches!(res, Ok(true)), "host verifier rejected: {res:?}");
    eprintln!("      ✓ host verifier accepted");

    std::fs::create_dir_all(&out)?;
    std::fs::write(out.join("golden_claim.bin"), p.golden())?;
    std::fs::write(out.join("vk.bin"), &p.vk_bytes)?;
    std::fs::write(out.join("proof.bin"), &p.proof_bytes)?;
    std::fs::write(out.join("public_inputs_be.bin"), p.public_inputs_be.concat())?;

    let golden_abs = std::fs::canonicalize(out.join("golden_claim.bin"))?;
    let i = &p.instances;
    let json = format!(
        "{{{},{},{},{},{},{},\"round_id\":{round_id},\"recipient_base58\":\"{recipient_s}\",\"leaf\":\"{}\",\"index\":{index},\"vk_hash\":\"{}\",\"proof_hash\":\"{}\",\"instance_hash\":\"{}\",\"k\":{K},\"trailing_zero_rows\":1,\"num_public_inputs\":{},\"proof_len\":{},\"vk_len\":{},\"srs\":\"{}\",\"golden\":\"{}\"}}",
        fe_json("root", &i[0]),
        fe_json("seed", &i[1]),
        fe_json("score", &i[2]),
        fe_json("nullifier", &i[3]),
        fe_json("round_id", &i[4]),
        fe_json("recipient", &i[5]),
        hex::encode(fr_to_bytes_le(&leaf)),
        hex::encode(p.vk_hash()),
        hex::encode(p.proof_hash()),
        hex::encode(p.instance_hash()),
        p.public_inputs_be.len(),
        p.proof_bytes.len(),
        p.vk_bytes.len(),
        srs.as_deref().unwrap_or("INSECURE"),
        golden_abs.display(),
    );
    std::fs::write(out.join("claim.json"), &json)?;
    println!("{json}");
    Ok(())
}
