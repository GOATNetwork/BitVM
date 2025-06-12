use ark_bn254::Bn254;
use bitcoin::{consensus, ScriptBuf, Transaction, Txid, Wtxid};
use bitvm::chunk::api::{
    PublicKeys as Groth16WotsPublicKeys, Signatures as Groth16WotsSignatures, NUM_HASH, NUM_PUBS,
    NUM_U256,
};
use bitvm::signatures::signing_winternitz::{WinternitzPublicKey, WinternitzSecret};
use bitvm::signatures::wots_api::{wots256, wots_hash};
use bitvm::treepp::*;
use goat::commitments::NUM_KICKOFF;
use goat::proof::{deserialize_proof, deserialize_pubin, deserialize_vk};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::path::Path;

const NUM_SIGS: usize = NUM_PUBS + NUM_HASH + NUM_U256;
pub type KickoffWotsSecretKeys = [WinternitzSecret; NUM_KICKOFF];
pub type Groth16WotsSecretKeys = [String; NUM_SIGS];
pub type WotsSecretKeys = (KickoffWotsSecretKeys, Groth16WotsSecretKeys);

pub type KickoffWotsPublicKeys = [WinternitzPublicKey; NUM_KICKOFF];
pub type WotsPublicKeys = (KickoffWotsPublicKeys, Groth16WotsPublicKeys);

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct SignedTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    txid: Txid,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    wtxid: Wtxid,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
}

impl SignedTransaction {
    pub fn new(tx: Transaction) -> Self {
        SignedTransaction {
            txid: tx.compute_txid(),
            wtxid: tx.compute_wtxid(),
            tx,
        }
    }
}

pub fn write_signed_assertions_to_file(file: &str, sigs: Groth16WotsSignatures) {
    let mut sigs_map: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
    let mut index = 0;
    for ss in *sigs.0 {
        let mut v: Vec<Vec<u8>> = Vec::new();
        for (s, d) in ss {
            v.push(s.to_vec());
            v.push(vec![d]);
        }
        sigs_map.insert(index, v);
        index += 1;
    }
    for ss in *sigs.1 {
        let mut v: Vec<Vec<u8>> = Vec::new();
        for (s, d) in ss {
            v.push(s.to_vec());
            v.push(vec![d]);
        }
        sigs_map.insert(index, v);
        index += 1;
    }
    for ss in *sigs.2 {
        let mut v: Vec<Vec<u8>> = Vec::new();
        for (s, d) in ss {
            v.push(s.to_vec());
            v.push(vec![d]);
        }
        sigs_map.insert(index, v);
        index += 1;
    }
    write_map_to_file(&sigs_map, file);
}
pub fn load_signed_assertions_from_file(file: &str) -> Groth16WotsSignatures {
    let sigs_map = read_map_from_file(file).expect(&format!("fail to open {:?}", file));
    const W256_LEN: u32 = wots256::N_DIGITS * 2;
    const WHASH_LEN: u32 = wots_hash::N_DIGITS * 2;

    let mut psig = vec![];
    let (min, max) = (0, NUM_PUBS);
    for i in min..max {
        let v = sigs_map.get(&(i as u32)).unwrap();
        assert!(
            v.len() == W256_LEN as usize,
            "Invalid wots siganture length"
        );
        let mut res: Vec<([u8; 20], u8)> = Vec::new();
        let sig_len = W256_LEN / 2;
        for i in 0..sig_len {
            res.push((
                v[(2 * i) as usize].clone().try_into().unwrap(),
                v[(2 * i + 1) as usize][0],
            ));
        }
        let sig: wots256::Signature = res.try_into().unwrap();
        psig.push(sig);
    }
    let psig: [wots256::Signature; NUM_PUBS] = psig.try_into().unwrap();

    let mut fsig = vec![];
    let (min, max) = (max, max + NUM_U256);
    for i in min..max {
        let v = sigs_map.get(&(i as u32)).unwrap();
        assert!(
            v.len() == W256_LEN as usize,
            "Invalid wots siganture length"
        );
        let mut res: Vec<([u8; 20], u8)> = Vec::new();
        let sig_len = W256_LEN / 2;
        for i in 0..sig_len {
            res.push((
                v[(2 * i) as usize].clone().try_into().unwrap(),
                v[(2 * i + 1) as usize][0],
            ));
        }
        let sig: wots256::Signature = res.try_into().unwrap();
        fsig.push(sig);
    }
    let fsig: [wots256::Signature; NUM_U256] = fsig.try_into().unwrap();

    let mut hsig = vec![];
    let (min, max) = (max, max + NUM_HASH);
    for i in min..max {
        let v = sigs_map.get(&(i as u32)).unwrap();
        assert!(
            v.len() == WHASH_LEN as usize,
            "Invalid wots siganture length"
        );
        let mut res: Vec<([u8; 20], u8)> = Vec::new();
        let sig_len = WHASH_LEN / 2;
        for i in 0..sig_len {
            res.push((
                v[(2 * i) as usize].clone().try_into().unwrap(),
                v[(2 * i + 1) as usize][0],
            ));
        }
        let sig: wots_hash::Signature = res.try_into().unwrap();
        hsig.push(sig);
    }
    let hsig: [wots_hash::Signature; NUM_HASH] = hsig.try_into().unwrap();

    let res = (Box::new(psig), Box::new(fsig), Box::new(hsig));
    res
}

pub fn load_groth16_vk(file: &str) -> ark_groth16::VerifyingKey<Bn254> {
    let vk_bin = fs::read(file).expect(&format!("fail to open {:?}", file));
    deserialize_vk(vk_bin)
}
pub fn load_groth16_proof(file: &str) -> ark_groth16::Proof<Bn254> {
    let proof_bin = fs::read(file).expect(&format!("fail to open {:?}", file));
    deserialize_proof(proof_bin)
}
pub fn load_groth16_pubin(file: &str) -> Vec<ark_bn254::Fr> {
    let pubin_bin = fs::read(file).expect(&format!("fail to open {:?}", file));
    deserialize_pubin(pubin_bin)
}

pub fn write_wots_seckeys(file: &str, seckeys: WotsSecretKeys) {
    create_necessary_dir(file);
    let json = serde_json::to_vec_pretty(&(seckeys.0.to_vec(), seckeys.1.to_vec())).unwrap();
    let mut file = File::create(file).unwrap();
    file.write_all(&json).unwrap();
}
pub fn load_wots_seckeys(file: &str) -> WotsSecretKeys {
    create_necessary_dir(file);
    let file = File::open(file).expect(&format!("fail to open {:?}", file));
    let reader = BufReader::new(file);
    let seckeys_vec: (Vec<WinternitzSecret>, Vec<String>) =
        serde_json::from_reader(reader).unwrap();
    (
        seckeys_vec
            .0
            .try_into()
            .unwrap_or_else(|_e| panic!("kickoff bitcom keys number not match")),
        seckeys_vec.1.try_into().unwrap(),
    )
}

pub fn write_wots_pubkeys(file: &str, pubkeys: WotsPublicKeys) {
    let mut pubkeys_map: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
    let mut index = 0;
    // wots pk for groth16 proof
    for pk in pubkeys.1 .0 {
        let mut v: Vec<Vec<u8>> = Vec::new();
        for d in pk {
            v.push(d.to_vec());
        }
        pubkeys_map.insert(index, v);
        index += 1;
    }
    for pk in pubkeys.1 .1 {
        let mut v: Vec<Vec<u8>> = Vec::new();
        for d in pk {
            v.push(d.to_vec());
        }
        pubkeys_map.insert(index, v);
        index += 1;
    }
    for pk in pubkeys.1 .2 {
        let mut v: Vec<Vec<u8>> = Vec::new();
        for d in pk {
            v.push(d.to_vec());
        }
        pubkeys_map.insert(index, v);
        index += 1;
    }

    // wots pk for kickoff bitcommitment
    let mut v_kickoff: Vec<Vec<u8>> = Vec::new();
    for pk in pubkeys.0 {
        let pk_vec = serde_json::to_vec(&pk).unwrap();
        v_kickoff.push(pk_vec);
    }
    pubkeys_map.insert(index, v_kickoff);
    // index += 1;

    write_map_to_file(&pubkeys_map, file);
}
pub fn load_wots_pubkeys(file: &str) -> WotsPublicKeys {
    let pubkeys_map = read_map_from_file(file).expect(&format!("fail to open {:?}", file));
    const W256_LEN: u32 = wots256::N_DIGITS;
    const WHASH_LEN: u32 = wots_hash::N_DIGITS;

    let mut pk0 = vec![];
    let (min, max) = (0, NUM_PUBS);
    for i in min..max {
        let v = pubkeys_map.get(&(i as u32)).unwrap();
        assert!(
            v.len() == W256_LEN as usize,
            "Invalid wots public-key length"
        );
        let mut res: Vec<[u8; 20]> = Vec::new();
        for i in 0..W256_LEN {
            res.push(v[i as usize].clone().try_into().unwrap());
        }
        let sig: wots256::PublicKey = res.try_into().unwrap();
        pk0.push(sig);
    }
    let pk0: [wots256::PublicKey; NUM_PUBS] = pk0.try_into().unwrap();

    let mut pk1 = vec![];
    let (min, max) = (max, max + NUM_U256);
    for i in min..max {
        let v = pubkeys_map.get(&(i as u32)).unwrap();
        assert!(
            v.len() == W256_LEN as usize,
            "Invalid wots public-key length"
        );
        let mut res: Vec<[u8; 20]> = Vec::new();
        for i in 0..W256_LEN {
            res.push(v[i as usize].clone().try_into().unwrap());
        }
        let sig: wots256::PublicKey = res.try_into().unwrap();
        pk1.push(sig);
    }
    let pk1: [wots256::PublicKey; NUM_U256] = pk1.try_into().unwrap();

    let mut pk2 = vec![];
    let (min, max) = (max, max + NUM_HASH);
    for i in min..max {
        let v = pubkeys_map.get(&(i as u32)).unwrap();
        assert!(
            v.len() == WHASH_LEN as usize,
            "Invalid wots public-key length"
        );
        let mut res: Vec<[u8; 20]> = Vec::new();
        for i in 0..WHASH_LEN {
            res.push(v[i as usize].clone().try_into().unwrap());
        }
        let sig: wots_hash::PublicKey = res.try_into().unwrap();
        pk2.push(sig);
    }
    let pk2: [wots_hash::PublicKey; NUM_HASH] = pk2.try_into().unwrap();

    let mut pk_kickoff: Vec<WinternitzPublicKey> = vec![];
    let (min, max) = (max, max + NUM_KICKOFF);
    for i in min..max {
        let v = pubkeys_map.get(&(i as u32)).unwrap();
        assert!(
            v.len() == NUM_KICKOFF,
            "Invalid kickoff wots public-key number"
        );
        for i in 0..NUM_KICKOFF {
            pk_kickoff.push(serde_json::from_slice(&v[i as usize].clone()).unwrap());
        }
    }
    let pk_kickoff: [WinternitzPublicKey; NUM_KICKOFF] = pk_kickoff
        .try_into()
        .unwrap_or_else(|_e| panic!("kickoff bitcom keys number not match"));

    let res = (pk_kickoff, (pk0, pk1, pk2));
    res
}

pub fn write_scripts_to_file(file: &str, scripts: Vec<Script>) {
    create_necessary_dir(file);
    let scripts_bytes: Vec<Vec<u8>> = scripts
        .into_iter()
        .map(|x| x.compile().to_bytes())
        .collect();
    let json = serde_json::to_vec_pretty(&scripts_bytes).unwrap();
    let mut file = File::create(file).unwrap();
    file.write_all(&json).unwrap();
}
pub fn load_scripts_from_file(file: &str) -> Vec<Script> {
    let scripts_bytes = load_scripts_bytes_from_file(file);
    scripts_bytes
        .into_iter()
        .map(|x| {
            let sc = script! {};
            let bf = ScriptBuf::from_bytes(x);
            let sc = sc.push_script(bf);
            sc
        })
        .collect()
}
pub fn load_scripts_bytes_from_file(file: &str) -> Vec<Vec<u8>> {
    let file = File::open(file).expect(&format!("fail to open {:?}", file));
    let reader = BufReader::new(file);
    let scripts_bytes: Vec<Vec<u8>> = serde_json::from_reader(reader).unwrap();
    scripts_bytes
}

pub fn write_disprove_witness(file: &str, index: usize, witness: Script) {
    create_necessary_dir(file);
    let witness_bytes = witness.compile().to_bytes();
    let json = serde_json::to_vec_pretty(&(index, witness_bytes)).unwrap();
    let mut file = File::create(file).unwrap();
    file.write_all(&json).unwrap();
}
pub fn load_disprove_witness(file: &str) -> (usize, Script) {
    let file = File::open(file).expect(&format!("fail to open {:?}", file));
    let reader = BufReader::new(file);
    let (index, witness_bytes): (usize, Vec<u8>) = serde_json::from_reader(reader).unwrap();
    let sc = script! {};
    let bf = ScriptBuf::from_bytes(witness_bytes);
    let sc = sc.push_script(bf);
    (index, sc)
}

pub(crate) fn file_exists(file: &str) -> bool {
    Path::new(file).exists()
}

pub(crate) fn create_necessary_dir(path: &str) {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).unwrap();
    };
}

pub(crate) fn write_bytes_to_file(data: &Vec<u8>, file: &str) {
    create_necessary_dir(&file);
    let mut file = File::create(file).unwrap();
    file.write_all(&data).unwrap();
}

fn write_map_to_file(map: &HashMap<u32, Vec<Vec<u8>>>, file: &str) {
    create_necessary_dir(file);
    let json = serde_json::to_vec_pretty(map).unwrap();
    let mut file = File::create(file).unwrap();
    file.write_all(&json).unwrap();
}
fn read_map_from_file(file: &str) -> Result<HashMap<u32, Vec<Vec<u8>>>, String> {
    let file = File::open(file).expect(&format!("fail to open {:?}", file));
    let reader = BufReader::new(file);
    let map = serde_json::from_reader(reader).unwrap();
    Ok(map)
}
