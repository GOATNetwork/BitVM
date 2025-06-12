use bitcoin::{Network, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::{
    commitments::CommitmentMessageId, connectors::connector_e::ConnectorE,
    connectors::connector_f::ConnectorF,
};

use bitvm::{
    chunk::api::{
        generate_signatures_for_any_proof,
        type_conversion_utils::{utils_raw_witnesses_from_signatures, RawProof, RawWitness},
        PublicKeys as ApiPublicKeys, NUM_HASH, NUM_PUBS, NUM_U256,
    },
    signatures::signing_winternitz::{WinternitzPublicKey, WinternitzSecret},
};

pub const MAX_CONNECTORS_E_PER_TX: usize = 100;
pub const NUM_CONNECTOR_E: usize = NUM_HASH + NUM_PUBS + NUM_U256;
pub const COMMIT_TX_NUM: usize = NUM_CONNECTOR_E.div_ceil(MAX_CONNECTORS_E_PER_TX);

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct SingleCommitConnectorsE {
    pub connectors_e: Vec<ConnectorE>,
}

impl SingleCommitConnectorsE {
    pub fn new(
        network: Network,
        operator_pubkey: &PublicKey,
        commitment_public_keys: &Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>,
    ) -> Self {
        SingleCommitConnectorsE {
            connectors_e: commitment_public_keys
                .iter()
                .map(|x| ConnectorE::new(network, operator_pubkey, x))
                .collect(),
        }
    }

    pub fn connectors_num(&self) -> usize {
        self.connectors_e.len()
    }

    pub fn get_connector_e(&self, idx: usize) -> &ConnectorE {
        &self.connectors_e[idx]
    }

    pub fn commitment_public_keys(
        &self,
    ) -> Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>> {
        self.connectors_e
            .iter()
            .map(|connector| connector.commitment_public_keys.clone())
            .collect()
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AllCommitConnectorsE {
    pub commit_connectors_e_vec: [SingleCommitConnectorsE; COMMIT_TX_NUM],
}

impl AllCommitConnectorsE {
    pub fn new(network: Network, operator_pubkey: &PublicKey, raw_pubkeys: &ApiPublicKeys) -> Self {
        let split_pubkeys_map = split_pubkeys(raw_pubkeys);
        AllCommitConnectorsE {
            commit_connectors_e_vec: split_pubkeys_map
                .iter()
                .map(|wpks| SingleCommitConnectorsE::new(network, operator_pubkey, wpks))
                .collect::<Vec<SingleCommitConnectorsE>>()
                .try_into()
                .unwrap_or_else(|_e| panic!("impossible")),
        }
    }

    pub fn connectors_num(&self) -> usize {
        self.commit_connectors_e_vec
            .iter()
            .map(|e| e.connectors_num())
            .sum()
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitConnectorsF {
    pub connectors_f: [ConnectorF; COMMIT_TX_NUM],
}

impl AssertCommitConnectorsF {
    pub fn new(network: Network, operator_public_key: &PublicKey) -> Self {
        AssertCommitConnectorsF {
            connectors_f: [ConnectorF::new(network, operator_public_key); COMMIT_TX_NUM],
        }
    }
}

pub fn sign_assert_tx_with_groth16_proof(
    commitment_secrets: &HashMap<CommitmentMessageId, WinternitzSecret>,
    proof: &RawProof,
) -> Vec<RawWitness> {
    let mut sorted_secrets: Vec<(u32, String)> = vec![];
    commitment_secrets.clone().into_iter().for_each(|(k, v)| {
        if let CommitmentMessageId::Groth16IntermediateValues((name, _)) = k {
            let index = u32::from_str_radix(&name, 10).unwrap();
            sorted_secrets.push((index, hex::encode(v.secret_key)));
        }
    });

    sorted_secrets.sort_by(|a, b| a.0.cmp(&b.0));
    let secrets = sorted_secrets.iter().map(|f| f.1.clone()).collect();

    let sigs = generate_signatures_for_any_proof(
        proof.proof.clone(),
        proof.public.clone(),
        &proof.vk,
        secrets,
    );

    utils_raw_witnesses_from_signatures(&sigs)
}

pub fn split_pubkeys(
    raw_pubkeys: &ApiPublicKeys,
) -> [Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>; COMMIT_TX_NUM] {
    let commitment_pubkeys = CommitmentMessageId::pubkey_map_for_assert(raw_pubkeys);
    let mut pubkeys_vec = vec![];
    for (message_id, pubkey) in commitment_pubkeys.iter() {
        if let CommitmentMessageId::Groth16IntermediateValues((name, _)) = message_id {
            let index = u32::from_str_radix(name, 10).unwrap();
            pubkeys_vec.push((index, (message_id, pubkey)));
        }
    }
    pubkeys_vec.sort_by(|a, b| a.0.cmp(&b.0));

    let res: Vec<Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>> = pubkeys_vec
        .chunks(MAX_CONNECTORS_E_PER_TX)
        .map(|chunk| {
            chunk
                .iter()
                .map(|&(_, (message_id, pubkey))| {
                    BTreeMap::from([(message_id.clone(), pubkey.clone())])
                })
                .collect()
        })
        .collect();

    res.try_into().unwrap_or_else(|_e| panic!("impossible"))
}

pub fn groth16_commitment_secrets_to_public_keys(
    commitment_secrets: &HashMap<CommitmentMessageId, WinternitzSecret>,
) -> [Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>; COMMIT_TX_NUM] {
    // hash map to btree map
    let commitment_secrets: BTreeMap<CommitmentMessageId, WinternitzSecret> =
        commitment_secrets.clone().into_iter().collect();

    let mut secrets_vec = vec![];
    for (message_id, secret) in commitment_secrets.iter() {
        if let CommitmentMessageId::Groth16IntermediateValues((name, _)) = message_id {
            let index = u32::from_str_radix(name, 10).unwrap();
            secrets_vec.push((index, (message_id, secret)));
        }
    }
    secrets_vec.sort_by(|a, b| a.0.cmp(&b.0));

    let res: Vec<Vec<BTreeMap<CommitmentMessageId, WinternitzPublicKey>>> = secrets_vec
        .chunks(MAX_CONNECTORS_E_PER_TX)
        .map(|chunk| {
            chunk
                .iter()
                .map(|&(_, (message_id, secret))| {
                    BTreeMap::from([(message_id.clone(), WinternitzPublicKey::from(secret))])
                })
                .collect()
        })
        .collect();

    res.try_into().unwrap_or_else(|_e| panic!("impossible"))
}

pub fn merge_to_connector_c_commits_public_key(
    connectors_e_commitment_public_keys: &[Vec<
        BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
    >],
) -> BTreeMap<CommitmentMessageId, WinternitzPublicKey> {
    let mut connector_c_commitment_public_keys = BTreeMap::new();
    for tree_vec in connectors_e_commitment_public_keys {
        for tree in tree_vec {
            for (message, pk) in tree {
                connector_c_commitment_public_keys.insert(message.clone(), pk.clone());
            }
        }
    }
    connector_c_commitment_public_keys
}

pub fn convert_to_connector_c_commits_public_key(
    raw_pubkeys: &ApiPublicKeys,
) -> BTreeMap<CommitmentMessageId, WinternitzPublicKey> {
    let commitment_pubkeys = CommitmentMessageId::pubkey_map_for_assert(raw_pubkeys);
    let mut pubkeys_vec = vec![];
    for (message_id, pubkey) in commitment_pubkeys.iter() {
        if let CommitmentMessageId::Groth16IntermediateValues((name, _)) = message_id {
            let index = u32::from_str_radix(name, 10).unwrap();
            pubkeys_vec.push((index, (message_id, pubkey)));
        }
    }
    pubkeys_vec.sort_by(|a, b| a.0.cmp(&b.0));
    let mut connector_c_commitment_public_keys = BTreeMap::new();
    for (_, (message_id, pubkey)) in pubkeys_vec {
        connector_c_commitment_public_keys.insert(message_id.clone(), pubkey.clone());
    }
    connector_c_commitment_public_keys
}
