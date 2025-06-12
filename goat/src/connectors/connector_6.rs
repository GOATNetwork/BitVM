use std::collections::HashMap;

use crate::{
    commitments::CommitmentMessageId, constants::EVM_TXID_LENGTH, transactions::base::Input,
};

use bitvm::{
    signatures::signing_winternitz::{winternitz_message_checksig_verify, WinternitzPublicKey},
    treepp::script,
};

use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};

use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use super::base::{generate_default_tx_in, TaprootConnector};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Connector6 {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub commitment_public_keys: HashMap<CommitmentMessageId, WinternitzPublicKey>,
}

impl Connector6 {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
    ) -> Self {
        Connector6 {
            network,
            operator_taproot_public_key: *operator_taproot_public_key,
            commitment_public_keys: commitment_public_keys.clone(),
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        let evm_withdraw_txid_pubkey =
            &self.commitment_public_keys[&CommitmentMessageId::EvmWithdrawTxid];
        script! {
            { winternitz_message_checksig_verify(evm_withdraw_txid_pubkey, EVM_TXID_LENGTH * 2) }
            { self.operator_taproot_public_key }
            OP_CHECKSIG
        }
        .compile()
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }
}

impl TaprootConnector for Connector6 {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .finalize(SECP256K1, self.operator_taproot_public_key) // TODO: should be operator key?
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
