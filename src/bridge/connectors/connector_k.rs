use bitcoin::{
    key::Secp256k1, opcodes::OP_TRUE, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, PublicKey as B_PublicKey, ScriptBuf, TxIn, Witness, XOnlyPublicKey
};
use crate::bridge::{commitment, graphs::base::CALC_ROUND};
use crate::bridge::hash_chain;
use crate::signatures::winternitz::{self, PublicKey as W_PublicKey};
use super::{
    super::{scripts::*, transactions::base::Input},
    connector::*,
};
use crate::treepp::*;

pub struct ConnectorK {
    pub network: Network,
    pub operator_public_key: B_PublicKey,
    pub operator_commitment_key: W_PublicKey,
    pub operator_taproot_public_key: XOnlyPublicKey,
}

impl ConnectorK {
    pub fn new(
        network: Network, 
        operator_public_key: &B_PublicKey, 
        operator_commitment_key: &W_PublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
    ) -> Self {
        ConnectorK {
            network,
            operator_public_key: operator_public_key.clone(),
            operator_commitment_key: operator_commitment_key.clone(),
            operator_taproot_public_key: operator_taproot_public_key.clone(),
        }
    }

    pub fn generate_taproot_leaf0_lock_script(&self) -> ScriptBuf {
        script! {
            // OP_TRUE
            { hash_chain::commitment_script_lock(&self.operator_commitment_key, CALC_ROUND) }
        }
        .compile()
    }

    pub fn generate_taproot_leaf0_unlock_script(&self, operator_commitment_seckey: &[u8; 20], statement: &[u8]) -> ScriptBuf {
        let round = CALC_ROUND;
        let sig_script = hash_chain::sign_result(operator_commitment_seckey, statement, round);
        let stack_script = hash_chain::push_stack_script(statement, round);
        script! {
            { hash_chain::commitment_script_unlock(sig_script, stack_script, round) }
        }
        .compile()
    }

    pub fn push_leaf0_unlock_witness(&self, witness: &mut Witness, operator_commitment_seckey: &[u8; 20], statement: &[u8]) {
        let round = CALC_ROUND;
        witness.push([0x1]);
        hash_chain::push_commitment_unlock_witness(witness, operator_commitment_seckey, statement, round)
    }

    fn generate_taproot_leaf0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }
}

impl TaprootConnector for ConnectorK {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf0_lock_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf0_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.generate_taproot_leaf0_lock_script())
            .expect("Unable to add leaf0")
            .finalize(&Secp256k1::new(), self.operator_taproot_public_key) 
            .expect("Unable to finalize ttaproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}


// standard P2wsh have a size linmit of 10k
// impl ConnectorK {
//     pub fn new(
//         network: Network, 
//         operator_public_key: &B_PublicKey, 
//         operator_commitment_key: &W_PublicKey,
//     ) -> Self {
//         ConnectorK {
//             network,
//             operator_public_key: operator_public_key.clone(),
//             operator_commitment_key: operator_commitment_key.clone(),
//         }
//     }

//     pub fn generate_unlock_script(&self, operator_commitment_seckey: &[u8; 20], statement: &[u8]) -> ScriptBuf {
//         let round = CALC_ROUND;
//         let sig_script = hash_chain::sign_result(operator_commitment_seckey, statement, round);
//         let stack_script = hash_chain::push_stack_script(statement, round);
//         script! {
//             { hash_chain::commitment_script_unlock(sig_script, stack_script, round) }
//         }
//         .compile()
//     }

//     pub fn generate_lock_script(&self) -> ScriptBuf {
//         script! {
//             { hash_chain::commitment_script_lock(&self.operator_commitment_key, CALC_ROUND) }
//             // { self.operator_public_key.clone() }
//             // OP_CHECKSIG
//         }
//         .compile()
//     }
// }

// impl P2wshConnector for ConnectorK {
//     fn generate_script(&self) -> ScriptBuf {
//         self.generate_lock_script()
//     }

//     fn generate_address(&self) -> Address {
//         Address::p2wsh(&self.generate_script(), self.network)
//     }

//     fn generate_tx_in(&self, input: &Input) -> TxIn { generate_default_tx_in(input) }
// }