use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use bitvm::signatures::{signing_winternitz::WinternitzPublicKey, WinternitzSecret, Wots, Wots32};
use bitvm::treepp::*;
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use crate::{constants::CONNECTOR_G_TIMELOCK, utils::num_blocks_per_network};

use super::{
    super::{error::Error, scripts::*, transactions::base::Input},
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorG {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub blockhash_wots_pubkey: WinternitzPublicKey,
    pub operator_commit_blocks_timelock: u32,
}

impl ConnectorG {
    pub fn new(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        blockhash_wots_pubkey: &<Wots32 as Wots>::PublicKey,
    ) -> Self {
        let blockhash_wots_pubkey = WinternitzPublicKey {
            public_key: blockhash_wots_pubkey.to_vec(),
            parameters: <Wots32 as Wots>::PARAMETERS,
        };
        ConnectorG {
            network,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            operator_taproot_public_key: *operator_taproot_public_key,
            blockhash_wots_pubkey,
            operator_commit_blocks_timelock: num_blocks_per_network(network, CONNECTOR_G_TIMELOCK),
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        let blockhash_wots_pubkey: <Wots32 as Wots>::PublicKey = self
            .blockhash_wots_pubkey
            .public_key
            .as_slice()
            .try_into()
            .unwrap();
        script! {
            { Wots32::checksig_verify_and_clear_stack(&blockhash_wots_pubkey) }
            OP_TRUE
        }
        .compile()
    }

    pub fn generate_leaf_0_unlock_data(
        &self,
        wots_secret_key: &WinternitzSecret,
        latest_blockhash: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>, Error> {
        let witness = Wots32::sign_to_raw_witness(wots_secret_key, latest_blockhash);
        let witness_script = script! {
            { witness.clone() }
        };
        let verification_script = witness_script.push_script(self.generate_taproot_leaf_0_script());
        let exec_result = execute_script(verification_script);
        match exec_result.success {
            true => Ok(witness.to_vec()),
            false => Err(Error::Other("Invalid WOTS secret-key for Connector G.")),
        }
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        generate_timelock_taproot_script(
            &self.n_of_n_taproot_public_key,
            self.operator_commit_blocks_timelock,
        )
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.operator_commit_blocks_timelock)
    }
}

impl TaprootConnector for ConnectorG {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            1 => self.generate_taproot_leaf_1_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            1 => self.generate_taproot_leaf_1_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .add_leaf(1, self.generate_taproot_leaf_1_script())
            .expect("Unable to add leaf 1")
            .finalize(SECP256K1, self.n_of_n_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}

#[test]
fn test_connector_g_leaf_0() {
    let secp = &SECP256K1;
    let mut rng = rand::thread_rng();
    let kp = bitcoin::key::Keypair::new(secp, &mut rng);
    let (xonly_pk, _) = XOnlyPublicKey::from_keypair(&kp);

    let wots_privkey = Wots32::generate_secret_key();
    let wots_pubkey = Wots32::generate_public_key(&wots_privkey);
    let latest_blockhash = [1u8; 32];

    let connector_g = ConnectorG::new(Network::Regtest, &xonly_pk, &xonly_pk, &wots_pubkey);

    let unlock_data = connector_g
        .generate_leaf_0_unlock_data(&wots_privkey, &latest_blockhash)
        .unwrap();

    let verification_script = script! {
        { unlock_data }
    }
    .push_script(connector_g.generate_taproot_leaf_0_script());
    let exec_result = execute_script(verification_script);
    assert!(exec_result.success);
}
