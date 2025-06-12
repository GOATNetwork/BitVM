use bitcoin::{absolute, consensus, Amount, ScriptBuf, TapSighashType, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{
            base::*, connector_3::Connector3, connector_6::Connector6, connector_a::ConnectorA,
            connector_b::ConnectorB,
        },
        contexts::operator::OperatorContext,
    },
    base::{DUST_AMOUNT, *},
    pre_signed::*,
    signing::{generate_taproot_leaf_schnorr_signature, populate_taproot_input_witness},
};
use bitvm::signatures::signing_winternitz::{generate_winternitz_witness, WinternitzSigningInputs};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct KickOffTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for KickOffTransaction {
    fn tx(&self) -> &Transaction {
        &self.tx
    }

    fn tx_mut(&mut self) -> &mut Transaction {
        &mut self.tx
    }

    fn prev_outs(&self) -> &Vec<TxOut> {
        &self.prev_outs
    }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> {
        &self.prev_scripts
    }
}

impl KickOffTransaction {
    pub fn new(
        connector_3: &Connector3,
        connector_6: &Connector6,
        connector_a: &ConnectorA,
        connector_b: &ConnectorB,
        input_0: Input,
    ) -> Self {
        Self::new_for_validation(connector_3, connector_6, connector_a, connector_b, input_0)
    }

    pub fn new_for_validation(
        connector_3: &Connector3,
        connector_6: &Connector6,
        connector_a: &ConnectorA,
        connector_b: &ConnectorB,
        input_0: Input,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = connector_6.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(MIN_RELAY_FEE_KICK_OFF);

        let _output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_3.generate_address().script_pubkey(),
        };

        let _output_1 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
        };

        let _output_2 = TxOut {
            value: total_output_amount - _output_0.value - _output_1.value,
            script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
        };

        KickOffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0, _output_1, _output_2],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_6.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_6.generate_taproot_leaf_script(input_0_leaf)],
        }
    }

    fn sign_input_0(
        &mut self,
        context: &OperatorContext,
        connector_6: &Connector6,
        evm_txid_inputs: &WinternitzSigningInputs,
    ) {
        let input_index = 0;
        let script = &self.prev_scripts()[input_index].clone();
        let prev_outs = &self.prev_outs().clone();
        let taproot_spend_info = connector_6.generate_taproot_spend_info();
        let mut unlock_data: Vec<Vec<u8>> = Vec::new();

        // get schnorr signature
        let schnorr_signature = generate_taproot_leaf_schnorr_signature(
            self.tx_mut(),
            prev_outs,
            input_index,
            TapSighashType::All,
            script,
            &context.operator_keypair,
        );
        unlock_data.push(schnorr_signature.to_vec());

        // get winternitz signature for evm withdraw txid
        unlock_data.extend(generate_winternitz_witness(evm_txid_inputs).to_vec());

        populate_taproot_input_witness(
            self.tx_mut(),
            input_index,
            &taproot_spend_info,
            script,
            unlock_data,
        );
    }

    pub fn sign(
        &mut self,
        context: &OperatorContext,
        connector_6: &Connector6,
        evm_txid_inputs: &WinternitzSigningInputs,
    ) {
        self.sign_input_0(context, connector_6, evm_txid_inputs);
    }
}

impl BaseTransaction for KickOffTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "KickOff"
    }
}
