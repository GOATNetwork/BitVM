use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use serde::{Deserialize, Serialize};
use crate::treepp::*;
use crate::bridge::{connectors::connector_k, hash_chain};

use super::{
    super::{
        connectors::{
            connector::*, connector_1::Connector1, connector_a::ConnectorA, connector_b::ConnectorB, connector_k::ConnectorK
        },
        contexts::operator::OperatorContext,
        graphs::base::{DUST_AMOUNT, FEE_AMOUNT},
        scripts::*,
    },
    base::*,
    pre_signed::*,
};



#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct KickOffTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for KickOffTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl KickOffTransaction {
    pub fn new(context: &OperatorContext, input0: Input, compressed_statement: &[u8]) -> Self {
        let connector_1 = Connector1::new(context.network, &context.operator_public_key);
        let connector_a = ConnectorA::new(
            context.network,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
        );
        let connector_b = ConnectorB::new(context.network, &context.n_of_n_taproot_public_key);
        let connector_k = ConnectorK::new(context.network, &context.operator_public_key, &context.operator_commitment_pubkey);

        let _input0 = connector_k.generate_tx_in(&input0);

        let available_input_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_1.generate_address().script_pubkey(),
        };

        let _output1 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
        };

        let _output2 = TxOut {
            value: available_input_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
        };

        let statement = &compressed_statement[1..];
        let round = compressed_statement[0];
        let sig_script = hash_chain::sign_result(&context.operator_commitment_seckey, statement, round as u32);
        let stack_script = hash_chain::push_stack_script(statement, round as u32);
        let commit_y_script = script! {
            { hash_chain::commitment_script_unlock(sig_script, stack_script, 0) }
        };

        let mut this = KickOffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: generate_pay_to_pubkey_script_address(
                    context.network,
                    &context.operator_public_key,
                )
                .script_pubkey(), 
            }],
            prev_scripts: vec![commit_y_script.compile()],
        };

        this.sign_input0(context);

        this
    }

    fn sign_input0(&mut self, context: &OperatorContext) {
        pre_sign_p2wsh_input(
            self,
            context,
            0,
            EcdsaSighashType::All,
            &vec![&context.operator_keypair],
        );
    }
}

impl BaseTransaction for KickOffTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
