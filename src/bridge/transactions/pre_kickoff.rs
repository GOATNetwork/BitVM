use bitcoin::{
    absolute, consensus, Amount, ScriptBuf, Sequence, EcdsaSighashType, Transaction,
    TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};
use std::process::exit;

use super::{
    super::{
        connectors::{connector::*, connector_k::ConnectorK},
        contexts::operator::OperatorContext,
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct PreKickOffTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for PreKickOffTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PreKickOffTransaction {
    pub fn new(context: &OperatorContext,  operator_input: Input) -> Self {
        let connector_k = ConnectorK::new(
            context.network,
            &context.operator_public_key,
            &context.operator_commitment_pubkey,
            &context.operator_taproot_public_key,
        );

        let _input0 = TxIn {
            previous_output: operator_input.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_output_amount = operator_input.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount,
            script_pubkey: connector_k.generate_taproot_address().script_pubkey(),
        };

        let mut this = PreKickOffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0],
            },
            prev_outs: vec![TxOut {
                value: operator_input.amount,
                script_pubkey: generate_pay_to_pubkey_script_address(
                    context.network,
                    &context.operator_public_key,
                )
                .script_pubkey(),
            }],
            prev_scripts: vec![generate_pay_to_pubkey_script(&context.operator_public_key)],
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

impl BaseTransaction for PreKickOffTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
