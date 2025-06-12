use bitcoin::{absolute, consensus, Address, Amount, Transaction, TxIn, TxOut};
use serde::{Deserialize, Serialize};

use crate::scripts::generate_opreturn_script;

use super::super::{
    super::connectors::{base::*, connector_0::Connector0},
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    fee_amount: Amount,
    pub input_amounts: Vec<Amount>,
}

impl PegInTransaction {
    pub fn new_for_validation(
        connector_0: &Connector0,
        inputs: Vec<Input>,
        deposit_amount: Amount,
        fee_amount: Amount,
        change_address: Address,
        message: Vec<u8>,
    ) -> Self {
        let mut total_input_amount = Amount::ZERO;
        let input_amounts: Vec<Amount> = inputs.iter().map(|input| input.amount).collect();
        let txins: Vec<TxIn> = inputs
            .iter()
            .map(|input| {
                total_input_amount += input.amount;
                generate_default_tx_in(input)
            })
            .collect();
        let change_amount = total_input_amount - deposit_amount - fee_amount;
        let mut txouts = vec![];
        let output_0 = TxOut {
            value: deposit_amount,
            script_pubkey: connector_0.generate_taproot_address().script_pubkey(),
        };
        txouts.push(output_0);
        let output_1 = TxOut {
            value: Amount::ZERO,
            script_pubkey: generate_opreturn_script(message),
        };
        txouts.push(output_1);
        let mut fee_amount = fee_amount;
        if change_amount > Amount::from_sat(DUST_AMOUNT) {
            let output_2 = TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            };
            txouts.push(output_2);
        } else {
            fee_amount += change_amount;
        }

        PegInTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: txins,
                output: txouts,
            },
            fee_amount,
            input_amounts,
        }
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    pub fn tx_mut(&mut self) -> &mut Transaction {
        &mut self.tx
    }
}

impl BaseTransaction for PegInTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "PegIn"
    }
}
