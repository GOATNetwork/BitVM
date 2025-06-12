use bitcoin::{
    absolute, consensus, Address, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf,
    Transaction, TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{base::*, connector_6::Connector6},
        contexts::operator::OperatorContext,
        scripts::*,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PreKickoffTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    fee_amount: Amount,
    pub input_amounts: Vec<Amount>,
}

impl PreKickoffTransaction {
    pub fn new_unsigned(
        connector_6: &Connector6,
        inputs: Vec<Input>,
        stake_amount: Amount,
        fee_amount: Amount,
        change_address: Address,
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
        let change_amount = total_input_amount - stake_amount - fee_amount;
        let mut txouts = vec![];
        let output_0 = TxOut {
            value: stake_amount,
            script_pubkey: connector_6.generate_taproot_address().script_pubkey(),
        };
        txouts.push(output_0);
        let mut fee_amount = fee_amount;
        if change_amount > Amount::from_sat(DUST_AMOUNT) {
            let output_1 = TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            };
            txouts.push(output_1);
        } else {
            fee_amount += change_amount;
        }

        PreKickoffTransaction {
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

    pub fn add_unlock_witness(&mut self, input_index: usize, witness: Witness) {
        self.tx.input[input_index].witness = witness
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    pub fn tx_mut(&mut self) -> &mut Transaction {
        &mut self.tx
    }
}

impl BaseTransaction for PreKickoffTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "PreKickoff"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegOutConfirmTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for PegOutConfirmTransaction {
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

impl PegOutConfirmTransaction {
    pub fn new(context: &OperatorContext, connector_6: &Connector6, input_0: Input) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            connector_6,
            input_0,
        );

        this.sign_input_0(context);

        this
    }

    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        connector_6: &Connector6,
        input_0: Input,
    ) -> Self {
        let _input_0 = generate_default_tx_in(&input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(MIN_RELAY_FEE_PEG_OUT_CONFIRM);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: connector_6.generate_taproot_address().script_pubkey(),
        };

        PegOutConfirmTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: generate_pay_to_pubkey_script_address(network, operator_public_key)
                    .script_pubkey(),
            }],
            prev_scripts: vec![generate_pay_to_pubkey_script(operator_public_key)],
        }
    }

    fn sign_input_0(&mut self, context: &OperatorContext) {
        let input_index = 0;
        pre_sign_p2wsh_input(
            self,
            input_index,
            EcdsaSighashType::All,
            &vec![&context.operator_keypair],
        );
    }
}

impl BaseTransaction for PegOutConfirmTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "PegOutConfirm"
    }
}
