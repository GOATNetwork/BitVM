use bitcoin::{
    absolute, consensus, key::Keypair, Address, Amount, ScriptBuf, TapSighashType, Transaction,
    TxIn, TxOut,
};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::{
        base::{generate_default_tx_in, TaprootConnector},
        connector_b::ConnectorB,
        watchtower_connectors::WatchtowerChallengeConnector,
    },
    contexts::operator::OperatorContext,
    error::{Error, TransactionError::InsufficientInputAmount},
    scripts::{generate_data_commitment_outputs, p2a_output},
    transactions::signing::populate_taproot_input_witness_default,
};

use super::{base::*, pre_signed::*};

// Build WatchtowerChallenge transaction and sign ChallengeConnector(txin[0])
pub fn watchtower_challenge(
    watchtower_keypair: &Keypair,
    watchtower_challenge_connector: &WatchtowerChallengeConnector,
    commitment: &[u8],
    input_0: Input,
    payer_inputs: Vec<Input>,
    change_address: &Address,
    fee_amount: Amount,
) -> Result<Transaction, Error> {
    let input_0_leaf = 0;
    let mut _input_0 =
        watchtower_challenge_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

    let mut txins = vec![_input_0];
    let mut total_input_amount = input_0.amount;
    txins.extend(
        payer_inputs
            .iter()
            .map(|input| {
                total_input_amount += input.amount;
                generate_default_tx_in(input)
            })
            .collect::<Vec<TxIn>>(),
    );

    let commitment_outputs = generate_data_commitment_outputs(commitment);
    let commitment_amounts = commitment_outputs
        .iter()
        .map(|out| out.value)
        .sum::<Amount>();

    if total_input_amount < fee_amount + commitment_amounts {
        return Err(Error::Transaction(InsufficientInputAmount));
    }

    let total_output_amount = total_input_amount - fee_amount;
    let change_amount = total_output_amount - commitment_amounts;
    let mut txouts = commitment_outputs;
    if change_amount >= Amount::from_sat(DUST_AMOUNT) {
        let change_output = TxOut {
            value: change_amount,
            script_pubkey: change_address.script_pubkey(),
        };
        txouts.push(change_output);
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: txins,
        output: txouts,
    };

    // sign input_0
    let input_index = 0;
    let prev_outs = vec![TxOut {
        value: input_0.amount,
        script_pubkey: watchtower_challenge_connector
            .generate_taproot_address()
            .script_pubkey(),
    }];
    let script = watchtower_challenge_connector.generate_taproot_leaf_script(input_0_leaf);
    populate_taproot_input_witness_default(
        &mut tx,
        &prev_outs,
        input_index,
        TapSighashType::AllPlusAnyoneCanPay,
        &watchtower_challenge_connector.generate_taproot_spend_info(),
        &script,
        &vec![watchtower_keypair],
    );

    Ok(tx)
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct WatchtowerChallengeInitTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for WatchtowerChallengeInitTransaction {
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
impl WatchtowerChallengeInitTransaction {
    pub fn new_for_validation(
        connector_b: &ConnectorB,
        watchtower_challenge_connectors: &Vec<WatchtowerChallengeConnector>,
        input_0: Input,
    ) -> Result<Self, Error> {
        let input_0_leaf = 0;
        let _input_0 = connector_b.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        if input_0.amount
            < Amount::from_sat(max_watchtower_challenge_cost(
                watchtower_challenge_connectors.len(),
            ))
        {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let mut txouts = vec![];
        for watchtower_challenge_connector in watchtower_challenge_connectors {
            let challenge_output = TxOut {
                value: Amount::from_sat(DUST_AMOUNT),
                script_pubkey: watchtower_challenge_connector
                    .generate_taproot_address()
                    .script_pubkey(),
            };
            txouts.push(challenge_output);
        }

        let anchor_output = p2a_output();
        txouts.push(anchor_output);

        Ok(WatchtowerChallengeInitTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: txouts,
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_b.generate_taproot_leaf_script(input_0_leaf)],
        })
    }

    pub fn sign_input_0(&mut self, context: &OperatorContext, connector_b: &ConnectorB) {
        let input_index = 0;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            connector_b.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn watchtower_connector_input(&self, index: usize) -> Result<Input, Error> {
        let watchtower_num = self.tx.output.len().saturating_sub(1);
        if index >= watchtower_num {
            return Err(Error::Other("watchtower connector index out of bounds"));
        }

        tx_output_input(
            &self.tx,
            output_topology::watchtower_challenge_init::watchtower_connector(index),
        )
    }

    pub fn watchtower_connector_inputs(&self) -> Result<Vec<Input>, Error> {
        if self.tx.output.is_empty() {
            return Err(Error::Other("watchtower challenge init has no outputs"));
        }

        let watchtower_num = self.tx.output.len() - 1;
        (0..watchtower_num)
            .map(|index| self.watchtower_connector_input(index))
            .collect()
    }

    pub fn anchor_input(&self) -> Result<Input, Error> {
        let watchtower_num = self.tx.output.len().saturating_sub(1);
        tx_output_input(
            &self.tx,
            output_topology::watchtower_challenge_init::anchor(watchtower_num),
        )
    }
}
impl BaseTransaction for WatchtowerChallengeInitTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "WatchtowerChallengeInit"
    }
}
