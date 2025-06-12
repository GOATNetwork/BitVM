use bitcoin::{absolute, consensus, Amount, ScriptBuf, Transaction, TxOut};
use bitvm::{chunk::api::type_conversion_utils::RawWitness, execute_raw_script_with_inputs};
use serde::{Deserialize, Serialize};

use crate::transactions::{
    assert::utils::MAX_CONNECTORS_E_PER_TX, signing::populate_taproot_input_witness,
};

use super::{
    super::{
        super::connectors::{base::*, connector_f::ConnectorF},
        base::*,
        pre_signed::*,
    },
    utils::{
        AllCommitConnectorsE, AssertCommitConnectorsF, SingleCommitConnectorsE, COMMIT_TX_NUM,
    },
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitTransactionSet {
    pub commit_txns: [AssertCommitTransaction; COMMIT_TX_NUM],
}
impl AssertCommitTransactionSet {
    pub fn new(
        all_connectors_e: &AllCommitConnectorsE,
        connectors_f: &AssertCommitConnectorsF,
        tx_inputs: Vec<Input>,
    ) -> Self {
        assert_eq!(
            tx_inputs.len(),
            all_connectors_e.connectors_num(),
            "inputs and connectors e don't match"
        );

        let mut commit_txns = vec![];
        for (i, inputs) in (0..COMMIT_TX_NUM).zip(tx_inputs.chunks(MAX_CONNECTORS_E_PER_TX)) {
            commit_txns.push(AssertCommitTransaction::new(
                &all_connectors_e.commit_connectors_e_vec[i],
                &connectors_f.connectors_f[i],
                inputs.to_vec(),
            ));
        }
        AssertCommitTransactionSet {
            commit_txns: commit_txns
                .try_into()
                .unwrap_or_else(|_e| panic!("impossible")),
        }
    }

    pub fn sign(
        &mut self,
        all_connectors_e: &AllCommitConnectorsE,
        all_witnesses: Vec<RawWitness>,
    ) {
        for (i, witness) in (0..COMMIT_TX_NUM).zip(all_witnesses.chunks(MAX_CONNECTORS_E_PER_TX)) {
            self.commit_txns[i].sign(
                &all_connectors_e.commit_connectors_e_vec[i],
                witness.to_vec(),
            );
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for AssertCommitTransaction {
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

impl AssertCommitTransaction {
    pub fn new(
        connectors_e: &SingleCommitConnectorsE,
        connector_f: &ConnectorF,
        tx_inputs: Vec<Input>,
    ) -> Self {
        assert_eq!(
            tx_inputs.len(),
            connectors_e.connectors_num(),
            "inputs and connectors e don't match"
        );

        Self::new_for_validation(connectors_e, connector_f, tx_inputs)
    }

    pub fn new_for_validation(
        connectors_e: &SingleCommitConnectorsE,
        connector_f_1: &ConnectorF,
        tx_inputs: Vec<Input>,
    ) -> Self {
        let mut inputs = vec![];
        let mut prev_outs = vec![];
        let mut prev_scripts = vec![];
        let mut total_output_amount = Amount::from_sat(0);

        for (connector_e, input) in (0..connectors_e.connectors_num())
            .map(|idx| connectors_e.get_connector_e(idx))
            .zip(tx_inputs)
        {
            inputs.push(connector_e.generate_taproot_leaf_tx_in(0, &input));
            prev_outs.push(TxOut {
                value: input.amount,
                script_pubkey: connector_e.generate_taproot_address().script_pubkey(),
            });
            prev_scripts.push(connector_e.generate_taproot_leaf_script(0));
            total_output_amount += input.amount;
        }
        total_output_amount -= Amount::from_sat(MIN_RELAY_FEE_ASSERT_COMMIT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: connector_f_1.generate_address().script_pubkey(),
        };

        AssertCommitTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: inputs,
                output: vec![_output_0],
            },
            prev_outs,
            prev_scripts,
        }
    }

    pub fn sign(&mut self, connectors_e: &SingleCommitConnectorsE, witnesses: Vec<RawWitness>) {
        assert_eq!(witnesses.len(), connectors_e.connectors_num());
        for (input_index, witness) in (0..connectors_e.connectors_num()).zip(witnesses) {
            let taproot_spend_info = connectors_e
                .get_connector_e(input_index)
                .generate_taproot_spend_info();
            let script = &self.prev_scripts()[input_index].clone();
            let res = execute_raw_script_with_inputs(script.clone().to_bytes(), witness.clone());
            assert!(
                res.success,
                "script: {:?}, res: {:?}: stack: {:?}, variable name: {:?}",
                script,
                res,
                res.final_stack,
                connectors_e
                    .get_connector_e(input_index)
                    .commitment_public_keys
                    .keys()
            );
            populate_taproot_input_witness(
                self.tx_mut(),
                input_index,
                &taproot_spend_info,
                script,
                witness,
            );
        }
    }
}

impl BaseTransaction for AssertCommitTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "AssertCommit"
    }
}
