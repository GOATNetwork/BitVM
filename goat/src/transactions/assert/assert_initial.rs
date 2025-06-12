use bitcoin::{absolute, consensus, Amount, ScriptBuf, TapSighashType, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::{base::*, connector_b::ConnectorB, connector_d::ConnectorD},
    contexts::operator::OperatorContext,
    transactions::{
        assert::utils::{AllCommitConnectorsE, COMMIT_TX_NUM},
        base::DUST_AMOUNT,
        base::*,
        pre_signed::*,
    },
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertInitialTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for AssertInitialTransaction {
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

impl AssertInitialTransaction {
    pub fn new(
        context: &OperatorContext,
        connector_b: &ConnectorB,
        connector_d: &ConnectorD,
        all_commit_connectors_e: &AllCommitConnectorsE,
        input_0: Input,
    ) -> Self {
        let mut this =
            Self::new_for_validation(connector_b, connector_d, all_commit_connectors_e, input_0);

        this.sign_input_0(&context, &connector_b);

        this
    }

    pub fn new_for_validation(
        connector_b: &ConnectorB,
        connector_d: &ConnectorD,
        all_commit_connectors_e: &AllCommitConnectorsE,
        input_0: Input,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = connector_b.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);
        let total_output_amount = input_0.amount - Amount::from_sat(MIN_RELAY_FEE_ASSERT_INITIAL);

        let assert_commits_expense = Amount::from_sat(
            MIN_RELAY_FEE_ASSERT_COMMIT * COMMIT_TX_NUM as u64
                + all_commit_connectors_e.connectors_num() as u64 * DUST_AMOUNT,
        );
        // goes to assert_final
        let _output_0 = TxOut {
            value: total_output_amount - assert_commits_expense,
            script_pubkey: connector_d.generate_taproot_address().script_pubkey(),
        };
        let mut txouts = vec![_output_0];

        for i in 0..COMMIT_TX_NUM {
            let assert_commit_i_connectors_e = &all_commit_connectors_e.commit_connectors_e_vec[i];
            for j in 0..assert_commit_i_connectors_e.connectors_num() {
                let amount = if j == 0 {
                    MIN_RELAY_FEE_ASSERT_COMMIT + DUST_AMOUNT
                } else {
                    DUST_AMOUNT
                };
                txouts.push(TxOut {
                    value: Amount::from_sat(amount),
                    script_pubkey: assert_commit_i_connectors_e
                        .get_connector_e(j)
                        .generate_taproot_address()
                        .script_pubkey(),
                });
            }
        }

        AssertInitialTransaction {
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
        }
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
}

impl BaseTransaction for AssertInitialTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "AssertInitial"
    }
}
