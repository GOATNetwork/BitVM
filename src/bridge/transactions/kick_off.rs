use bitcoin::{
    absolute, consensus, witness, Amount, EcdsaSighashType, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness
};
use serde::{Deserialize, Serialize};
use crate::bridge::graphs::base::HIGH_FEE_AMOUNT;
use crate::treepp::*;
use crate::bridge::{connectors::connector_k, hash_chain, transactions::signing};

use super::signing::push_taproot_leaf_script_and_control_block_to_witness;
use super::{
    super::{
        connectors::{
            connector::*, connector_1::Connector1, connector_a::ConnectorA, connector_b::ConnectorB, connector_k::ConnectorK
        },
        contexts::operator::OperatorContext,
        graphs::base::{DUST_AMOUNT, FEE_AMOUNT, CALC_ROUND},
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
    pub fn new(context: &OperatorContext, input0: Input, statement: &[u8]) -> Self {
        let connector_1 = Connector1::new(context.network, &context.operator_public_key);
        let connector_a = ConnectorA::new(
            context.network,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
        );
        let connector_b = ConnectorB::new(context.network, &context.n_of_n_taproot_public_key);
        let connector_k = ConnectorK::new(
            context.network, 
            &context.operator_public_key, 
            &context.operator_commitment_pubkey,
            &context.operator_taproot_public_key,
        );

        let _input0 = connector_k.generate_taproot_leaf_tx_in(0, &input0);

        let available_input_amount = input0.amount - Amount::from_sat(HIGH_FEE_AMOUNT);

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

        let mut this = KickOffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: connector_k.generate_taproot_address().script_pubkey(), 
            }],
            prev_scripts: vec![connector_k.generate_taproot_leaf_script(0)],
        };
        
        // push witness for connector_k
        connector_k.push_leaf0_unlock_witness(&mut this.tx.input[0].witness, &context.operator_commitment_seckey, statement);
        let redeem_script = connector_k.generate_taproot_leaf_script(0);
        let taproot_spend_info = connector_k.generate_taproot_spend_info();
        push_taproot_leaf_script_and_control_block_to_witness(&mut this.tx, 0, &taproot_spend_info, &redeem_script);

        // // debug
        // let witness = this.tx.input[0].witness.clone();
        // for i in 0..witness.len()/4 {
        //     let ele_0 = witness.nth(4*i).unwrap();
        //     let ele_1 = witness.nth(4*i+1).unwrap();
        //     let ele_2 = witness.nth(4*i+2).unwrap();
        //     let ele_3 = witness.nth(4*i+3).unwrap();
        //     let res_0 = hex::encode(&ele_0);
        //     let res_1 = hex::encode(&ele_1);
        //     let res_2 = hex::encode(&ele_2);
        //     let res_3 = hex::encode(&ele_3);
        //     println!("{res_0} {res_1} {res_2} {res_3}");
        // }

        this
    }
}

impl BaseTransaction for KickOffTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
