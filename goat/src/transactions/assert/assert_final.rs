use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, PublicKey, ScriptBuf, TapSighashType,
    Transaction, TxOut,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    super::{
        super::{
            connectors::{
                base::*, connector_4::Connector4, connector_5::Connector5, connector_c::ConnectorC,
                connector_d::ConnectorD,
            },
            contexts::{base::BaseContext, operator::OperatorContext, verifier::VerifierContext},
            transactions::base::DUST_AMOUNT,
        },
        base::*,
        pre_signed::*,
        pre_signed_musig2::*,
        signing::*,
    },
    utils::{AssertCommitConnectorsF, COMMIT_TX_NUM},
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertFinalTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for AssertFinalTransaction {
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

impl PreSignedMusig2Transaction for AssertFinalTransaction {
    fn musig2_nonces(&self) -> &HashMap<usize, HashMap<PublicKey, PubNonce>> {
        &self.musig2_nonces
    }
    fn musig2_nonces_mut(&mut self) -> &mut HashMap<usize, HashMap<PublicKey, PubNonce>> {
        &mut self.musig2_nonces
    }
    fn musig2_nonce_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, Signature>> {
        &self.musig2_nonce_signatures
    }
    fn musig2_nonce_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, Signature>> {
        &mut self.musig2_nonce_signatures
    }
    fn musig2_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, PartialSignature>> {
        &self.musig2_signatures
    }
    fn musig2_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, PartialSignature>> {
        &mut self.musig2_signatures
    }
    fn verifier_inputs(&self) -> Vec<usize> {
        vec![0]
    }
}

impl AssertFinalTransaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: &OperatorContext,
        connector_4: &Connector4,
        connector_5: &Connector5,
        connector_c: &ConnectorC,
        connector_d: &ConnectorD,
        assert_commit_connectors_f: &AssertCommitConnectorsF,
        input_0: Input,
        input_f: [Input; COMMIT_TX_NUM],
    ) -> Self {
        let mut this = Self::new_for_validation(
            connector_4,
            connector_5,
            connector_c,
            connector_d,
            assert_commit_connectors_f,
            input_0,
            input_f,
        );

        this.sign_commit_inputs(context);

        this
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_validation(
        connector_4: &Connector4,
        connector_5: &Connector5,
        connector_c: &ConnectorC,
        connector_d: &ConnectorD,
        assert_commit_connectors_f: &AssertCommitConnectorsF,
        input_0: Input,
        input_f: [Input; COMMIT_TX_NUM],
    ) -> Self {
        let mut txins = vec![];
        let mut prev_outs = vec![];
        let mut prev_scripts = vec![];
        let mut total_input_amount = Amount::ZERO;

        // input_0 : connector_d
        let input_0_leaf = 0;
        txins.push(connector_d.generate_taproot_leaf_tx_in(input_0_leaf, &input_0));
        prev_outs.push(TxOut {
            value: input_0.amount,
            script_pubkey: connector_d.generate_taproot_address().script_pubkey(),
        });
        prev_scripts.push(connector_d.generate_taproot_leaf_script(input_0_leaf));
        total_input_amount += input_0.amount;

        // other inputs: connectors_f
        for i in 0..COMMIT_TX_NUM {
            txins.push(assert_commit_connectors_f.connectors_f[i].generate_tx_in(&input_f[i]));
            prev_outs.push(TxOut {
                value: input_f[i].amount,
                script_pubkey: assert_commit_connectors_f.connectors_f[i]
                    .generate_address()
                    .script_pubkey(),
            });
            prev_scripts.push(assert_commit_connectors_f.connectors_f[i].generate_script());
            total_input_amount += input_f[i].amount;
        }
        let total_output_amount = total_input_amount - Amount::from_sat(MIN_RELAY_FEE_ASSERT_FINAL);

        // goes to take_2 tx
        let _output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_4.generate_address().script_pubkey(),
        };

        // goes to take_2 tx or disprove tx
        let _output_1 = TxOut {
            value: total_output_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: connector_5.generate_taproot_address().script_pubkey(),
        };

        // goes to take_2 tx or disprove tx
        let _output_2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
        };

        AssertFinalTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: txins,
                output: vec![_output_0, _output_1, _output_2],
            },
            prev_outs,
            prev_scripts,
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    fn sign_input_0(
        &mut self,
        context: &VerifierContext,
        connector_d: &ConnectorD,
        secret_nonce: &SecNonce,
    ) {
        let input_index = 0;
        pre_sign_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            secret_nonce,
        );

        // TODO: Consider verifying the final signature against the n-of-n public key and the tx.
        if self.musig2_signatures[&input_index].len() == context.n_of_n_public_keys.len() {
            self.finalize_input_0(context, connector_d);
        }
    }

    pub fn sign_commit_inputs(&mut self, context: &OperatorContext) {
        for input_index in 1..(COMMIT_TX_NUM + 1) {
            pre_sign_p2wsh_input(
                self,
                input_index,
                EcdsaSighashType::All,
                &vec![&context.operator_keypair],
            );
        }
    }

    fn finalize_input_0(&mut self, context: &dyn BaseContext, connector_d: &ConnectorD) {
        let input_index = 0;
        finalize_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            connector_d.generate_taproot_spend_info(),
        );
    }

    pub fn push_pre_sigs(
        &mut self,
        connector_d: &ConnectorD,
        input_0_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_d.generate_taproot_spend_info();
        let tx_mut = self.tx_mut();
        // Push signature to witness
        tx_mut.input[input_index]
            .witness
            .push(input_0_sig.serialize());

        // Push script + control block
        push_taproot_leaf_script_and_control_block_to_witness(
            tx_mut,
            input_index,
            &spend_info,
            &script,
        );
    }

    pub fn pre_sign(
        &mut self,
        context: &VerifierContext,
        connector_d: &ConnectorD,
        secret_nonces: &HashMap<usize, SecNonce>,
    ) {
        let input_index = 0;
        self.sign_input_0(context, connector_d, &secret_nonces[&input_index]);
    }

    pub fn merge(&mut self, assert: &AssertFinalTransaction) {
        merge_transactions(&mut self.tx, &assert.tx);
        merge_musig2_nonces_and_signatures(self, assert);
    }
}

impl BaseTransaction for AssertFinalTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "AssertFinal"
    }
}
