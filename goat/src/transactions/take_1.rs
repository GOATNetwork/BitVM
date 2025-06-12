use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, TapSighashType,
    Transaction, TxOut,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    super::{
        connectors::{
            base::*, connector_0::Connector0, connector_3::Connector3, connector_a::ConnectorA,
        },
        contexts::{base::BaseContext, operator::OperatorContext, verifier::VerifierContext},
        scripts::*,
    },
    base::*,
    pre_signed::*,
    pre_signed_musig2::*,
    signing::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Take1Transaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for Take1Transaction {
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

impl PreSignedMusig2Transaction for Take1Transaction {
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
        vec![0, 3]
    }
}

impl Take1Transaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: &OperatorContext,
        connector_0: &Connector0,
        connector_3: &Connector3,
        connector_a: &ConnectorA,
        input_0: Input,
        input_1: Input,
        input_2: Input,
    ) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            connector_0,
            connector_3,
            connector_a,
            input_0,
            input_1,
            input_2,
        );

        this.sign_input_1(context, connector_a);
        this.sign_input_2(context);

        this
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        connector_0: &Connector0,
        connector_3: &Connector3,
        connector_a: &ConnectorA,
        input_0: Input,
        input_1: Input,
        input_2: Input,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = connector_0.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 0;
        let _input_1 = connector_a.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        let _input_2 = connector_3.generate_tx_in(&input_2);

        let total_output_amount = input_0.amount + input_1.amount + input_2.amount
            - Amount::from_sat(MIN_RELAY_FEE_TAKE_1);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(network, operator_public_key)
                .script_pubkey(),
        };

        Take1Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1, _input_2],
                output: vec![_output_0],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: connector_0.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_2.amount,
                    script_pubkey: connector_3.generate_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_0.generate_taproot_leaf_script(input_0_leaf),
                connector_a.generate_taproot_leaf_script(input_1_leaf),
                connector_3.generate_script(),
            ],
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    fn sign_input_0(
        &mut self,
        context: &VerifierContext,
        connector_0: &Connector0,
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
            self.finalize_input_0(context, connector_0);
        }
    }

    fn finalize_input_0(&mut self, context: &dyn BaseContext, connector_0: &Connector0) {
        let input_index = 0;
        finalize_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            connector_0.generate_taproot_spend_info(),
        );
    }

    pub fn sign_input_1(&mut self, context: &OperatorContext, connector_a: &ConnectorA) {
        let input_index = 1;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            connector_a.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn sign_input_2(&mut self, context: &OperatorContext) {
        let input_index = 2;
        pre_sign_p2wsh_input(
            self,
            input_index,
            EcdsaSighashType::All,
            &vec![&context.operator_keypair],
        );
    }

    pub fn push_pre_sigs(
        &mut self,
        connector_0: &Connector0,
        input_0_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_0.generate_taproot_spend_info();
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
        connector_0: &Connector0,
        secret_nonces: &HashMap<usize, SecNonce>,
    ) {
        let input_index = 0;
        self.sign_input_0(context, connector_0, &secret_nonces[&input_index]);
    }

    pub fn merge(&mut self, take_1: &Take1Transaction) {
        merge_transactions(&mut self.tx, &take_1.tx);
        merge_musig2_nonces_and_signatures(self, take_1);
    }
}

impl BaseTransaction for Take1Transaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "Take1"
    }
}
