use bitcoin::{
    absolute, consensus, key::Keypair, Address, Amount, ScriptBuf, TapSighashType, Transaction,
    TxIn, TxOut,
};
use bitvm::signatures::WinternitzSecret;
use musig2::{errors::SigningError, AggNonce, PartialSignature, SecNonce};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::{
        base::{generate_default_tx_in, TaprootConnector},
        connector_b::ConnectorB,
        connector_f::ConnectorF,
        connector_g::ConnectorG,
        watchtower_connectors::WatchctowerConnectors,
    },
    contexts::{base::BaseContext, operator::OperatorContext, verifier::VerifierContext},
    error::{Error, TransactionError::InsufficientInputAmount},
    scripts::{generate_data_commitment_outputs, p2a_output},
    transactions::{
        signing::{
            populate_taproot_input_witness_default, populate_taproot_txin_witness,
            push_taproot_leaf_script_and_control_block_to_witness,
        },
        signing_musig2::{
            generate_taproot_aggregated_signature, generate_taproot_partial_signature,
        },
    },
};

use super::{base::*, pre_signed::*};

// return BlockhashCommitTransaction's necessary txin(Connector-G) and set wots sig for blockhash as witness for it
pub fn operator_commit_blockhash(
    connector_g: &ConnectorG,
    latest_blockhash: &[u8; 32],
    wots_secret_key: &WinternitzSecret,
    input_0: Input,
) -> Result<TxIn, Error> {
    let input_0_leaf = 0;
    let mut _input_0 = connector_g.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);
    match connector_g.generate_leaf_0_unlock_data(wots_secret_key, latest_blockhash) {
        Ok(unlock_data) => {
            populate_taproot_txin_witness(
                &mut _input_0,
                &connector_g.generate_taproot_spend_info(),
                &connector_g.generate_taproot_leaf_script(input_0_leaf),
                unlock_data,
            );
            Ok(_input_0)
        }
        Err(e) => return Err(e),
    }
}

// return AckTransaction's necessary txin(AckConnector) and set preimage as witness for it
pub fn operator_ack(
    watchtower_connectors: &WatchctowerConnectors,
    preimage: &[u8],
    input_0: Input,
) -> Result<TxIn, Error> {
    let input_0_leaf = 1;
    let mut _input_0 = watchtower_connectors
        .1
        .generate_taproot_leaf_tx_in(input_0_leaf, &input_0);
    match watchtower_connectors
        .1
        .generate_leaf_1_unlock_data(preimage)
    {
        Ok(unlock_data) => {
            populate_taproot_txin_witness(
                &mut _input_0,
                &watchtower_connectors.1.generate_taproot_spend_info(),
                &watchtower_connectors
                    .1
                    .generate_taproot_leaf_script(input_0_leaf),
                unlock_data,
            );
            Ok(_input_0)
        }
        Err(e) => return Err(e),
    }
}

pub fn extract_operator_preimage_from_ack_txin(ack_txin: &TxIn) -> Result<Vec<u8>, Error> {
    ack_txin
        .witness
        .nth(0)
        .map(|w| w.to_vec())
        .ok_or(Error::Other(
            "Unable to extract preimage from ack txin witness",
        ))
}

// Build WatchtowerChallenge transaction and sign ChallengeConnector(txin[0])
pub fn watchtower_challenge(
    watchtower_keypair: &Keypair,
    watchtower_connectors: &WatchctowerConnectors,
    commitment: &[u8],
    input_0: Input,
    payer_inputs: Vec<Input>,
    change_address: &Address,
    fee_amount: Amount,
) -> Result<Transaction, Error> {
    let input_0_leaf = 0;
    let mut _input_0 = watchtower_connectors
        .0
        .generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

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
        script_pubkey: watchtower_connectors
            .0
            .generate_taproot_address()
            .script_pubkey(),
    }];
    let script = watchtower_connectors
        .0
        .generate_taproot_leaf_script(input_0_leaf);
    populate_taproot_input_witness_default(
        &mut tx,
        &prev_outs,
        input_index,
        TapSighashType::AllPlusAnyoneCanPay,
        &watchtower_connectors.0.generate_taproot_spend_info(),
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
        connector_g: &ConnectorG,
        connector_f: &ConnectorF,
        watchtower_connectors_array: &Vec<WatchctowerConnectors>,
        input_0: Input,
    ) -> Result<Self, Error> {
        let input_0_leaf = 0;
        let _input_0 = connector_b.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        if input_0.amount
            < Amount::from_sat(
                min_relay_fee_watchtower_challenge_init(watchtower_connectors_array.len())
                    + (watchtower_connectors_array.len() * 2 + 3) as u64 * DUST_AMOUNT,
            )
        {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let mut total_output_amount = input_0.amount
            - Amount::from_sat(min_relay_fee_watchtower_challenge_init(
                watchtower_connectors_array.len(),
            ));
        let mut txouts = vec![];
        for watchtower_connectors in watchtower_connectors_array {
            let challenge_output = TxOut {
                value: Amount::from_sat(DUST_AMOUNT),
                script_pubkey: watchtower_connectors
                    .0
                    .generate_taproot_address()
                    .script_pubkey(),
            };
            let ack_output = TxOut {
                value: Amount::from_sat(DUST_AMOUNT),
                script_pubkey: watchtower_connectors
                    .1
                    .generate_taproot_address()
                    .script_pubkey(),
            };
            total_output_amount = total_output_amount - challenge_output.value - ack_output.value;
            txouts.push(challenge_output);
            txouts.push(ack_output);
        }

        let output_connector_g = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_g.generate_taproot_address().script_pubkey(),
        };
        let anchor_output = p2a_output();
        total_output_amount = total_output_amount - output_connector_g.value;
        total_output_amount = total_output_amount - anchor_output.value;
        let output_connector_f = TxOut {
            value: total_output_amount,
            script_pubkey: connector_f.generate_taproot_address().script_pubkey(),
        };
        txouts.push(output_connector_g);
        txouts.push(output_connector_f);
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
}
impl BaseTransaction for WatchtowerChallengeInitTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "WatchtowerChallengeInit"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct WatchtowerChallengeTimeoutTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for WatchtowerChallengeTimeoutTransaction {
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
impl WatchtowerChallengeTimeoutTransaction {
    pub fn new_for_validation(
        watchtower_connectors: &WatchctowerConnectors,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let input_0_leaf = 1;
        let _input_0 = watchtower_connectors
            .0
            .generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 0;
        let _input_1 = watchtower_connectors
            .1
            .generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        let output_0 = p2a_output();

        WatchtowerChallengeTimeoutTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![output_0],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: watchtower_connectors
                        .0
                        .generate_taproot_address()
                        .script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: watchtower_connectors
                        .1
                        .generate_taproot_address()
                        .script_pubkey(),
                },
            ],
            prev_scripts: vec![
                watchtower_connectors
                    .0
                    .generate_taproot_leaf_script(input_0_leaf),
                watchtower_connectors
                    .1
                    .generate_taproot_leaf_script(input_1_leaf),
            ],
        }
    }

    pub fn sign_input_0(
        &mut self,
        context: &OperatorContext,
        watchtower_connectors: &WatchctowerConnectors,
    ) {
        let input_index = 0;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            watchtower_connectors.0.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    fn sign_input_1_musig2(
        &mut self,
        context: &VerifierContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
    ) -> Result<PartialSignature, SigningError> {
        let input_index = 1;
        // We choose SIGHASH_NONE here, so if the fee_rate is low enough, the operator can replace the
        // anchor output with an OP_RETURN output carrying 0 amount, eliminating the need for additional CPFP.
        let sighash_type = TapSighashType::None;
        generate_taproot_partial_signature(
            &context,
            self.tx(),
            sec_nonce,
            agg_nonce,
            input_index,
            self.prev_outs(),
            &self.prev_scripts()[input_index],
            sighash_type,
        )
    }

    fn push_input_1_signature(
        &mut self,
        watchtower_connectors: &WatchctowerConnectors,
        input_1_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 1;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = watchtower_connectors.1.generate_taproot_spend_info();
        let tx_mut = self.tx_mut();
        // Push signature to witness
        tx_mut.input[input_index]
            .witness
            .push(input_1_sig.serialize());

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
        sec_nonces: &[SecNonce; 1],
        agg_nonces: &[AggNonce; 1],
    ) -> Result<[PartialSignature; 1], SigningError> {
        let input_0_sig = self.sign_input_1_musig2(context, &sec_nonces[0], &agg_nonces[0]);
        match [input_0_sig]
            .into_iter()
            .collect::<Result<Vec<PartialSignature>, SigningError>>()
        {
            Ok(sigs) => Ok(sigs.try_into().unwrap()),
            Err(e) => Err(e),
        }
    }

    pub fn aggregate_pre_sigs(
        &self,
        context: &dyn BaseContext,
        partial_signatures: &[Vec<PartialSignature>; 1],
        agg_nonces: &[AggNonce; 1],
    ) -> Result<[bitcoin::taproot::Signature; 1], Error> {
        let input_index = 1;
        let sig_index = 0;
        let sighash_type = TapSighashType::None;
        let input_0_sig = match generate_taproot_aggregated_signature(
            context,
            self.tx(),
            &agg_nonces[sig_index],
            input_index,
            self.prev_outs(),
            &self.prev_scripts()[input_index],
            sighash_type,
            partial_signatures[sig_index].clone(),
        ) {
            Ok(sig) => bitcoin::taproot::Signature {
                signature: sig.into(),
                sighash_type,
            },
            Err(_) => return Err(Error::Other("Failed to aggregate signatures")),
        };
        Ok([input_0_sig])
    }

    pub fn push_pre_sigs(
        &mut self,
        watchtower_connectors: &WatchctowerConnectors,
        pre_sigs: [bitcoin::taproot::Signature; 1],
    ) {
        self.push_input_1_signature(watchtower_connectors, pre_sigs[0].clone());
    }
}
impl BaseTransaction for WatchtowerChallengeTimeoutTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "WatchtowerChallengeTimeout"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct NackTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for NackTransaction {
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
impl NackTransaction {
    pub fn new_for_validation(
        watchtower_connectors: &WatchctowerConnectors,
        connector_f: &ConnectorF,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let input_0_leaf = 2;
        let _input_0 = watchtower_connectors
            .1
            .generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 1;
        let _input_1 = connector_f.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        let output_0 = p2a_output();

        NackTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![output_0],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: watchtower_connectors
                        .1
                        .generate_taproot_address()
                        .script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: connector_f.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                watchtower_connectors
                    .1
                    .generate_taproot_leaf_script(input_0_leaf),
                connector_f.generate_taproot_leaf_script(input_1_leaf),
            ],
        }
    }

    fn sign_input_0_musig2(
        &mut self,
        context: &VerifierContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
    ) -> Result<PartialSignature, SigningError> {
        let input_index = 0;
        let sighash_type = TapSighashType::All;
        generate_taproot_partial_signature(
            &context,
            self.tx(),
            sec_nonce,
            agg_nonce,
            input_index,
            self.prev_outs(),
            &self.prev_scripts()[input_index],
            sighash_type,
        )
    }

    fn push_input_0_signature(
        &mut self,
        watchtower_connectors: &WatchctowerConnectors,
        input_0_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = watchtower_connectors.1.generate_taproot_spend_info();
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

    fn sign_input_1_musig2(
        &mut self,
        context: &VerifierContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
    ) -> Result<PartialSignature, SigningError> {
        let input_index = 1;
        let sighash_type = TapSighashType::All;
        generate_taproot_partial_signature(
            &context,
            self.tx(),
            sec_nonce,
            agg_nonce,
            input_index,
            self.prev_outs(),
            &self.prev_scripts()[input_index],
            sighash_type,
        )
    }

    fn push_input_1_signature(
        &mut self,
        connector_f: &ConnectorF,
        input_1_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 1;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_f.generate_taproot_spend_info();
        let tx_mut = self.tx_mut();
        // Push signature to witness
        tx_mut.input[input_index]
            .witness
            .push(input_1_sig.serialize());

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
        sec_nonces: &[SecNonce; 2],
        agg_nonces: &[AggNonce; 2],
    ) -> Result<[PartialSignature; 2], SigningError> {
        let input_0_sig = self.sign_input_0_musig2(context, &sec_nonces[0], &agg_nonces[0]);
        let input_1_sig = self.sign_input_1_musig2(context, &sec_nonces[1], &agg_nonces[1]);
        match [input_0_sig, input_1_sig]
            .into_iter()
            .collect::<Result<Vec<PartialSignature>, SigningError>>()
        {
            Ok(sigs) => Ok(sigs.try_into().unwrap()),
            Err(e) => Err(e),
        }
    }

    pub fn aggregate_pre_sigs(
        &self,
        context: &dyn BaseContext,
        partial_signatures: &[Vec<PartialSignature>; 2],
        agg_nonces: &[AggNonce; 2],
    ) -> Result<[bitcoin::taproot::Signature; 2], Error> {
        let (input_0_sig, input_1_sig);
        {
            let input_index = 0;
            let sig_index = 0;
            let sighash_type = TapSighashType::All;
            input_0_sig = match generate_taproot_aggregated_signature(
                context,
                self.tx(),
                &agg_nonces[sig_index],
                input_index,
                self.prev_outs(),
                &self.prev_scripts()[input_index],
                sighash_type,
                partial_signatures[sig_index].clone(),
            ) {
                Ok(sig) => bitcoin::taproot::Signature {
                    signature: sig.into(),
                    sighash_type,
                },
                Err(_) => return Err(Error::Other("Failed to aggregate signatures")),
            };
        }
        {
            let input_index = 1;
            let sig_index = 1;
            let sighash_type = TapSighashType::All;
            input_1_sig = match generate_taproot_aggregated_signature(
                context,
                self.tx(),
                &agg_nonces[sig_index],
                input_index,
                self.prev_outs(),
                &self.prev_scripts()[input_index],
                sighash_type,
                partial_signatures[sig_index].clone(),
            ) {
                Ok(sig) => bitcoin::taproot::Signature {
                    signature: sig.into(),
                    sighash_type,
                },
                Err(_) => return Err(Error::Other("Failed to aggregate signatures")),
            };
        }
        Ok([input_0_sig, input_1_sig])
    }

    pub fn push_pre_sigs(
        &mut self,
        watchtower_connectors: &WatchctowerConnectors,
        connector_f: &ConnectorF,
        pre_sigs: [bitcoin::taproot::Signature; 2],
    ) {
        self.push_input_0_signature(watchtower_connectors, pre_sigs[0].clone());
        self.push_input_1_signature(connector_f, pre_sigs[1].clone());
    }
}
impl BaseTransaction for NackTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "Nack"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct BlockhashCommitTimeoutTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for BlockhashCommitTimeoutTransaction {
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
impl BlockhashCommitTimeoutTransaction {
    pub fn new_for_validation(
        connector_g: &ConnectorG,
        connector_f: &ConnectorF,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let input_0_leaf = 1;
        let _input_0 = connector_g.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 1;
        let _input_1 = connector_f.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        let output_0 = p2a_output();

        BlockhashCommitTimeoutTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![output_0],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: connector_g.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: connector_f.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_g.generate_taproot_leaf_script(input_0_leaf),
                connector_f.generate_taproot_leaf_script(input_1_leaf),
            ],
        }
    }

    fn sign_input_0_musig2(
        &mut self,
        context: &VerifierContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
    ) -> Result<PartialSignature, SigningError> {
        let input_index = 0;
        let sighash_type = TapSighashType::All;
        generate_taproot_partial_signature(
            &context,
            self.tx(),
            sec_nonce,
            agg_nonce,
            input_index,
            self.prev_outs(),
            &self.prev_scripts()[input_index],
            sighash_type,
        )
    }

    fn push_input_0_signature(
        &mut self,
        connector_g: &ConnectorG,
        input_0_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_g.generate_taproot_spend_info();
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

    fn sign_input_1_musig2(
        &mut self,
        context: &VerifierContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
    ) -> Result<PartialSignature, SigningError> {
        let input_index = 1;
        let sighash_type = TapSighashType::All;
        generate_taproot_partial_signature(
            &context,
            self.tx(),
            sec_nonce,
            agg_nonce,
            input_index,
            self.prev_outs(),
            &self.prev_scripts()[input_index],
            sighash_type,
        )
    }

    fn push_input_1_signature(
        &mut self,
        connector_f: &ConnectorF,
        input_1_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 1;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_f.generate_taproot_spend_info();
        let tx_mut = self.tx_mut();
        // Push signature to witness
        tx_mut.input[input_index]
            .witness
            .push(input_1_sig.serialize());

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
        sec_nonces: &[SecNonce; 2],
        agg_nonces: &[AggNonce; 2],
    ) -> Result<[PartialSignature; 2], SigningError> {
        let input_0_sig = self.sign_input_0_musig2(context, &sec_nonces[0], &agg_nonces[0]);
        let input_1_sig = self.sign_input_1_musig2(context, &sec_nonces[1], &agg_nonces[1]);
        match [input_0_sig, input_1_sig]
            .into_iter()
            .collect::<Result<Vec<PartialSignature>, SigningError>>()
        {
            Ok(sigs) => Ok(sigs.try_into().unwrap()),
            Err(e) => Err(e),
        }
    }

    pub fn aggregate_pre_sigs(
        &self,
        context: &dyn BaseContext,
        partial_signatures: &[Vec<PartialSignature>; 2],
        agg_nonces: &[AggNonce; 2],
    ) -> Result<[bitcoin::taproot::Signature; 2], Error> {
        let (input_0_sig, input_1_sig);
        {
            let input_index = 0;
            let sig_index = 0;
            let sighash_type = TapSighashType::All;
            input_0_sig = match generate_taproot_aggregated_signature(
                context,
                self.tx(),
                &agg_nonces[sig_index],
                input_index,
                self.prev_outs(),
                &self.prev_scripts()[input_index],
                sighash_type,
                partial_signatures[sig_index].clone(),
            ) {
                Ok(sig) => bitcoin::taproot::Signature {
                    signature: sig.into(),
                    sighash_type,
                },
                Err(_) => return Err(Error::Other("Failed to aggregate signatures")),
            };
        }
        {
            let input_index = 1;
            let sig_index = 1;
            let sighash_type = TapSighashType::All;
            input_1_sig = match generate_taproot_aggregated_signature(
                context,
                self.tx(),
                &agg_nonces[sig_index],
                input_index,
                self.prev_outs(),
                &self.prev_scripts()[input_index],
                sighash_type,
                partial_signatures[sig_index].clone(),
            ) {
                Ok(sig) => bitcoin::taproot::Signature {
                    signature: sig.into(),
                    sighash_type,
                },
                Err(_) => return Err(Error::Other("Failed to aggregate signatures")),
            };
        }
        Ok([input_0_sig, input_1_sig])
    }

    pub fn push_pre_sigs(
        &mut self,
        connector_g: &ConnectorG,
        connector_f: &ConnectorF,
        pre_sigs: [bitcoin::taproot::Signature; 2],
    ) {
        self.push_input_0_signature(connector_g, pre_sigs[0].clone());
        self.push_input_1_signature(connector_f, pre_sigs[1].clone());
    }
}
impl BaseTransaction for BlockhashCommitTimeoutTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "BlockhashCommitTimeout"
    }
}
