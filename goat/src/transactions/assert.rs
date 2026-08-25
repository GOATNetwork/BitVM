use ark_std::iterable::Iterable;
use bitcoin::{absolute, consensus, Amount, ScriptBuf, TapSighashType, Transaction, TxIn, TxOut};
use bitvm::signatures::WinternitzSecret;
use musig2::{errors::SigningError, AggNonce, PartialSignature, SecNonce};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::{
        assert_connectors::AssertCommitConnector, base::TaprootConnector, connector_c::ConnectorC,
        connector_d::ConnectorD,
    },
    contexts::{base::BaseContext, operator::OperatorContext, verifier::VerifierContext},
    disprove_scripts::AssertAssertions,
    error::{Error, TransactionError::InsufficientInputAmount},
    scripts::p2a_output,
    transactions::{
        signing::{
            populate_taproot_txin_witness, push_taproot_leaf_script_and_control_block_to_witness,
        },
        signing_musig2::{
            generate_taproot_aggregated_signature, generate_taproot_partial_signature,
        },
    },
};

use super::{base::*, pre_signed::*};

pub fn operator_commit_proof(
    assert_commit_connectors: &Vec<AssertCommitConnector>,
    wots_secret_keys: &Vec<WinternitzSecret>,
    assert_commit_inputs: &Vec<Input>,
    assertions: &AssertAssertions,
) -> Result<Vec<TxIn>, Error> {
    if assert_commit_connectors.len() != assert_commit_inputs.len() {
        return Err(Error::Other(
            "Mismatched number of AssertCommit connectors and inputs",
        ));
    }
    let mut wots_32_num = 0;
    let mut wots_16_num = 0;
    let nguest = assertions.0.len();
    let npub = assertions.1 .0.len();
    let n32 = assertions.1 .1.len();
    let n16 = assertions.1 .2.len();
    for acc in assert_commit_connectors.iter() {
        wots_32_num += acc.wots32_pubkeys.len();
        wots_16_num += acc.wots16_pubkeys.len();
    }
    if (wots_32_num + wots_16_num) != wots_secret_keys.len() {
        return Err(Error::Other("Mismatched number of WOTS keys"));
    }
    if wots_32_num != nguest + npub + n32 {
        return Err(Error::Other("Mismatched number of WOTS32 assertions"));
    }
    if wots_16_num != n16 {
        return Err(Error::Other("Mismatched number of WOTS16 assertions"));
    }

    let mut res = vec![];
    let mut cur_index = 0;
    for (i, acc) in assert_commit_connectors.iter().enumerate() {
        let input_0_leaf = 0;
        let mut txin = acc.generate_taproot_leaf_tx_in(input_0_leaf, &assert_commit_inputs[i]);
        let start_index = cur_index;
        let end_index = cur_index + acc.wots32_pubkeys.len() + acc.wots16_pubkeys.len();

        let startguest = start_index.min(nguest);
        let endguest = end_index.min(nguest);

        let startpub = start_index.saturating_sub(nguest).min(npub);
        let endpub = end_index.saturating_sub(nguest).min(npub);

        let start32 = start_index.saturating_sub(npub + nguest).min(n32);
        let end32 = end_index.saturating_sub(npub + nguest).min(n32);

        let start16 = start_index.saturating_sub(nguest + npub + n32);
        let end16 = end_index.saturating_sub(nguest + npub + n32);

        cur_index = end_index;

        let wots32_sks =
            wots_secret_keys[start_index..(start_index + acc.wots32_pubkeys.len())].to_vec();
        let wots16_sks =
            wots_secret_keys[(start_index + acc.wots32_pubkeys.len())..end_index].to_vec();

        let mut wots32_values = assertions.0[startguest..endguest].to_vec();
        wots32_values.extend(assertions.1 .0[startpub..endpub].to_vec());
        wots32_values.extend(assertions.1 .1[start32..end32].to_vec());
        let wots16_values = assertions.1 .2[start16..end16].to_vec();

        match acc.generate_leaf_0_unlock_data(
            &wots32_sks,
            &wots16_sks,
            &wots32_values,
            &wots16_values,
        ) {
            Ok(unlock_data) => {
                populate_taproot_txin_witness(
                    &mut txin,
                    &acc.generate_taproot_spend_info(),
                    &acc.generate_taproot_leaf_script(0),
                    unlock_data,
                );
            }
            Err(e) => return Err(e),
        }
        res.push(txin);
    }

    Ok(res)
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertInitTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for AssertInitTransaction {
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
impl AssertInitTransaction {
    pub fn new_for_validation(
        connector_c: &ConnectorC,
        connector_d: &ConnectorD,
        assert_commit_connectors: &Vec<AssertCommitConnector>,
        input_0: &Input,
    ) -> Result<Self, Error> {
        let input_0_leaf = 0;
        let _input_0 = connector_c.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        if input_0.amount
            < Amount::from_sat(
                min_relay_fee_assert_init(assert_commit_connectors.len())
                    + (assert_commit_connectors.len() as u64 + 2) * DUST_AMOUNT,
            )
        {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let mut total_output_amount = input_0.amount
            - Amount::from_sat(min_relay_fee_assert_init(assert_commit_connectors.len()));
        let mut txouts = vec![];
        for assert_commit_connector in assert_commit_connectors {
            let commit_output = TxOut {
                value: Amount::from_sat(DUST_AMOUNT),
                script_pubkey: assert_commit_connector
                    .generate_taproot_address()
                    .script_pubkey(),
            };
            total_output_amount -= commit_output.value;
            txouts.push(commit_output);
        }
        let anchor_output = p2a_output();
        total_output_amount -= anchor_output.value;
        let output_connector_d = TxOut {
            value: total_output_amount,
            script_pubkey: connector_d.generate_taproot_address().script_pubkey(),
        };
        txouts.push(output_connector_d);
        txouts.push(anchor_output);

        Ok(AssertInitTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: txouts,
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_c.generate_taproot_leaf_script(input_0_leaf)],
        })
    }

    pub fn sign_input_0(&mut self, context: &OperatorContext, connector_c: &ConnectorC) {
        let input_index = 0;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            connector_c.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }
}
impl BaseTransaction for AssertInitTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "AssertInit"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitTimeoutTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for AssertCommitTimeoutTransaction {
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
impl AssertCommitTimeoutTransaction {
    pub fn new_for_validation(
        assert_commit_connector: &AssertCommitConnector,
        connector_d: &ConnectorD,
        input_0: &Input,
        input_1: &Input,
    ) -> Self {
        let input_0_leaf = 1;
        let _input_0 = assert_commit_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 1;
        let _input_1 = connector_d.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        let output_0 = p2a_output();

        AssertCommitTimeoutTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![output_0],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: assert_commit_connector
                        .generate_taproot_address()
                        .script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: connector_d.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                assert_commit_connector.generate_taproot_leaf_script(input_0_leaf),
                connector_d.generate_taproot_leaf_script(input_1_leaf),
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
        assert_commit_connector: &AssertCommitConnector,
        input_0_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = assert_commit_connector.generate_taproot_spend_info();
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
        connector_d: &ConnectorD,
        input_1_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 1;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_d.generate_taproot_spend_info();
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
        assert_commit_connector: &AssertCommitConnector,
        connector_d: &ConnectorD,
        pre_sigs: [bitcoin::taproot::Signature; 2],
    ) {
        self.push_input_0_signature(assert_commit_connector, pre_sigs[0].clone());
        self.push_input_1_signature(connector_d, pre_sigs[1].clone());
    }
}
impl BaseTransaction for AssertCommitTimeoutTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "AssertCommitTimeout"
    }
}

#[test]
fn test_operator_commit_proof() {
    use crate::connectors::assert_connectors::generate_chunked_assert_commit_connectors;
    use crate::disprove_scripts::NUM_GUEST_PUBS_ASSERT;
    use bitcoin::{Network, XOnlyPublicKey};
    use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
    use bitvm::signatures::{WinternitzSecret, Wots, Wots16, Wots32};
    use std::str::FromStr;
    let test_assertions: AssertAssertions = (
        [[0u8; 32]; NUM_GUEST_PUBS_ASSERT],
        (
            [[1u8; 32]; NUM_PUBS],
            [[2u8; 32]; NUM_U256],
            [[3u8; 16]; NUM_HASH],
        ),
    );
    let guest_privkeys = (0..NUM_GUEST_PUBS_ASSERT)
        .map(|_| Wots32::generate_secret_key())
        .collect::<Vec<WinternitzSecret>>();
    let pub_privkeys = (0..NUM_PUBS)
        .map(|_| Wots32::generate_secret_key())
        .collect::<Vec<WinternitzSecret>>();
    let u32_privkeys = (0..NUM_U256)
        .map(|_| Wots32::generate_secret_key())
        .collect::<Vec<WinternitzSecret>>();
    let hash_privkeys = (0..NUM_HASH)
        .map(|_| Wots16::generate_secret_key())
        .collect::<Vec<WinternitzSecret>>();
    let guest_pubkeys = guest_privkeys
        .iter()
        .map(|sk| Wots32::generate_public_key(sk))
        .collect::<Vec<<Wots32 as Wots>::PublicKey>>();
    let pub_pubkeys = pub_privkeys
        .iter()
        .map(|sk| Wots32::generate_public_key(sk))
        .collect::<Vec<<Wots32 as Wots>::PublicKey>>();
    let u32_pubkeys = u32_privkeys
        .iter()
        .map(|sk| Wots32::generate_public_key(sk))
        .collect::<Vec<<Wots32 as Wots>::PublicKey>>();
    let hash_pubkeys = hash_privkeys
        .iter()
        .map(|sk| Wots16::generate_public_key(sk))
        .collect::<Vec<<Wots16 as Wots>::PublicKey>>();
    let assert_commit_connector = generate_chunked_assert_commit_connectors(
        Network::Regtest,
        &XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
        (
            guest_pubkeys.try_into().unwrap(),
            (
                pub_pubkeys.try_into().unwrap(),
                u32_pubkeys.try_into().unwrap(),
                hash_pubkeys.try_into().unwrap(),
            ),
        ),
    );
    let test_input = Input {
        outpoint: bitcoin::OutPoint {
            txid: bitcoin::Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            vout: 0,
        },
        amount: bitcoin::Amount::from_sat(0),
    };
    let test_inputs = std::iter::repeat(test_input)
        .take(assert_commit_connector.len())
        .collect::<Vec<Input>>();
    let res = operator_commit_proof(
        &assert_commit_connector,
        &[guest_privkeys, pub_privkeys, u32_privkeys, hash_privkeys].concat(),
        &test_inputs,
        &test_assertions,
    )
    .unwrap();
    println!("num txins: {:?}", res.len());
}
