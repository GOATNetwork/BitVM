use bitcoin::{
    hashes::{sha256, Hash},
    key::Keypair,
    taproot::TaprootSpendInfo,
    PublicKey, TapSighashType, XOnlyPublicKey,
};
use musig2::{
    secp::MaybeScalar,
    secp256k1::{schnorr::Signature, Message},
    BinaryEncoding, PartialSignature, PubNonce, SecNonce,
};
use std::collections::HashMap;

use super::{
    super::contexts::{base::BaseContext, verifier::VerifierContext},
    super::error::Error,
    pre_signed::PreSignedTransaction,
    signing::push_taproot_leaf_script_and_control_block_to_witness,
    signing_musig2::{
        generate_aggregated_nonce, generate_nonce, generate_taproot_aggregated_signature,
        generate_taproot_partial_signature,
    },
};

pub fn generate_nonce_and_sign(signer_keypair: Keypair) -> (SecNonce, PubNonce, Signature) {
    let secret_nonce = generate_nonce();
    let public_nonce = secret_nonce.public_nonce();
    let nonce_signature =
        signer_keypair.sign_schnorr(get_nonce_message(&secret_nonce.public_nonce()));
    (secret_nonce, public_nonce, nonce_signature)
}

pub trait PreSignedMusig2Transaction: PreSignedTransaction {
    fn musig2_nonces(&self) -> &HashMap<usize, HashMap<PublicKey, PubNonce>>;
    fn musig2_nonces_mut(&mut self) -> &mut HashMap<usize, HashMap<PublicKey, PubNonce>>;
    fn musig2_nonce_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, Signature>>;
    fn musig2_nonce_signatures_mut(&mut self)
        -> &mut HashMap<usize, HashMap<PublicKey, Signature>>;
    fn musig2_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, PartialSignature>>;
    fn musig2_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, PartialSignature>>;
    fn verifier_inputs(&self) -> Vec<usize>;
    fn has_nonces_for(&self, verifier_pubkey: PublicKey) -> bool {
        self.has_all_nonces(&[verifier_pubkey])
    }
    fn has_all_nonces(&self, verifier_pubkeys: &[PublicKey]) -> bool {
        self.verifier_inputs().into_iter().all(|input_index| {
            verifier_pubkeys.iter().all(|pubkey| {
                self.musig2_nonces().contains_key(&input_index)
                    && self.musig2_nonces()[&input_index].contains_key(pubkey)
            })
        })
    }
    fn has_signatures_for(&self, verifier_pubkey: PublicKey) -> bool {
        self.has_all_signatures(&[verifier_pubkey])
    }
    fn has_all_signatures(&self, verifier_pubkeys: &[PublicKey]) -> bool {
        self.verifier_inputs().into_iter().all(|input_index| {
            verifier_pubkeys.iter().all(|pubkey| {
                self.musig2_signatures().contains_key(&input_index)
                    && self.musig2_signatures()[&input_index].contains_key(pubkey)
            })
        })
    }

    fn push_nonces(&mut self, context: &VerifierContext) -> HashMap<usize, SecNonce> {
        self.verifier_inputs()
            .iter()
            .map(|input_index| (*input_index, self.push_nonce(context, *input_index)))
            .collect()
    }

    fn push_nonce(&mut self, context: &VerifierContext, input_index: usize) -> SecNonce {
        // Push nonce
        let musig2_nonces = self.musig2_nonces_mut();
        if musig2_nonces.get(&input_index).is_none() {
            musig2_nonces.insert(input_index, HashMap::new());
        }

        let secret_nonce = generate_nonce();
        musig2_nonces
            .get_mut(&input_index)
            .unwrap()
            .insert(context.verifier_public_key, secret_nonce.public_nonce());

        // Sign the nonce and push the signature
        let musig2_nonce_signatures = self.musig2_nonce_signatures_mut();
        if musig2_nonce_signatures.get(&input_index).is_none() {
            musig2_nonce_signatures.insert(input_index, HashMap::new());
        }

        let nonce_signature = context
            .verifier_keypair
            .sign_schnorr(get_nonce_message(&secret_nonce.public_nonce()));

        musig2_nonce_signatures
            .get_mut(&input_index)
            .unwrap()
            .insert(context.verifier_public_key, nonce_signature);

        secret_nonce
    }

    fn push_nonces_with_sigs(
        &mut self,
        verifier_pubkey: &PublicKey,
        nonces_with_sigs: &HashMap<usize, (PubNonce, Signature)>,
    ) -> Option<Error> {
        for index in self.verifier_inputs() {
            let (pub_nonce, nonce_signature) = match nonces_with_sigs.get(&index) {
                Some(v) => v,
                _ => return Some(Error::Other("PubNonce for {index}'th input not found")),
            };
            if !verify_public_nonce(
                nonce_signature,
                pub_nonce,
                &XOnlyPublicKey::from(*verifier_pubkey),
            ) {
                return Some(Error::Other(
                    "invalid nonce signature for PubNonce of {index}'th input",
                ));
            }

            // push pub_nonce
            let musig2_nonces = self.musig2_nonces_mut();
            if musig2_nonces.get(&index).is_none() {
                musig2_nonces.insert(index, HashMap::new());
            }
            musig2_nonces
                .get_mut(&index)
                .unwrap()
                .insert(*verifier_pubkey, pub_nonce.clone());

            // push pub_nonce_signature
            let musig2_nonce_signatures = self.musig2_nonce_signatures_mut();
            if musig2_nonce_signatures.get(&index).is_none() {
                musig2_nonce_signatures.insert(index, HashMap::new());
            }
            musig2_nonce_signatures
                .get_mut(&index)
                .unwrap()
                .insert(*verifier_pubkey, nonce_signature.clone());
        }
        None
    }

    fn push_partial_signatures(
        &mut self,
        verifier_pubkey: &PublicKey,
        partial_sigs: &HashMap<usize, PartialSignature>,
    ) -> Option<Error> {
        for index in self.verifier_inputs() {
            let partial_signature = match partial_sigs.get(&index) {
                Some(v) => v,
                _ => {
                    return Some(Error::Other(
                        "partial signature for {index}'th input not found",
                    ))
                }
            };

            let musig2_signatures = self.musig2_signatures_mut();
            if musig2_signatures.get(&index).is_none() {
                musig2_signatures.insert(index, HashMap::new());
            }
            musig2_signatures
                .get_mut(&index)
                .unwrap()
                .insert(*verifier_pubkey, *partial_signature);
        }
        None
    }
}

pub fn get_nonce_message(nonce: &PubNonce) -> Message {
    let nonce_hash = sha256::Hash::hash(nonce.to_bytes().as_slice());
    Message::from_digest_slice(nonce_hash.as_ref()).expect("Failed to create nonce message")
}

fn verify_schnorr_signature(sig: &Signature, msg: &Message, pubkey: &XOnlyPublicKey) -> bool {
    match sig.verify(msg, pubkey) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("verify_schnorr() failed with: {e}");
            false
        }
    }
}

pub fn verify_public_nonce(sig: &Signature, nonce: &PubNonce, pubkey: &XOnlyPublicKey) -> bool {
    verify_schnorr_signature(sig, &get_nonce_message(nonce), pubkey)
}

pub fn pre_sign_musig2_taproot_input<T: PreSignedTransaction + PreSignedMusig2Transaction>(
    tx: &mut T,
    context: &VerifierContext,
    input_index: usize,
    sighash_type: TapSighashType,
    secret_nonce: &SecNonce,
) {
    // TODO validate nonces first

    let prev_outs = &tx.prev_outs().clone();
    let script = &tx.prev_scripts()[input_index].clone();
    let musig2_nonces = &tx.musig2_nonces()[&input_index].values().cloned().collect();

    let partial_signature = generate_taproot_partial_signature(
        context,
        tx.tx_mut(),
        secret_nonce,
        &generate_aggregated_nonce(musig2_nonces),
        input_index,
        prev_outs,
        script,
        sighash_type,
    )
    .unwrap(); // TODO: Add error handling.

    let musig2_signatures = tx.musig2_signatures_mut();
    if musig2_signatures.get(&input_index).is_none() {
        musig2_signatures.insert(input_index, HashMap::new());
    }
    musig2_signatures
        .get_mut(&input_index)
        .unwrap()
        .insert(context.verifier_public_key, partial_signature);
}

pub fn finalize_musig2_taproot_input<T: PreSignedTransaction + PreSignedMusig2Transaction>(
    tx: &mut T,
    context: &dyn BaseContext,
    input_index: usize,
    sighash_type: TapSighashType,
    taproot_spend_info: TaprootSpendInfo,
) {
    // TODO: Verify we have partial signatures from all verifiers.
    // TODO: Verify each signature against the signers public key.
    // See example here: https://github.com/conduition/musig2/blob/c39bfce58098d337a3ec38b54d93def8306d9953/src/signing.rs#L358C1-L366C65

    let prev_outs = &tx.prev_outs().clone();
    let script = &tx.prev_scripts()[input_index].clone();
    let musig2_nonces: &Vec<PubNonce> =
        &tx.musig2_nonces()[&input_index].values().cloned().collect();
    let musig2_signatures: Vec<MaybeScalar> = tx.musig2_signatures()[&input_index]
        .values()
        .map(|&partial_signature| PartialSignature::from(partial_signature))
        .collect();
    let tx_mut = tx.tx_mut();

    // Aggregate signature
    let signature = generate_taproot_aggregated_signature(
        context,
        tx_mut,
        &generate_aggregated_nonce(musig2_nonces),
        input_index,
        prev_outs,
        script,
        sighash_type,
        musig2_signatures, // TODO: Is there a more elegant way of doing this?
    )
    .unwrap(); // TODO: Add error handling.

    let final_signature = bitcoin::taproot::Signature {
        signature: signature.into(),
        sighash_type,
    };

    // Push signature to witness
    tx_mut.input[input_index]
        .witness
        .push(final_signature.serialize());

    // Push script + control block
    push_taproot_leaf_script_and_control_block_to_witness(
        tx_mut,
        input_index,
        &taproot_spend_info,
        script,
    );
}

#[test]
fn test_musig2() {
    use super::super::connectors::{
        connector_0::Connector0, connector_3::Connector3, connector_a::ConnectorA,
    };
    use super::super::contexts::{
        base::generate_keys_from_secret, operator::OperatorContext, verifier::VerifierContext,
    };
    use super::{base::Input, take_1::Take1Transaction};
    use bitcoin::{
        sighash::{Prevouts, SighashCache},
        taproot::LeafVersion,
        Amount, Network, OutPoint, PublicKey, TapLeafHash, Txid,
    };
    use std::str::FromStr;

    let source_network = Network::Testnet;
    const OPERATOR_SECRET: &str =
        "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac";
    const VERIFIER_0_SECRET: &str =
        "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2";
    const VERIFIER_1_SECRET: &str =
        "fc294c70faf210d4d0807ea7a3dba8f7e41700d90c119e1ae82a0687d89d297f";

    let (_, verifier_0_public_key) = generate_keys_from_secret(source_network, VERIFIER_0_SECRET);
    let (_, verifier_1_public_key) = generate_keys_from_secret(source_network, VERIFIER_1_SECRET);
    let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
    n_of_n_public_keys.push(verifier_0_public_key);
    n_of_n_public_keys.push(verifier_1_public_key);

    let operator_context =
        OperatorContext::new(source_network, OPERATOR_SECRET, &n_of_n_public_keys);
    let verifier_0_context =
        VerifierContext::new(source_network, VERIFIER_0_SECRET, &n_of_n_public_keys);
    let verifier_1_context =
        VerifierContext::new(source_network, VERIFIER_1_SECRET, &n_of_n_public_keys);

    let connector_0 = Connector0::new(
        source_network,
        &verifier_0_context.n_of_n_taproot_public_key,
    );
    let connector_3 = Connector3::new(source_network, &operator_context.operator_public_key);
    let connector_a = ConnectorA::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &verifier_0_context.n_of_n_taproot_public_key,
    );
    let mock_input = Input {
        outpoint: OutPoint {
            txid: Txid::from_str(
                "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            )
            .unwrap(),
            vout: 0,
        },
        amount: Amount::from_sat(100000),
    };

    let mut take_1 = Take1Transaction::new_for_validation(
        source_network,
        &operator_context.operator_public_key,
        &connector_0,
        &connector_3,
        &connector_a,
        mock_input.clone(),
        mock_input.clone(),
        mock_input.clone(),
    );
    let pre_sign_input_index = 0;
    let sighash_type = TapSighashType::All;

    let (sec_nonce_0, pub_nonce_0, _) =
        generate_nonce_and_sign(verifier_0_context.verifier_keypair);
    let (sec_nonce_1, pub_nonce_1, _) =
        generate_nonce_and_sign(verifier_1_context.verifier_keypair);
    let agg_nonce = generate_aggregated_nonce(&vec![pub_nonce_0, pub_nonce_1]);

    let partial_sig_0 = generate_taproot_partial_signature(
        &verifier_0_context,
        take_1.tx(),
        &sec_nonce_0,
        &agg_nonce,
        pre_sign_input_index,
        take_1.prev_outs(),
        &take_1.prev_scripts()[pre_sign_input_index],
        sighash_type,
    )
    .unwrap();
    let partial_sig_1 = generate_taproot_partial_signature(
        &verifier_1_context,
        take_1.tx(),
        &sec_nonce_1,
        &agg_nonce,
        pre_sign_input_index,
        take_1.prev_outs(),
        &take_1.prev_scripts()[pre_sign_input_index],
        sighash_type,
    )
    .unwrap();

    let agg_sig = generate_taproot_aggregated_signature(
        &operator_context,
        take_1.tx(),
        &agg_nonce,
        pre_sign_input_index,
        take_1.prev_outs(),
        &take_1.prev_scripts()[pre_sign_input_index],
        sighash_type,
        vec![partial_sig_0, partial_sig_1],
    )
    .unwrap();

    let final_signature = bitcoin::taproot::Signature {
        signature: agg_sig.into(),
        sighash_type,
    };

    take_1.push_pre_sigs(&connector_0, final_signature);

    let leaf_hash = TapLeafHash::from_script(
        &take_1.prev_scripts()[pre_sign_input_index],
        LeafVersion::TapScript,
    );
    let prevouts = take_1.prev_outs().clone();
    let prevouts = Prevouts::All(&prevouts);
    let sighash = SighashCache::new(take_1.tx_mut())
        .taproot_script_spend_signature_hash(
            pre_sign_input_index,
            &prevouts,
            leaf_hash,
            sighash_type,
        )
        .expect("Failed to construct sighash");
    let success = verify_schnorr_signature(
        &final_signature.signature,
        &Message::from(sighash),
        &operator_context.n_of_n_taproot_public_key,
    );
    assert!(success);
}
