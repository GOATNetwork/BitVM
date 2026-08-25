use crate::connectors::base::generate_default_tx_in;
use crate::disprove_scripts::{
    utils_signatures_from_raw_witnesses, validate_guest_assertions, GUEST_VALIDATION_TAPS,
};
use crate::{error::Error, transactions::base::Input};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use bitcoin::taproot::LeafVersion;
use bitcoin::{taproot::TaprootSpendInfo, ScriptBuf, TxIn};
use bitvm::chunk::api::type_conversion_utils::script_to_witness;
use bitvm::chunk::api::validate_assertions_lit;
use bitvm::chunk::api::{type_conversion_utils::RawWitness, NUM_TAPS};

pub fn validate_assert(
    raw_commit_blockhash_witness: Vec<RawWitness>,
    raw_assert_witness: Vec<RawWitness>,
    ack_preimages: Vec<Vec<u8>>, // preimages length should match the number of hashes, use empty vec for unknown preimages
    guest_validation_scripts: &[ScriptBuf; GUEST_VALIDATION_TAPS],
    vk: &VerifyingKey<Bn254>,
    proof_validation_scripts: &[ScriptBuf; NUM_TAPS],
) -> Option<(RawWitness, ScriptBuf)> {
    let mut raw_wits = raw_commit_blockhash_witness;
    raw_wits.extend(raw_assert_witness);
    let wots_sigs = utils_signatures_from_raw_witnesses(&raw_wits);

    if let Some((index, wit)) = validate_guest_assertions(
        &wots_sigs.0,
        &wots_sigs.1 .0.clone(),
        &ack_preimages,
        guest_validation_scripts,
    ) {
        return Some((
            script_to_witness(wit),
            guest_validation_scripts[index].clone(),
        ));
    };
    if let Some((index, wit)) = validate_assertions_lit(vk, wots_sigs.1, proof_validation_scripts) {
        return Some((
            script_to_witness(wit),
            proof_validation_scripts[index].clone(),
        ));
    };
    None
}

pub fn disprove(
    connector_e_taproot_spend_info: &TaprootSpendInfo,
    connector_e_input: &Input,
    input_script_witness: RawWitness,
    input_lock_script: ScriptBuf,
) -> Result<TxIn, Error> {
    let mut txin = generate_default_tx_in(connector_e_input);
    // push witness
    input_script_witness
        .into_iter()
        .for_each(|x| txin.witness.push(x));
    // push script and control block
    let prevout_leaf = (input_lock_script, LeafVersion::TapScript);
    let control_block = match connector_e_taproot_spend_info.control_block(&prevout_leaf) {
        Some(c) => c,
        _ => {
            return Err(Error::Other(
                "Unable to generate control block for disprove txin",
            ))
        }
    };
    txin.witness.push(prevout_leaf.0.to_bytes());
    txin.witness.push(control_block.serialize());
    Ok(txin)
}
