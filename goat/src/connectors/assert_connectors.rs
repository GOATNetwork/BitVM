use super::{super::transactions::base::Input, base::*};
use crate::{
    constants::ASSERT_COMMIT_TIMELOCK,
    disprove_scripts::AssertPubkeys as AssertWotsPublicKeys,
    error::Error,
    scripts::generate_timelock_taproot_script,
    utils::{num_blocks_per_network, remove_script_and_control_block_from_witness},
};
use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, Witness, XOnlyPublicKey,
};
use bitvm::{
    chunk::api::type_conversion_utils::RawWitness,
    signatures::{
        signing_winternitz::WinternitzPublicKey, CompactWots, WinternitzSecret, Wots, Wots32,
    },
};
use bitvm::{signatures::Wots16, treepp::*};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommitConnector {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub wots32_pubkeys: Vec<WinternitzPublicKey>,
    pub wots16_pubkeys: Vec<WinternitzPublicKey>,
    pub assert_commit_blocks_timelock: u32,
}

impl AssertCommitConnector {
    pub fn new(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        wots32_pubkeys: &Vec<<Wots32 as Wots>::PublicKey>,
        wots16_pubkeys: &Vec<<Wots16 as Wots>::PublicKey>,
    ) -> Self {
        let wots32_pubkeys = wots32_pubkeys
            .iter()
            .map(|pk| WinternitzPublicKey {
                public_key: pk.to_vec(),
                parameters: <Wots32 as Wots>::PARAMETERS,
            })
            .collect::<Vec<WinternitzPublicKey>>();
        let wots16_pubkeys = wots16_pubkeys
            .iter()
            .map(|pk| WinternitzPublicKey {
                public_key: pk.to_vec(),
                parameters: <Wots16 as Wots>::PARAMETERS,
            })
            .collect::<Vec<WinternitzPublicKey>>();
        AssertCommitConnector {
            network,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            wots32_pubkeys,
            wots16_pubkeys,
            assert_commit_blocks_timelock: num_blocks_per_network(network, ASSERT_COMMIT_TIMELOCK),
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        let wots32_pubkeys = self
            .wots32_pubkeys
            .iter()
            .map(|pk| pk.public_key.as_slice().try_into().unwrap())
            .collect::<Vec<<Wots32 as Wots>::PublicKey>>();
        let wots16_pubkeys = self
            .wots16_pubkeys
            .iter()
            .map(|pk| pk.public_key.as_slice().try_into().unwrap())
            .collect::<Vec<<Wots16 as Wots>::PublicKey>>();
        script! {
            for pk in wots16_pubkeys.iter().rev() {
            { Wots16::checksig_verify_and_clear_stack(&pk) }
            }
            for pk in wots32_pubkeys.iter().rev() {
            { Wots32::checksig_verify_and_clear_stack(&pk) }
            }
            OP_TRUE
        }
        .compile()
    }

    pub fn generate_leaf_0_unlock_data(
        &self,
        wots32_secret_keys: &Vec<WinternitzSecret>,
        wots16_secret_keys: &Vec<WinternitzSecret>,
        wots32_values: &Vec<[u8; 32]>,
        wots16_values: &Vec<[u8; 16]>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        fn append_witness(a: &mut Witness, b: Witness) {
            for item in b.into_iter() {
                a.push(item);
            }
        }

        if wots32_secret_keys.len() != self.wots32_pubkeys.len()
            || wots16_secret_keys.len() != self.wots16_pubkeys.len()
            || wots32_values.len() != self.wots32_pubkeys.len()
            || wots16_values.len() != self.wots16_pubkeys.len()
        {
            return Err(Error::Other(
                "The length of WOTS secret-keys or values does not match the length of public-keys.",
            ));
        };

        let mut witness = Witness::new();
        for (i, sk) in wots32_secret_keys.iter().enumerate() {
            let wit = Wots32::sign_to_raw_witness(sk, &wots32_values[i]);
            append_witness(&mut witness, wit);
        }
        for (i, sk) in wots16_secret_keys.iter().enumerate() {
            let wit = Wots16::sign_to_raw_witness(sk, &wots16_values[i]);
            append_witness(&mut witness, wit);
        }

        let witness_script = script! {
            { witness.clone() }
        };
        let verification_script = witness_script.push_script(self.generate_taproot_leaf_0_script());
        let exec_result = execute_script(verification_script);
        match exec_result.success {
            true => Ok(witness.to_vec()),
            false => Err(Error::Other(
                "Invalid WOTS secret-key for Assert Commit Connector.",
            )),
        }
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        generate_timelock_taproot_script(
            &self.n_of_n_taproot_public_key,
            self.assert_commit_blocks_timelock,
        )
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.assert_commit_blocks_timelock)
    }
}

impl TaprootConnector for AssertCommitConnector {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            1 => self.generate_taproot_leaf_1_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            1 => self.generate_taproot_leaf_1_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .add_leaf(1, self.generate_taproot_leaf_1_script())
            .expect("Unable to add leaf 1")
            .finalize(SECP256K1, self.n_of_n_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}

pub fn extract_commits_from_txin(
    input: &TxIn,
    wots32_num: usize,
    wots16_num: usize,
) -> Result<Vec<RawWitness>, Error> {
    let mut res = Vec::new();
    let witness = remove_script_and_control_block_from_witness(input.witness.to_vec());
    let (wots32_witness_size, wots16_witness_size) = (
        Wots32::TOTAL_DIGIT_LEN as usize * 2,
        Wots16::TOTAL_DIGIT_LEN as usize * 2,
    );
    let expected_witness_size = wots32_witness_size * wots32_num + wots16_witness_size * wots16_num;
    if expected_witness_size != witness.len() {
        return Err(Error::Other(
            "Invalid witness size for Assert Commit Connector.",
        ));
    }
    for i in 0..wots32_num {
        let start = i * wots32_witness_size;
        let end = start + wots32_witness_size;
        res.push(witness[start..end].to_vec());
    }
    for i in 0..wots16_num {
        let start = wots32_witness_size * wots32_num + i * wots16_witness_size;
        let end = start + wots16_witness_size;
        res.push(witness[start..end].to_vec());
    }
    Ok(res)
}

pub fn extract_commits_from_txins(
    inputs: Vec<TxIn>,
    wots32_num: usize,
    wots16_num: usize,
) -> Result<Vec<RawWitness>, Error> {
    let mut sorted_inputs = inputs;
    sorted_inputs.sort_by_key(|txin| txin.previous_output.vout);
    let mut res = vec![];
    let use_compact_wots = false;
    let chunks = chunk_assert_commit(wots32_num, wots16_num, use_compact_wots);
    for (i, input) in sorted_inputs.into_iter().enumerate() {
        let (start, len) = chunks[i];
        let end = start + len;

        let chunk_wots32_num = end.min(wots32_num).saturating_sub(start.min(wots32_num));
        let chunk_wots16_num = end
            .saturating_sub(wots32_num)
            .saturating_sub(start.saturating_sub(wots32_num));

        let mut chunk_commits =
            extract_commits_from_txin(&input, chunk_wots32_num, chunk_wots16_num)?;
        res.append(&mut chunk_commits);
    }
    Ok(res)
}

pub fn generate_chunked_assert_commit_connectors(
    network: Network,
    n_of_n_taproot_public_key: &XOnlyPublicKey,
    wots_keys: AssertWotsPublicKeys,
) -> Vec<AssertCommitConnector> {
    let mut wots32_pubkeys = wots_keys.0.to_vec();
    wots32_pubkeys.extend(wots_keys.1 .0.to_vec());
    wots32_pubkeys.extend(wots_keys.1 .1.to_vec());
    let wots16_pubkeys = wots_keys.1 .2.to_vec();

    let use_compact_wots = false;
    let chunks = chunk_assert_commit(wots32_pubkeys.len(), wots16_pubkeys.len(), use_compact_wots);
    let mut connectors = vec![];
    let n32 = wots32_pubkeys.len();
    for (start_index, wots_num) in chunks {
        let end_index = start_index + wots_num;

        let start32 = start_index.min(n32);
        let end32 = end_index.min(n32);

        let start16 = start_index.saturating_sub(n32);
        let end16 = end_index.saturating_sub(n32);

        let chunk32 = wots32_pubkeys[start32..end32].to_vec();
        let chunk16 = wots16_pubkeys[start16..end16].to_vec();

        let connector =
            AssertCommitConnector::new(network, n_of_n_taproot_public_key, &chunk32, &chunk16);
        connectors.push(connector);
    }
    connectors
}

// return Vec<(start_index, wots_num)>
pub fn chunk_assert_commit(
    wots32_num: usize,
    wots16_num: usize,
    use_compact_wots: bool,
) -> Vec<(usize, usize)> {
    // let (wots32_witness_max_stack_items, wots16_witness_max_stack_items, runtime_extra_stack_items) = wots_stack_size(use_compact_wots);
    let (wots32_witness_max_stack_items, wots16_witness_max_stack_items, runtime_extra_stack_items) =
        precomputed_wots_stack_size(use_compact_wots);
    let max_stack_limit: usize = 1000;

    let max_pure_wot32_num =
        (max_stack_limit - runtime_extra_stack_items) / wots32_witness_max_stack_items;
    let max_pure_wot16_num =
        (max_stack_limit - runtime_extra_stack_items) / wots16_witness_max_stack_items;

    let mut res = vec![];
    let mut cur_index = 0;
    for _ in 0..(wots32_num / max_pure_wot32_num) {
        res.push((cur_index, max_pure_wot32_num));
        cur_index += max_pure_wot32_num;
    }

    let remaining_wots32_num = wots32_num % max_pure_wot32_num;
    let mut remaining_wots16_num = wots16_num;
    if remaining_wots32_num != 0 {
        let append_wots16_num = (max_stack_limit
            - runtime_extra_stack_items
            - remaining_wots32_num * wots32_witness_max_stack_items)
            / wots16_witness_max_stack_items;
        res.push((cur_index, append_wots16_num + remaining_wots32_num));
        cur_index += append_wots16_num + remaining_wots32_num;
        remaining_wots16_num -= append_wots16_num;
    }

    for _ in 0..(remaining_wots16_num / max_pure_wot16_num) {
        res.push((cur_index, max_pure_wot16_num));
        cur_index += max_pure_wot16_num;
    }

    let remaining_wots16_num = remaining_wots16_num % max_pure_wot16_num;
    if remaining_wots16_num != 0 {
        res.push((cur_index, remaining_wots16_num));
    }

    res
}

#[allow(dead_code)]
fn precomputed_wots_stack_size(use_compact_wots: bool) -> (usize, usize, usize) {
    if use_compact_wots {
        (68, 36, 5)
    } else {
        (136, 72, 9)
    }
}

#[allow(dead_code)]
fn wots_stack_size(use_compact_wots: bool) -> (usize, usize, usize) {
    let privkey32 = Wots32::generate_secret_key();
    let pubkey32 = Wots32::generate_public_key(&privkey32);
    let msg32 = [1u8; 32];

    let privkey16 = Wots16::generate_secret_key();
    let pubkey16 = Wots16::generate_public_key(&privkey16);
    let msg16 = [1u8; 16];

    if use_compact_wots {
        // Wots32
        let witness = Wots32::compact_sign_to_raw_witness(&privkey32, &msg32);
        let witness_script = script! {
            { witness.clone() }
        };
        let exec_result = execute_script(witness_script);
        let wots32_witness_stack_size = exec_result.stats.max_nb_stack_items;
        let lock_script = script! {
            { witness.clone() }
            { Wots32::compact_checksig_verify_and_clear_stack(&pubkey32) }
        };
        let exec_result = execute_script(lock_script);
        let wots32_full_script_stack_size = exec_result.stats.max_nb_stack_items;
        let wots32_runtime_extra_stack_items =
            wots32_full_script_stack_size - wots32_witness_stack_size;

        // Wots16
        let witness = Wots16::compact_sign_to_raw_witness(&privkey16, &msg16);
        let witness_script = script! {
            { witness.clone() }
        };
        let exec_result = execute_script(witness_script);
        let wots16_witness_stack_size = exec_result.stats.max_nb_stack_items;
        let lock_script = script! {
            { witness.clone() }
            { Wots16::compact_checksig_verify_and_clear_stack(&pubkey16) }
        };
        let exec_result = execute_script(lock_script);
        let wots16_full_script_stack_size = exec_result.stats.max_nb_stack_items;
        let wots16_runtime_extra_stack_items =
            wots16_full_script_stack_size - wots16_witness_stack_size;

        (
            wots32_witness_stack_size,
            wots16_witness_stack_size,
            std::cmp::max(
                wots32_runtime_extra_stack_items,
                wots16_runtime_extra_stack_items,
            ),
        )
    } else {
        // Wots32
        let witness = Wots32::sign_to_raw_witness(&privkey32, &msg32);
        let witness_script = script! {
            { witness.clone() }
        };
        let exec_result = execute_script(witness_script);
        let wots32_witness_stack_size = exec_result.stats.max_nb_stack_items;
        let lock_script = script! {
            { witness.clone() }
            { Wots32::checksig_verify_and_clear_stack(&pubkey32) }
        };
        let exec_result = execute_script(lock_script);
        let wots32_full_script_stack_size = exec_result.stats.max_nb_stack_items;
        let wots32_runtime_extra_stack_items =
            wots32_full_script_stack_size - wots32_witness_stack_size;

        // Wots16
        let witness = Wots16::sign_to_raw_witness(&privkey16, &msg16);
        let witness_script = script! {
            { witness.clone() }
        };
        let exec_result = execute_script(witness_script);
        let wots16_witness_stack_size = exec_result.stats.max_nb_stack_items;
        let lock_script = script! {
            { witness.clone() }
            { Wots16::checksig_verify_and_clear_stack(&pubkey16) }
        };
        let exec_result = execute_script(lock_script);
        let wots16_full_script_stack_size = exec_result.stats.max_nb_stack_items;
        let wots16_runtime_extra_stack_items =
            wots16_full_script_stack_size - wots16_witness_stack_size;

        (
            wots32_witness_stack_size,
            wots16_witness_stack_size,
            std::cmp::max(
                wots32_runtime_extra_stack_items,
                wots16_runtime_extra_stack_items,
            ),
        )
    }
}

#[test]
fn test_wots_stack_size() {
    assert_eq!(wots_stack_size(true), precomputed_wots_stack_size(true));
    assert_eq!(wots_stack_size(false), precomputed_wots_stack_size(false));
}

#[test]
fn test_assert_commit_connector_leaf_0() {
    fn run(wots32_num: usize, wots16_num: usize) {
        let secp = &SECP256K1;
        let mut rng = rand::thread_rng();
        let kp = bitcoin::key::Keypair::new(secp, &mut rng);
        let (xonly_pk, _) = XOnlyPublicKey::from_keypair(&kp);

        let wots32_privkeys = (0..wots32_num)
            .map(|_| Wots32::generate_secret_key())
            .collect::<Vec<WinternitzSecret>>();
        let wots16_privkeys = (0..wots16_num)
            .map(|_| Wots16::generate_secret_key())
            .collect::<Vec<WinternitzSecret>>();
        let wots32_pubkeys = wots32_privkeys
            .iter()
            .map(|sk| Wots32::generate_public_key(sk))
            .collect::<Vec<<Wots32 as Wots>::PublicKey>>();
        let wots16_pubkeys = wots16_privkeys
            .iter()
            .map(|sk| Wots16::generate_public_key(sk))
            .collect::<Vec<<Wots16 as Wots>::PublicKey>>();
        let wots32_values = (0..wots32_num)
            .map(|i| [i as u8; 32])
            .collect::<Vec<[u8; 32]>>();
        let wots16_values = (0..wots16_num)
            .map(|i| [i as u8; 16])
            .collect::<Vec<[u8; 16]>>();

        let connector = AssertCommitConnector::new(
            Network::Regtest,
            &xonly_pk,
            &wots32_pubkeys,
            &wots16_pubkeys,
        );

        let unlock_data = connector
            .generate_leaf_0_unlock_data(
                &wots32_privkeys,
                &wots16_privkeys,
                &wots32_values,
                &wots16_values,
            )
            .unwrap();

        let witness_script = script! {
            { unlock_data }
        };
        let verification_script =
            witness_script.push_script(connector.generate_taproot_leaf_0_script());
        let exec_result = execute_script(verification_script);
        assert_eq!(exec_result.success, true);
    }
    run(7, 0);
    run(2, 9);
    run(0, 13);
}
