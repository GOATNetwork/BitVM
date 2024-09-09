use crate::treepp::*;
use crate::signatures::winternitz::{self, PublicKey};
use crate::signatures::winternitz_hash;
use bitcoin::hashes::{hash160, Hash};

pub fn seed_to_secret(seed: &[u8]) -> [u8; 20] {
    let hash = hash160::Hash::hash(&seed);

    hash.to_byte_array()
}

pub fn seed_to_pubkey(seed: &[u8]) -> PublicKey {
    let secret = seed_to_secret(seed);
    let secret = hex::encode(secret);

    winternitz::generate_public_key(secret.as_str())
}

pub fn sign_hash(sec_key: &[u8; 20], message: &[u8]) -> Script {
    let sec_key = hex::encode(sec_key.clone());
    winternitz_hash::sign_hash(&sec_key, message)
}

// final_stack would be empty
pub fn check_hash_sig(public_key: &PublicKey, input_len: usize) -> Script {
    winternitz_hash::check_hash_sig(public_key, input_len)
}

// all inputs will be kept in the final stack
pub fn check_hash_sig_dup_all(public_key: &PublicKey, input_len: usize) -> Script {
    winternitz_hash::check_hash_sig_dup_all(public_key, input_len)
}

// first input will be kept in the final stack
pub fn check_hash_sig_dup_top(public_key: &PublicKey, input_len: usize, num: usize) -> Script {
    winternitz_hash::check_hash_sig_dup_top(public_key, input_len, num)
}