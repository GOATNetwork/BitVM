use crate::treepp::*;
use crate::signatures::winternitz::{self, PublicKey, checksum, to_digits, N, N1};
use crate::signatures::winternitz_hash;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::Witness;
use blake3::hash as blake3;
use hex::decode as hex_decode;
use hex::encode as hex_encode;

pub fn seed_to_secret(seed: &[u8]) -> [u8; 20] {
    let hash = hash160::Hash::hash(&seed);

    hash.to_byte_array()
}

pub fn seed_to_pubkey(seed: &[u8]) -> PublicKey {
    let secret = seed_to_secret(seed);
    let secret = hex::encode(secret);

    winternitz::generate_public_key(secret.as_str())
}

/* 
pub fn push_sig_witness(witness: &mut Witness, sec_key: &[u8; 20], message: &[u8]) {
    let secret_key = hex::encode(sec_key.clone());

    // winternitz_hash::sign_hash(&sec_key, message)
    let message_hash = blake3(message);
    let message_hash_bytes = &message_hash.as_bytes()[0..20];

    // winternitz::sign(sec_key, message_hash_bytes)
    let mut message_digits = [0u8; 20 * 2 as usize];
    for (digits, byte) in message_digits.chunks_mut(2).zip(message_hash_bytes) {
        digits[0] = byte & 0b00001111;
        digits[1] = byte >> 4;
    }

    // winternitz::sign_digits(secret_key, message_digits)
    let mut checksum_digits = to_digits::<N1>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());
    for i in 0..N {
        // winternitz::digit_signature(secret_key, i, checksum_digits[ (N-1-i) as usize]) 
        let digit_index = i;
        let message_digit = checksum_digits[ (N-1-i) as usize];
        let mut secret_i = match hex_decode(&secret_key) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string"),
        };
    
        secret_i.push(digit_index as u8);
    
        let mut hash = hash160::Hash::hash(&secret_i);
    
        for _ in 0..message_digit {
            hash = hash160::Hash::hash(&hash[..]);
        }
    
        let hash_bytes = hash.as_byte_array().to_vec();

        witness.push(hash_bytes);
        if message_digit != 0u8 {
            witness.push([message_digit as u8]);
        } else {
            witness.push([]);
        }
    };
}
*/

// first n input will be kept in the final stack
pub fn check_sig_dup(public_key: &PublicKey, input_len: usize, num: usize) -> Script {

    // winternitz_hash::check_hash_sig_dup(public_key, input_len, num)
    winternitz_hash::check_raw_sig_dup(public_key, input_len, num)
}

pub fn sign_msg(sec_key: &[u8; 20], message: &[u8]) -> Script {
    let sec_key = hex::encode(sec_key.clone());
    
    // winternitz_hash::sign_hash(&sec_key, message)
    winternitz_hash::sign_raw(&sec_key, message)
}

pub fn push_sig_witness(witness: &mut Witness, sec_key: &[u8; 20], message: &[u8]) {
    let secret_key = hex::encode(sec_key.clone());

    // winternitz_hash::push_hash_sig_witness(witness, sec_key, message);
    winternitz_hash::push_raw_sig_witness(witness, sec_key, message);
}
