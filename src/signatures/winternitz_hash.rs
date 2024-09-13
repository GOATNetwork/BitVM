use crate::treepp::*;
use crate::signatures::winternitz::{sign, checksig_verify, generate_public_key, PublicKey, checksum, to_digits, N, N1
};
use crate::hash::blake3::blake3_160_var_length;
use bitcoin::opcodes::all::{OP_DEPTH, OP_DROP, OP_DUP, OP_ENDIF, OP_EQUALVERIFY, OP_NOTIF, OP_PICK, OP_RETURN};
use blake3::hash;
use bitcoin::Witness;
use hex::decode as hex_decode;
use bitcoin::hashes::{hash160, Hash};

use super::winternitz;

const MESSAGE_HASH_LEN: u8 = 20;


/// Verify a Winternitz signature for the hash of the top `input_len` many bytes on the stack
/// The hash function is blake3 with a 20-byte digest size
/// Fails if the signature is invalid
pub fn check_hash_sig_dup(public_key: &PublicKey, input_len: usize, num: usize) -> Script {
    script! {
        // 1. Verify the signature and compute the signed message
        { checksig_verify(&public_key) }
        for _ in 0..MESSAGE_HASH_LEN {
            OP_TOALTSTACK
        }
        
        // 1.5 Duplicate the first n element
        for _ in 0..(input_len-num) {
            { input_len - 1 }
            OP_ROLL
        }
        for _ in 0..num {
            { input_len - 1 }
            OP_PICK
        }

        // 2. Hash the inputs
        { blake3_160_var_length(input_len) }

        // 3. Compare signed message to the hash
        for _ in 0..MESSAGE_HASH_LEN / 4 {
            for j in 0..4 {
                { 3 - j }
                OP_ROLL
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
        }
    }
}

pub fn check_raw_sig_dup(public_key: &PublicKey, input_len: usize, num: usize) -> Script {
    script! {
        // 1. Verify the signature and compute the signed message
        { checksig_verify(&public_key) }
        for _ in 0..MESSAGE_HASH_LEN {
            OP_TOALTSTACK
        }
        
        // 1.5 Duplicate the first n element
        for _ in 0..(input_len-num) {
            { input_len - 1 }
            OP_ROLL
        }
        for _ in 0..num {
            { input_len - 1 }
            OP_PICK
        }
        
        // 2. Hash the inputs
        { dummy_hash160_script(input_len) }

        // 3. Compare signed message to the hash
        for i in 0..MESSAGE_HASH_LEN {
            OP_FROMALTSTACK
            { MESSAGE_HASH_LEN - i }
            OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

/// Create a Winternitz signature for the blake3 hash of a given message
pub fn sign_hash(sec_key: &str, message: &[u8]) -> Script {
    let message_hash = hash(message);
    let message_hash_bytes = &message_hash.as_bytes()[0..20];
    script! {
        { sign(sec_key, message_hash_bytes) }
    }
}

pub fn sign_raw(sec_key: &str, message: &[u8]) -> Script {
    let message_hash = dummy_hash160(message);
    let message_hash_bytes = &message_hash[0..20];
    script! {
        { sign(sec_key, message_hash_bytes) }
    }
}

// push witness
pub fn push_hash_sig_witness(witness: &mut Witness, sec_key: &[u8; 20], message: &[u8]) {
    let secret_key = hex::encode(sec_key.clone());

    // winternitz_hash::sign_hash(&sec_key, message)
    let message_hash = hash(message);
    let message_hash_bytes = &message_hash.as_bytes()[0..20];

    winternitz::sig_witness(witness, &secret_key, message_hash_bytes);
}

pub fn push_raw_sig_witness(witness: &mut Witness, sec_key: &[u8; 20], message: &[u8]) {
    let secret_key = hex::encode(sec_key.clone());

    let message_hash = dummy_hash160(message);
    let message_hash_bytes = &message_hash[0..20];

    winternitz::sig_witness(witness, &secret_key, message_hash_bytes);
}

pub fn dummy_hash160(msg: &[u8]) -> [u8; 20] {
    if msg.len() >= 20 {
        let res: [u8; 20] = msg[..20].try_into().expect("impossible?!");
        res
    } else {
        let mut res: [u8; 20] = [0xf; 20];
        for (i, &item) in msg.iter().enumerate() {
            res[20-msg.len()+i] = item;
        }
        res
    }
}

pub fn dummy_hash160_script(input_len: usize) -> Script {
    script! {
        if input_len >= 20 {
            for i in 0..(input_len-20) {
                { input_len -1 -i }
                OP_ROLL
                OP_DROP
            }
        } else {
            for _ in 0..(20-input_len) {
                0xf
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bridge::graphs::base::OPERATOR_SECRET;

    use super::*;

    #[test]
    fn test_check_hash_sig() {

        // My secret key 
        let my_sec_key = OPERATOR_SECRET;
        
        // My public key
        let public_key = generate_public_key(my_sec_key);

        // The message to sign
        // let message = *b"This is an arbitrary length input intended for testing purposes....";
        let message: [u8; 4] = [0x11, 0x22, 0x33, 0x44];


        dbg!(execute_script(script! {
            //
            // Unlocking Script
            //

            // 1. Push the message 
            for byte in message.iter().rev() {
                { *byte }
            }

            // 2. Push the signature
            { sign_hash(my_sec_key, &message) }
            
            
            //
            // Locking Script
            //
            { check_hash_sig_dup(&public_key, message.len(), 0) }
            
            OP_TRUE
        }));   
    }

}