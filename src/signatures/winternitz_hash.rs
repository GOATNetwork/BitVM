use crate::treepp::*;
use crate::signatures::winternitz::{sign, checksig_verify, generate_public_key, PublicKey
};
use crate::hash::blake3::blake3_160_var_length;
use bitcoin::opcodes::all::OP_PICK;
use blake3::hash;

const MESSAGE_HASH_LEN: u8 = 20;


/// Verify a Winternitz signature for the hash of the top `input_len` many bytes on the stack
/// The hash function is blake3 with a 20-byte digest size
/// Fails if the signature is invalid
pub fn check_hash_sig(public_key: &PublicKey, input_len: usize) -> Script {
    script! {
        // 1. Verify the signature and compute the signed message
        { checksig_verify(&public_key) }
        for _ in 0..MESSAGE_HASH_LEN {
            OP_TOALTSTACK
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

pub fn check_hash_sig_dup_all(public_key: &PublicKey, input_len: usize) -> Script {
    script! {
        // 1. Verify the signature and compute the signed message
        { checksig_verify(&public_key) }
        for _ in 0..MESSAGE_HASH_LEN {
            OP_TOALTSTACK
        }

        // 1.5 Duplicate the inputs
        for _ in 0..input_len {
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

pub fn check_hash_sig_dup_top(public_key: &PublicKey, input_len: usize, num: usize) -> Script {
    script! {
        // 1. Verify the signature and compute the signed message
        { checksig_verify(&public_key) }
        for _ in 0..MESSAGE_HASH_LEN {
            OP_TOALTSTACK
        }

        // 1.5 Duplicate the first input
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

/// Create a Winternitz signature for the blake3 hash of a given message
pub fn sign_hash(sec_key: &str, message: &[u8]) -> Script {
    let message_hash = hash(message);
    let message_hash_bytes = &message_hash.as_bytes()[0..20];
    script! {
        { sign(sec_key, message_hash_bytes) }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_check_hash_sig() {

        // My secret key 
        let my_sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";
        
        // My public key
        let public_key = generate_public_key(my_sec_key);

        // The message to sign
        // let message = *b"This is an arbitrary length input intended for testing purposes....";
        let message = [0x11, 0x22, 0x33, 0x44];


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
            { check_hash_sig_dup_all(&public_key, message.len()) }
            OP_TRUE
        }));   
    }

}