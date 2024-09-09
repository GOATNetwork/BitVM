use bitcoin::hashes::{hash160, Hash};
use crate::signatures::winternitz::{self, PublicKey};
use crate::bridge::commitment;
use crate::treepp::*;
use blake3::hash as blake3_hash;
use crate::hash::blake3::blake3_160_var_length;

const TEMP_STACK_LEN: usize = 20;
const INDEX_LEN: usize = 4;
const STACK_SCRIPT_LEN: usize = TEMP_STACK_LEN + INDEX_LEN;

fn concat_arrays<T, const A: usize, const B: usize, const C: usize>(a: [T; A], b: [T; B]) -> [T; C] {
    assert_eq!(A+B, C);
    let mut iter = a.into_iter().chain(b);
    std::array::from_fn(|_| iter.next().unwrap())
}

fn encode_index(index: u32) -> [u8; 4] {
    index.to_be_bytes()
}

fn blake3_160(pre_image: &[u8]) -> [u8; 20] {
    let hash_256 = blake3_hash(pre_image);
    let mut hash_160 = [0u8; 20];
    hash_160[..20].copy_from_slice(&hash_256.as_bytes()[0..20]);
    hash_160
}

fn blake3_160_n(pre_image: &[u8], n: u32) -> [u8; 20] {
    let hash_0 = blake3_160(pre_image);
    let mut hash_n = hash_0;
    for _ in 0..n {
        hash_n = blake3_160(&hash_n)
    }
    hash_n
}

pub fn push_stack_script(statement: &[u8], index: u32) -> Script {
    let hash_n: [u8; 20] = blake3_160_n(statement, index);
    script! {
        for byte in hash_n.iter().rev() {
            { *byte }
        }
    }
}

fn push_index_script(index: u32) -> Script {
    script! {
        for byte in encode_index(index).iter().rev() {
            { *byte }
        }
    }
}

fn check_index_script(index: u32) -> Script {
    let index = encode_index(index);
    script! {
        for i in 0..4 {
            { index[i] }
            OP_EQUALVERIFY
        }
    }
}

// Hash^n(statement) = result (i.e. y)
pub fn sign_result(sec_key: &[u8; 20], statement: &[u8], step_num: u32) -> Script {
    sign_temp(sec_key, statement, step_num)
}

pub fn sign_temp(sec_key: &[u8; 20], statement: &[u8], index: u32) -> Script {
    let hash_n: [u8; 20] = blake3_160_n(statement, index);
    let index: [u8; 4] = encode_index(index);
    let message: [u8; 24] = concat_arrays(index, hash_n); 
    script! {
        { commitment::sign_hash(&sec_key, &message) }
    }
}

pub fn step_script() -> Script {
    let temp_len = TEMP_STACK_LEN;
    script! {
        { blake3_160_var_length(temp_len) }
        for i in 1..TEMP_STACK_LEN / 4 {
            for _ in 0..4 {
                { 4 * i + 3 }
                OP_ROLL
            }
        }
    }
}

/*
    stack_script: 
        start| 0x1 0x2 0x3 0x4 index

    restored stack:
        bottom| 0x1 0x2 0x3 0x4
*/
pub fn chunk_script_unlock(input_sig: Script, output_sig: Script, input_stack: Script, output_stack: Script, index: u32) -> Script {
    script! {
        { output_stack }
        { push_index_script(index+1) }
        { output_sig }

        { input_stack }
        { push_index_script(index) }
        { input_sig }
    }
}

pub fn chunk_script_lock(pubkey: &PublicKey, index: u32) -> Script {
    script! {
        // 1. check bitcommitment of the input 
        { commitment::check_hash_sig_dup_all(pubkey, STACK_SCRIPT_LEN) }
        { check_index_script(index) }


        // 2. do calculation
        { step_script() }


        // 3. check bitcommitment of the output & compare
        for _ in 0..TEMP_STACK_LEN {
            OP_TOALTSTACK
        }

        { commitment::check_hash_sig_dup_all(pubkey, STACK_SCRIPT_LEN) }
        { check_index_script(index+1) }

        OP_TRUE
        for i in 0..TEMP_STACK_LEN {
            { TEMP_STACK_LEN - i }
            OP_ROLL
            OP_FROMALTSTACK
            OP_EQUAL
            OP_BOOLAND
        }
        OP_IF
        OP_RETURN
        OP_ENDIF
    }   
}

pub fn commitment_script_unlock(sig_script: Script, stack_script: Script, index: u32) -> Script {
    script! {
        { stack_script }
        { push_index_script(index) }
        { sig_script }
    }
}

pub fn commitment_script_lock(pubkey: &PublicKey, index: u32) -> Script {
    script! {
        { commitment::check_hash_sig_dup_top(pubkey, STACK_SCRIPT_LEN, INDEX_LEN) }
        { check_index_script(index) }
    }  
}

mod test {
    use crate::bridge::transactions::assert;

    use super::*;

    #[test]
    fn test_bitcommitment() {
        let seed = [1u8, 2u8, 0xff, 0xee];
        let pubkey = commitment::seed_to_pubkey(&seed);
        let statement = [0x1u8, 0x2, 0x3, 0x4];
        let index: u32 = 0x123;
        let sec_key = commitment::seed_to_secret(&seed);

        let sig_script = sign_temp(&sec_key, &statement, index);
        let stack_script = push_stack_script(&statement, index);

        let res = dbg!(execute_script(script! {
            { commitment_script_unlock(sig_script, stack_script, index) }
            
            { commitment_script_lock(&pubkey, index)}

            OP_TRUE
        }));
        assert!(res.success);
    }

    #[test]
    fn test_chunk() {
        let seed = [1u8, 2u8, 0xff, 0xee];
        let pubkey = commitment::seed_to_pubkey(&seed);
        let statement = [0x1u8, 0x2, 0x3, 0x4];
        let index: u32 = 0x8;
        let sec_key = commitment::seed_to_secret(&seed);

        let input_stack = push_stack_script(&statement, index);
        let output_stack = push_stack_script(&statement, index+1);

        let input_sig = sign_temp(&sec_key, &statement, index);
        let output_sig = sign_temp(&sec_key, &statement, index+1);


        let res = dbg!(execute_script(script! {
            { chunk_script_unlock(input_sig, output_sig, input_stack, output_stack, index) }

            { chunk_script_lock(&pubkey, index) }

            OP_TRUE
        }));
        assert!(res.success);
    }

    #[test]
    fn debug_test() {
        let seed = [1u8, 2u8, 0xff, 0xee];
        let pubkey = commitment::seed_to_pubkey(&seed);
        let statement = [0x1u8, 0x2, 0x3, 0x4];
        let index: u32 = 0x5;
        let sec_key = commitment::seed_to_secret(&seed);

        let input_stack = push_stack_script(&statement, index);
        let output_stack = push_stack_script(&statement, index+1);

        let input_sig = sign_temp(&sec_key, &statement, index);
        let output_sig = sign_temp(&sec_key, &statement, index+1);

        // dbg!(blake3_160_n(&statement, index+1));

        dbg!(execute_script(script! {
            { input_stack }
            { push_index_script(index) }
            { input_sig }
            { commitment::check_hash_sig_dup_all(&pubkey, STACK_SCRIPT_LEN) }
            { check_index_script(index) }
            { step_script() }
        }));

        dbg!(execute_script(script! {
            { output_stack }
            { push_index_script(index+1) }
            { output_sig }
            { commitment::check_hash_sig_dup_all(&pubkey, STACK_SCRIPT_LEN) }
            { check_index_script(index+1) }
        }));
    }
}
