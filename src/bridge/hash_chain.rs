use bitcoin::hashes::{hash160, Hash};
use bitcoin::opcodes::all::{OP_EQUALVERIFY, OP_RETURN};
use bitcoin::Witness;
use crate::signatures::winternitz::{self, PublicKey};
use crate::bridge::commitment;
use crate::treepp::*;
use blake3::hash as blake3_hash;
use crate::hash::blake3::blake3_160_var_length;
use bitcoin_scriptexec::ExecError::OpReturn;
use hex::encode;

use super::connectors::connector_c::UnlockWitnessData;

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
        { commitment::sign_msg(&sec_key, &message) }
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
pub fn push_chunk_unlock_witness(witness: &mut Witness, sec_key: &[u8; 20], statement: &[u8], index: u32) {
    push_commitment_unlock_witness(witness, sec_key, statement, index+1);
    push_commitment_unlock_witness(witness, sec_key, statement, index);
}

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
        { commitment::check_sig_dup(pubkey, STACK_SCRIPT_LEN, STACK_SCRIPT_LEN) }
        { check_index_script(index) }


        // 2. do calculation
        { step_script() }


        // 3. check bitcommitment of the output & compare
        for _ in 0..TEMP_STACK_LEN {
            OP_TOALTSTACK
        }

        { commitment::check_sig_dup(pubkey, STACK_SCRIPT_LEN, STACK_SCRIPT_LEN) }
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

pub fn push_commitment_unlock_witness(witness: &mut Witness, sec_key: &[u8; 20], statement: &[u8], index: u32) {
    // push stack element
    let hash_n: [u8; 20] = blake3_160_n(statement, index);
    for byte in hash_n.iter().rev() {
        if *byte != 0u8 {
            if *byte > 0x7f {
                witness.push([*byte,0x00].to_vec());
            } else {
                witness.push([*byte].to_vec());
            }
        } else {
            witness.push([]);
        }
    }
    
    // push index
    for byte in encode_index(index).iter().rev() {
        if *byte != 0u8 {
            if *byte > 0x7f {
                witness.push([*byte,0x00].to_vec());
            } else {
                witness.push([*byte].to_vec());
            }
        } else {
            witness.push([]);
        }
    }

    // push signature
    let hash_n: [u8; 20] = blake3_160_n(statement, index);
    let index: [u8; 4] = encode_index(index);
    let message: [u8; 24] = concat_arrays(index, hash_n); 
    commitment::push_sig_witness(witness, &sec_key, &message);
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
        { commitment::check_sig_dup(pubkey, STACK_SCRIPT_LEN, INDEX_LEN) }
        { check_index_script(index) }
    }  
}

mod test {
    use bitcoin::witness;

    use crate::bridge::{graphs::base::{CALC_ROUND, OPERATOR_SECRET, OPERATOR_STATEMENT}, transactions::assert};

    use super::*;

    #[test]
    fn test_bitcommitment() {
        let seed = OPERATOR_SECRET;
        let pubkey = commitment::seed_to_pubkey(seed.as_bytes());
        let statement = OPERATOR_STATEMENT;
        let index: u32 = CALC_ROUND;
        let sec_key = commitment::seed_to_secret(seed.as_bytes());

        let sig_script = sign_temp(&sec_key, &statement, index);
        let stack_script = push_stack_script(&statement, index);

        let full_script = script! {
            { commitment_script_unlock(sig_script, stack_script, index) }
            
            { commitment_script_lock(&pubkey, index)}

            // OP_TRUE
        };
        dbg!(full_script.len());

        let res = dbg!(execute_script(full_script));
        assert!(res.success);
    }

    #[test]
    fn test_chunk() {
        let seed = OPERATOR_SECRET;
        let pubkey = commitment::seed_to_pubkey(seed.as_bytes());
        let statement = OPERATOR_STATEMENT;
        let index: u32 = CALC_ROUND;
        let sec_key = commitment::seed_to_secret(seed.as_bytes());

        let input_stack = push_stack_script(&statement, index);
        let output_stack = push_stack_script(&statement, index+1);

        let input_sig = sign_temp(&sec_key, &statement, index);
        let output_sig = sign_temp(&sec_key, &statement, index+1);

        let full_script = script! {
            { chunk_script_unlock(input_sig, output_sig, input_stack, output_stack, index) }

            { chunk_script_lock(&pubkey, index) }
        };
        dbg!(full_script.len());

        let res = dbg!(execute_script(full_script));
        assert!(!res.success);
        assert_eq!(res.error.unwrap(), OpReturn);
    }

    #[test]
    fn debug_test() {
        let seed = OPERATOR_SECRET;
        let pubkey = commitment::seed_to_pubkey(seed.as_bytes());
        let statement = OPERATOR_STATEMENT;
        let index: u32 = CALC_ROUND;
        let sec_key = commitment::seed_to_secret(seed.as_bytes());

        let input_stack = push_stack_script(&statement, index);
        let output_stack = push_stack_script(&statement, index+1);

        let input_sig = sign_temp(&sec_key, &statement, index);
        let output_sig = sign_temp(&sec_key, &statement, index+1);

        // dbg!(execute_script(script! {
        //     OP_TRUE
        // }));

        let mut witness = Witness::new();

        push_commitment_unlock_witness(&mut witness, &sec_key, &statement, index);

        for i in 0..witness.len()/4 {
            let ele_0 = witness.nth(4*i).unwrap();
            let ele_1 = witness.nth(4*i+1).unwrap();
            let ele_2 = witness.nth(4*i+2).unwrap();
            let ele_3 = witness.nth(4*i+3).unwrap();
            let res_0 = hex::encode(&ele_0);
            let res_1 = hex::encode(&ele_1);
            let res_2 = hex::encode(&ele_2);
            let res_3 = hex::encode(&ele_3);
            println!("{res_0} {res_1} {res_2} {res_3}");
        }
    }
}
