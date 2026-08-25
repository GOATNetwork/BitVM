use bitcoin::{ScriptBuf, Witness};
use bitvm::bigint::U256;
use bitvm::chunk::api::type_conversion_utils::RawWitness;
use bitvm::chunk::api::{
    Assertions as ProofAssertions, PublicKeys as ProofPubkeys, Signatures as ProofSignatures,
    NUM_HASH, NUM_PUBS, NUM_U256,
};
use bitvm::hash::sha256_u4::sha256 as sha256_u4;
use bitvm::signatures::{Wots, Wots16, Wots32};
#[allow(unused_imports)]
use bitvm::u4::u4_std::u4_hex_to_nibbles;
use bitvm::{treepp::*, FmtStack};

pub type ChallengeHashType = [u8; 20]; // OP_HASH160

pub const GUEST_PUBIN_G16_PUBIN_INDEX: usize = 1; 
pub const GUEST_PUBIN_COMMITMENT_INDEX: usize = 0; // public inputs are reversed in assertions
pub const NUM_GUEST_PUBS_ASSERT: usize = 2; // commit [constants, watchtower-inclued-map]
pub const NUM_GUEST_PUBS_EXTRA: usize = 1; // commit blockhash
pub const NUM_GUEST: usize = NUM_GUEST_PUBS_ASSERT + NUM_GUEST_PUBS_EXTRA;
pub const GUEST_VALIDATION_TAPS: usize = 1;

pub type AssertGuestValidationPubkeys = [<Wots32 as Wots>::PublicKey; NUM_GUEST_PUBS_ASSERT];
pub type AssertGuestValidationAssertions = [[u8; 32]; NUM_GUEST_PUBS_ASSERT];

pub type AssertPubkeys = (AssertGuestValidationPubkeys, ProofPubkeys);
pub type AssertAssertions = (AssertGuestValidationAssertions, ProofAssertions);

pub type GuestPubinSignatures = Box<[<Wots32 as Wots>::Signature; NUM_GUEST]>;
pub type Groth16PubinSignatures = Box<[<Wots32 as Wots>::Signature; NUM_PUBS]>;

pub fn validate_guest_assertions(
    guest_sigs: &GuestPubinSignatures,
    pubin_sigs: &Groth16PubinSignatures,
    ack_preimages: &Vec<Vec<u8>>, // preimages length should match the number of hashes, use empty vec for unknown preimages
    guest_validation_scripts: &[ScriptBuf; GUEST_VALIDATION_TAPS],
) -> Option<(usize, Script)> {
    let witness_script = script! {
        { Wots32::signature_to_raw_witness(&pubin_sigs[GUEST_PUBIN_COMMITMENT_INDEX]) }
        { Wots32::signature_to_raw_witness(&guest_sigs[0]) }
        { Wots32::signature_to_raw_witness(&guest_sigs[1]) }
        { push_preimage_to_stack(&ack_preimages) }
        { Wots32::signature_to_raw_witness(&guest_sigs[2]) }
    };
    let full_script = witness_script
        .clone()
        .push_script(guest_validation_scripts[0].clone());
    let res = execute_script(full_script);
    if res.success {
        Some((0, witness_script))
    } else if res.final_stack.len() == 1 {
        None
    } else {
        panic!("unexpected script execution result, maybe sigs/scripts do not match?");
    }
}

pub fn generate_guest_pubin_commitment(guest_pubin_num: u32) -> Script {
    script! {
        for i in 0..guest_pubin_num as usize {
            { lift_and_reverse_bytes_u4(64 * i, 32) }
        }
        { sha256_u4(guest_pubin_num * 32) }
        { reverse_bytes_u4(32) }
        OP_SWAP { mod2_u4() } OP_SWAP
    }
}

// // with 8-bytes length prefix (deprecated)
// pub fn generate_guest_pubin_commitment(guest_pubin_num: u32) -> Script {
//     fn push_length_prefix_rev_u4() -> Script {
//         script! {
//             { u4_hex_to_nibbles("0000000000000020")}
//         }
//     }
//     script! {
//         for i in 0..guest_pubin_num as usize {
//             { push_length_prefix_rev_u4() }
//             { lift_and_reverse_bytes_u4(80 * i + 16, 32) }
//         }
//         { sha256_u4(guest_pubin_num * 40) }
//         { reverse_bytes_u4(32) }
//         OP_SWAP { mod2_u4() } OP_SWAP
//     }
// }

pub fn verify_guest_pubin(
    guest_pubin_wots_pubkeys: &[<Wots32 as Wots>::PublicKey; NUM_GUEST],
    groth16_pubin_wots_pubkeys: &[<Wots32 as Wots>::PublicKey; NUM_PUBS],
    constant_value: &[u8; 32],
    hashes: &Vec<ChallengeHashType>,
) -> [Script; GUEST_VALIDATION_TAPS] {
    let wots32_msg_stack_items_num = Wots32::MSG_BYTE_LEN as usize * 2;
    let wots32_sig_stack_items_num = Wots32::TOTAL_DIGIT_LEN as usize * 2;
    let zipped_wots32_msg_stack_items_num = Wots32::MSG_BYTE_LEN as usize;
    let scr = script! {
        { 1 } OP_TOALTSTACK // flag for overall result

        { verify_hashlock_pubin_script_dup(&guest_pubin_wots_pubkeys[2], hashes) }
        OP_FROMALTSTACK OP_BOOLAND OP_TOALTSTACK

        { roll_n(wots32_msg_stack_items_num, wots32_sig_stack_items_num) }

        { verify_constant_pubin_script_dup(&guest_pubin_wots_pubkeys[1], constant_value) }
        OP_FROMALTSTACK OP_BOOLAND OP_TOALTSTACK

        { roll_n(wots32_msg_stack_items_num * 2, wots32_sig_stack_items_num) }

        { Wots32::checksig_verify(&guest_pubin_wots_pubkeys[0]) }

        { roll_n(wots32_msg_stack_items_num * 3, wots32_sig_stack_items_num) }

        { Wots32::checksig_verify(&groth16_pubin_wots_pubkeys[GUEST_PUBIN_COMMITMENT_INDEX]) }

        { reverse_zip_nibbles_bytes32() }

        { roll_n(zipped_wots32_msg_stack_items_num, wots32_msg_stack_items_num * 3) }

        { generate_guest_pubin_commitment(NUM_GUEST as u32) } // guest-pubin-commitment = hash(blockhash || constant || included_watchtowers_map)

        { zip_nibbles_bytes32() }

        OP_FROMALTSTACK
        for i in (0..32).rev() {
            OP_SWAP { i + 2 } OP_ROLL OP_NUMEQUAL OP_BOOLAND
        }

        // if flag remains 1, all checks passed, disprove shall fail
        OP_NOT
    };
    [scr]
}

/// Returns a Bitcoin script that verifies a Winternitz signature for the given `wots_pk`
/// and additionally checks that message matches the provided `constant_value`
///
/// ## Precondition
///
/// - The Winternitz signature (compact) is at the stack top.
///
/// ## Postcondition
///
/// - If the signature is invalid: the script fails immediately
/// - If the signature is valid: the script continues to compare msg against `constant_value`
///   - `1` (true): every nibble matches exactly;
///   - `0` (false): at least one nibble does not match.
/// - The comparison process consumes the message, leaving only the final boolean result.
///
pub fn verify_constant_pubin_script(
    wots_pk: &<Wots32 as Wots>::PublicKey,
    constant_value: &[u8; 32],
) -> Script {
    script! {
        { Wots32::checksig_verify(wots_pk) }
        { verify_constant_pubin_script_inner(constant_value) }
    }
}
// same as `verify_constant_pubin_script` but leave message in stack (below the boolean result)
pub fn verify_constant_pubin_script_dup(
    wots_pk: &<Wots32 as Wots>::PublicKey,
    constant_value: &[u8; 32],
) -> Script {
    script! {
        { Wots32::checksig_verify(wots_pk) }
        for i in 0..64 {
            { i } OP_PICK
            OP_TOALTSTACK
        }
        { verify_constant_pubin_script_inner(constant_value) }
        for _ in 0..64 {
            OP_FROMALTSTACK
        }
        { 64 } OP_ROLL
    }
}
// inner part of `verify_constant_pubin_script` that assumes the signature has been verified
pub fn verify_constant_pubin_script_inner(constant_value: &[u8; 32]) -> Script {
    script! {
        { 1 }
        for byte in constant_value.to_vec() {
            OP_SWAP
            { byte & 0x0F }
            OP_NUMEQUAL
            OP_BOOLAND

            OP_SWAP
            { byte >> 4 }
            OP_NUMEQUAL
            OP_BOOLAND
        }
    }
}

/// Returns a Bitcoin script that verifies a Winternitz signature for the given `wots_pk`
/// corresponding to a watchtower-included bitmap, and checks the relationship between
/// the bitmap and provided `preimages`.
///
/// ## Precondition
///
/// - The stack top contains the compact Winternitz signature for the watchtower-included bitmap.
/// - Below the signature on the stack is the list of `preimages`
///
/// ## Postcondition
///
/// - If the Winternitz signature is invalid: the script fails immediately.
/// - If the signature is valid: the script iterates over each index `i` of the bitmap:
///   - If `watchtower_included_bitmap[i] == 0` and `hash(preimages[i]) == hashes[i]`,
///     the final stack result is `0` (false).
///   - Otherwise, the final stack result is `1` (true).
/// - The comparison consumes the message and preimages from the stack, leaving only the final boolean result.
///
pub fn verify_hashlock_pubin_script(
    wots_pk: &<Wots32 as Wots>::PublicKey,
    hashes: &Vec<ChallengeHashType>,
) -> Script {
    script! {
        { Wots32::checksig_verify(wots_pk) }
        { verify_hashlock_pubin_script_inner(hashes) }
    }
}
// same as `verify_hashlock_pubin_script` but leave bitmap in stack (below the boolean result)
pub fn verify_hashlock_pubin_script_dup(
    wots_pk: &<Wots32 as Wots>::PublicKey,
    hashes: &Vec<ChallengeHashType>,
) -> Script {
    script! {
        { Wots32::checksig_verify(wots_pk) }
        for i in 0..64 {
            { i } OP_PICK
            OP_TOALTSTACK
        }
        { verify_hashlock_pubin_script_inner(hashes) }
        for _ in 0..64 {
            OP_FROMALTSTACK
        }
        { 64 } OP_ROLL
    }
}
// inner part of `verify_hashlock_pubin_script` that assumes the signature has been verified
fn verify_hashlock_pubin_script_inner(hashes: &Vec<ChallengeHashType>) -> Script {
    // assert!(hashes.len() <= TBD);
    fn chunk_count(len: usize, chunk_size: usize) -> usize {
        (len + chunk_size - 1) / chunk_size
    }
    script! {
        for _ in 0..hashes.len() {
            { 64 } OP_ROLL OP_TOALTSTACK
        }
        { 1 }
        for chunk in hashes.chunks(4) {
            OP_SWAP
            for i in (1..4).rev() {
                if i >= chunk.len() {
                    { 1 << i } OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF
                        OP_SUB
                    OP_ELSE
                        OP_DROP
                    OP_ENDIF
                } else {
                    { 1 << i } OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF
                        OP_SUB OP_FROMALTSTACK OP_DROP
                    OP_ELSE
                        OP_DROP
                        OP_SWAP
                        OP_FROMALTSTACK
                        OP_HASH160
                        { chunk[i].to_vec() }
                        OP_EQUAL
                        OP_NOT
                        OP_BOOLAND
                        OP_SWAP
                    OP_ENDIF
                }
            }
            OP_IF
                OP_FROMALTSTACK OP_DROP
            OP_ELSE
                OP_FROMALTSTACK
                OP_HASH160
                { chunk[0].to_vec() }
                OP_EQUAL
                OP_NOT
                OP_BOOLAND
            OP_ENDIF
        }
        for _ in 0..(64 - chunk_count(hashes.len(), 4)) {
            OP_NIP
        }
    }
}

pub fn push_preimage_to_stack(preimages: &Vec<Vec<u8>>) -> Script {
    script! {
        for chunk in preimages.chunks(4) {
            for i in (0..chunk.len()).rev() {
                { chunk[i].to_vec() }
            }
        }
    }
}

fn roll(d: usize) -> Script {
    match d {
        0 => script! {},
        1 => script! { OP_SWAP },
        2 => script! { OP_ROT },
        _ => script! { { d } OP_ROLL },
    }
}

fn lift_and_reverse_bytes_u4(depth: usize, num_bytes: usize) -> Script {
    script! {
        for i in 0..num_bytes {
            { roll(depth + 2*i + 1) }
            { roll(depth + 2*i + 1) }
        }
    }
}

fn reverse_bytes_u4(num_bytes: usize) -> Script {
    lift_and_reverse_bytes_u4(0, num_bytes)
}

fn roll_n(depth: usize, num_items: usize) -> Script {
    script! {
        for _ in 0..num_items {
            { roll(depth + num_items - 1) }
        }
    }
}

fn mod2_u4() -> Script {
    script! {
        OP_DUP
        OP_8
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_8
            OP_SUB
        OP_ENDIF

        OP_DUP
        OP_4
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_4
            OP_SUB
        OP_ENDIF

        OP_DUP
        OP_3
        OP_EQUAL

        OP_SWAP
        OP_1
        OP_EQUAL
        OP_BOOLOR
    }
}

fn zip_nibbles_bytes32() -> Script {
    script! {
        { U256::transform_limbsize(4, 8) }
    }
}

fn reverse_zip_nibbles_bytes32() -> Script {
    script! {
        for _ in 0..32 {
            { roll(62) }
            { roll(63) }
        }
        { zip_nibbles_bytes32() }
    }
}

pub fn bits_to_bytes32(bits: &[bool]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bits.len().min(256);
    for i in 0..len {
        let byte_index = i / 8;
        let bit_index = i % 8;
        if bits[i] {
            out[byte_index] |= 1 << bit_index;
        }
    }
    out
}

pub fn hash160(msg: &Vec<u8>) -> [u8; 20] {
    use bitcoin::hashes::{hash160, Hash};
    hash160::Hash::hash(msg).to_byte_array()
}

pub fn utils_signatures_from_raw_witnesses(
    raw_wits: &[RawWitness], // commit_blockhash witnesses || assert_commit witnesses
) -> (GuestPubinSignatures, ProofSignatures) {
    assert_eq!(raw_wits.len(), NUM_GUEST + NUM_PUBS + NUM_U256 + NUM_HASH);
    let mut guest_sigs = vec![];
    for i in 0..NUM_GUEST {
        let a = Wots32::raw_witness_to_signature(&Witness::from_slice(&raw_wits[i]));
        guest_sigs.push(a);
    }
    let mut asigs = vec![];
    for i in 0..NUM_PUBS {
        let a = Wots32::raw_witness_to_signature(&Witness::from_slice(&raw_wits[i + NUM_GUEST]));
        asigs.push(a);
    }
    let mut bsigs = vec![];
    for i in 0..NUM_U256 {
        let a = Wots32::raw_witness_to_signature(&Witness::from_slice(
            &raw_wits[i + NUM_GUEST + NUM_PUBS],
        ));
        bsigs.push(a);
    }
    let mut csigs = vec![];
    for i in 0..NUM_HASH {
        let a = Wots16::raw_witness_to_signature(&Witness::from_slice(
            &raw_wits[i + NUM_GUEST + NUM_PUBS + NUM_U256],
        ));
        csigs.push(a);
    }
    let guest_sigs = guest_sigs.try_into().unwrap();
    let asigs = asigs.try_into().unwrap();
    let bsigs = bsigs.try_into().unwrap();
    let csigs = csigs.try_into().unwrap();
    (guest_sigs, (asigs, bsigs, csigs))
}

/// Parse `num_bytes` bytes from the stack, starting at `start_index` (from the top).
/// Each byte is encoded as two 4-bit nibbles (high, low) on the stack.
pub fn parse_u4_stack(start_index: usize, num_bytes: usize, stack: &FmtStack) -> Vec<u8> {
    fn get_stack_element_from_top(stack: &FmtStack, index_from_top: usize) -> Vec<u8> {
        stack.get(stack.len() - 1 - index_from_top).to_vec()
    }
    fn to_u4(v: &[u8]) -> Option<u8> {
        if v.is_empty() {
            return Some(0);
        }
        if v[0] > 0x0F {
            return None;
        }
        for &byte in &v[1..] {
            if byte != 0 {
                return None;
            }
        }
        Some(v[0])
    }
    let mut v = vec![];
    assert!(
        stack.len() >= start_index + num_bytes * 2,
        "stack too short"
    );
    for i in 0..num_bytes {
        let low = get_stack_element_from_top(stack, start_index + i * 2);
        let low = to_u4(&low).expect(&format!("low nibble out of range: {}", hex::encode(low)));
        let high = get_stack_element_from_top(stack, start_index + i * 2 + 1);
        let high = to_u4(&high).expect(&format!("high nibble out of range: {}", hex::encode(high)));
        v.push(high * 16 + low);
    }
    v
}

pub fn reverse_each_byte(input: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for i in 0..32 {
        let byte = input[i];
        let high_nibble = (byte & 0xF0) >> 4;
        let low_nibble = byte & 0x0F;
        output[i] = (low_nibble << 4) | high_nibble;
    }
    output
}

#[test]
fn test_hash160() {
    let input = "hello world".as_bytes().to_vec();
    let hash = hash160(&input);
    let hash160_script = script! {
        { input } OP_HASH160
        { hash.to_vec() }
        OP_EQUAL
    };
    let result = execute_script(hash160_script);
    assert!(result.success);
}

#[test]
fn test_verify_constant_pubin_script() {
    use hex::FromHex;
    let secret = Wots32::generate_secret_key();
    let public_key = Wots32::generate_public_key(&secret);
    let correct_msg =
        <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let incorrect_msg =
        <[u8; 32]>::from_hex("100102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let constant =
        <[u8; 32]>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();

    let s = script! {
      { Wots32::sign_to_raw_witness(&secret, &correct_msg) }
      { verify_constant_pubin_script(&public_key, &constant) }
      { 1 }
      OP_EQUALVERIFY
      OP_TRUE
    };
    println!("constant check script length: {}", s.len());
    let result = execute_script(s);
    assert!(result.success);
    assert_eq!(result.final_stack.len(), 1);

    let s = script! {
      { Wots32::sign_to_raw_witness(&secret, &incorrect_msg) }
      { verify_constant_pubin_script(&public_key, &constant) }
      { 0 }
      OP_EQUALVERIFY
      OP_TRUE
    };
    let result = execute_script(s);
    assert!(result.success);
    assert_eq!(result.final_stack.len(), 1);

    let s = script! {
      { Wots32::sign_to_raw_witness(&secret, &correct_msg) }
      { verify_constant_pubin_script_dup(&public_key, &constant) }
    };
    let result = execute_script(s);
    assert_eq!(
        parse_u4_stack(1, 32, &result.final_stack),
        correct_msg.to_vec()
    );
}

#[test]
fn test_verify_hashlock_pubin_script() {
    let secret = Wots32::generate_secret_key();
    let public_key = Wots32::generate_public_key(&secret);
    let hashes_len = 11;
    let mut preimages: Vec<Vec<u8>> = vec![];
    let mut hashes: Vec<[u8; 20]> = vec![];
    for i in 0..hashes_len {
        preimages.push(format!("preimage_{:02x}", i).into_bytes());
        hashes.push(hash160(&preimages[i].clone()));
        // println!("hash {}: {:?}", i, hex::encode(hashes[i].iter().rev().cloned().collect::<Vec<u8>>()));
    }
    fn to_bool_vec(input: &[u8]) -> Vec<bool> {
        input.iter().map(|x| *x != 0).collect()
    }

    {
        // TEST OP_TRUE case: all bitmap=0 indices have preimages that do NOT match the corresponding hashes
        let inclueded = to_bool_vec(&[1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]);
        let mut input_preimages = vec![vec![]; hashes_len];
        input_preimages[1] = preimages[1].clone();
        input_preimages[2] = preimages[1].clone();
        let s = script! {
            { push_preimage_to_stack(&input_preimages) }
            { Wots32::sign_to_raw_witness(&secret, &bits_to_bytes32(&inclueded)) }
            { verify_hashlock_pubin_script(&public_key, &hashes) }
            { 1 }
            OP_EQUALVERIFY
            OP_TRUE
        };
        println!("hashlock check script length: {}", s.len());
        let result = execute_script(s);
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
    }

    {
        // TEST OP_FALSE case 1: at least one bitmap=0 index has a matching preimage hash
        let inclueded = to_bool_vec(&[1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]);
        let mut input_preimages = vec![vec![]; hashes_len];
        input_preimages[2] = preimages[2].clone();
        let s = script! {
            { push_preimage_to_stack(&input_preimages) }
            { Wots32::sign_to_raw_witness(&secret, &bits_to_bytes32(&inclueded)) }
            { verify_hashlock_pubin_script(&public_key, &hashes) }
            { 0 }
            OP_EQUALVERIFY
            OP_TRUE
        };
        let result = execute_script(s);
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
    }

    {
        // TEST OP_FALSE case 2: bitmap padded with extra bits
        // extra padded bitmap bits should not change the result
        let inclueded = to_bool_vec(&[1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1]);
        let mut input_preimages = vec![vec![]; hashes_len];
        input_preimages[2] = preimages[2].clone();
        let s = script! {
            { push_preimage_to_stack(&input_preimages) }
            { Wots32::sign_to_raw_witness(&secret, &bits_to_bytes32(&inclueded)) }
            { verify_hashlock_pubin_script(&public_key, &hashes) }
            { 0 }
            OP_EQUALVERIFY
            OP_TRUE
        };
        let result = execute_script(s);
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
    }

    {
        // TEST dup version: leave bitmap in stack
        let inclueded = to_bool_vec(&[1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]);
        let mut input_preimages = vec![vec![]; hashes_len];
        input_preimages[1] = preimages[1].clone();
        let s = script! {
            { push_preimage_to_stack(&input_preimages) }
            { Wots32::sign_to_raw_witness(&secret, &bits_to_bytes32(&inclueded)) }
            { verify_hashlock_pubin_script_dup(&public_key, &hashes) }
        };
        let result = execute_script(s);
        assert_eq!(
            parse_u4_stack(1, 32, &result.final_stack),
            bits_to_bytes32(&inclueded).to_vec()
        );
    }
}

#[test]
fn test_verify_guest_pubin_ziren() {
    use hex::FromHex;
    let secrets = std::iter::repeat(Wots32::generate_secret_key())
        .take(NUM_GUEST + NUM_PUBS)
        .collect::<Vec<_>>();
    let pubkeys = secrets
        .iter()
        .map(|s| Wots32::generate_public_key(s))
        .collect::<Vec<_>>();
    let blockhash =
        <[u8; 32]>::from_hex("5a690bba0ba076d621f77665398f4b1ddbfc2349bbb3e8880307625ac5cfa900")
            .unwrap();
    let constant =
        <[u8; 32]>::from_hex("2df7bde0605973f5809a1338094cb47a309bc38363dd35ce178c088cd3cda79f")
            .unwrap();
    let included_bitmap =
        <[u8; 32]>::from_hex("0100000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    // let groth16_pubin =
    //     <[u8; 32]>::from_hex("1a5605834864faf9cb10055606d9ae06425ea5cf8cf757f996182cd1da196158")
    //         .unwrap();

    use ark_serialize::CanonicalDeserialize;
    use ark_ff::{BigInteger, PrimeField};
    // let proof_file = "ziren/proof.bin";
    // let proof_bin = std::fs::read(proof_file).unwrap();
    // let groth16_proof = ark_groth16::Proof::<ark_bn254::Bn254>::deserialize_compressed(&*proof_bin).unwrap();
    // let vk_file = "ziren/vk.bin";
    // let vk_bin = std::fs::read(vk_file).unwrap();
    // let groth16_vkey = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(&*vk_bin).unwrap();
    let pubin_file = "ziren/public_inputs.bin";
    let pubin_bin = std::fs::read(pubin_file).unwrap();
    let groth16_public_inputs = <[ark_bn254::Fr; 2]>::deserialize_compressed(&*pubin_bin).unwrap();
    let guest_pubin_commitment = groth16_public_inputs[GUEST_PUBIN_G16_PUBIN_INDEX];
    let guest_pubin_commitment_bytes = guest_pubin_commitment.into_bigint().to_bytes_be();
    let mut groth16_pubin = [0u8; 32];
    groth16_pubin[32 - guest_pubin_commitment_bytes.len()..]
        .copy_from_slice(&guest_pubin_commitment_bytes);

    let hashes_len = 2;
    let mut preimages: Vec<Vec<u8>> = vec![];
    let mut hashes: Vec<[u8; 20]> = vec![];
    for i in 0..hashes_len {
        preimages.push(format!("preimage_{:02x}", i).into_bytes());
        hashes.push(hash160(&preimages[i].clone()));
    }

    let lock_scr = script! {
        { verify_guest_pubin(
            &pubkeys[0..NUM_GUEST].try_into().unwrap(),
            &pubkeys[NUM_GUEST..NUM_GUEST + NUM_PUBS].try_into().unwrap(),
            &constant,
            &hashes,
        )[0].clone() }
    };
    println!("guest pubin validation script length: {}", lock_scr.len());

    {
        // TEST SUCCESS case: provide preimages for some bitmap = 0 indices
        let mut input_preimages = vec![vec![]; hashes_len];
        input_preimages[1] = preimages[1].clone();
        let full_scr = script! {
            { Wots32::sign_to_raw_witness(&secrets[NUM_GUEST + GUEST_PUBIN_COMMITMENT_INDEX], &reverse_each_byte(groth16_pubin)) }
            { Wots32::sign_to_raw_witness(&secrets[0], &blockhash) }
            { Wots32::sign_to_raw_witness(&secrets[1], &constant) }
            { push_preimage_to_stack(&input_preimages) }
            { Wots32::sign_to_raw_witness(&secrets[2], &included_bitmap) }
            { lock_scr.clone() }
        };
        println!("full script length: {}", full_scr.len());
        let result = execute_script_without_stack_limit(full_scr);
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
    }

    {
        // TEST SUCCESS case: mismatch constant
        let input_preimages = vec![vec![]; hashes_len];
        let mut mismatched_constant = constant.clone();
        mismatched_constant[0] ^= 0xFF;
        let full_scr = script! {
            { Wots32::sign_to_raw_witness(&secrets[NUM_PUBS + GUEST_PUBIN_COMMITMENT_INDEX], &reverse_each_byte(groth16_pubin)) }
            { Wots32::sign_to_raw_witness(&secrets[0], &blockhash) }
            { Wots32::sign_to_raw_witness(&secrets[1], &mismatched_constant) }
            { push_preimage_to_stack(&input_preimages) }
            { Wots32::sign_to_raw_witness(&secrets[2], &included_bitmap) }
            { lock_scr.clone() }
        };
        let result = execute_script_without_stack_limit(full_scr);
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
    }

    {
        // TEST SUCCESS case: mismatch groth16 pubin
        let input_preimages = vec![vec![]; hashes_len];
        let mut mismatched_groth16_pubin = groth16_pubin.clone();
        mismatched_groth16_pubin[1] ^= 0xFF;
        let full_scr = script! {
            { Wots32::sign_to_raw_witness(&secrets[NUM_PUBS + GUEST_PUBIN_COMMITMENT_INDEX], &reverse_each_byte(mismatched_groth16_pubin)) }
            { Wots32::sign_to_raw_witness(&secrets[0], &blockhash) }
            { Wots32::sign_to_raw_witness(&secrets[1], &constant) }
            { push_preimage_to_stack(&input_preimages) }
            { Wots32::sign_to_raw_witness(&secrets[2], &included_bitmap) }
            { lock_scr.clone() }
        };
        let result = execute_script_without_stack_limit(full_scr);
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
    }

    {
        // TEST FAILURE case: everything correct
        let mut input_preimages = vec![vec![]; hashes_len];
        input_preimages[0] = preimages[0].clone();
        let full_scr = script! {
            { Wots32::sign_to_raw_witness(&secrets[NUM_PUBS + GUEST_PUBIN_COMMITMENT_INDEX], &reverse_each_byte(groth16_pubin)) }
            { Wots32::sign_to_raw_witness(&secrets[0], &blockhash) }
            { Wots32::sign_to_raw_witness(&secrets[1], &constant) }
            { push_preimage_to_stack(&input_preimages) }
            { Wots32::sign_to_raw_witness(&secrets[2], &included_bitmap) }
            { lock_scr.clone() }
        };
        let result = execute_script_without_stack_limit(full_scr);
        assert!(!result.success);
        assert_eq!(result.final_stack.len(), 1);
    }
}

#[test]
fn test_generate_guest_pubin_commitment_ziren() {
    fn u4_bytes_to_nibbles(bytes: &[u8]) -> Script {
        let mut rev_bytes = bytes.to_vec();
        rev_bytes.reverse();
        // u4_hex_to_nibbles takes little-endian hex strings
        script! {
            { u4_hex_to_nibbles(&hex::encode(rev_bytes)) }
        }
    }
    let pubins: Vec<[u8; 32]> = vec![
        hex::decode("5a690bba0ba076d621f77665398f4b1ddbfc2349bbb3e8880307625ac5cfa900")
            .unwrap()
            .try_into()
            .unwrap(),
        hex::decode("2df7bde0605973f5809a1338094cb47a309bc38363dd35ce178c088cd3cda79f")
            .unwrap()
            .try_into()
            .unwrap(),
        hex::decode("0100000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .try_into()
            .unwrap(),
    ];
    // expected_commit_value with length prefix: 001df6fc84f5d020f1453744b865e29750c935c11c89e3c1605e27db449d8821
    let expected_commit_value: [u8; 32] =
        hex::decode("1a5605834864faf9cb10055606d9ae06425ea5cf8cf757f996182cd1da196158")
            .unwrap()
            .try_into()
            .unwrap();

    let s = script! {
        { u4_bytes_to_nibbles(&pubins[2]) }
        { u4_bytes_to_nibbles(&pubins[1]) }
        { u4_bytes_to_nibbles(&pubins[0]) }
        { generate_guest_pubin_commitment(3) }
    };
    let result = execute_script(s);
    let commit_values = parse_u4_stack(0, 32, &result.final_stack);
    assert_eq!(expected_commit_value.to_vec(), commit_values);
}
