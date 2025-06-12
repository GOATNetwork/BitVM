pub mod commands;
pub mod config;
pub mod files;
pub mod handles;

use bitcoin::{Address, Amount, OutPoint, Txid};
use clap::{arg, command, Parser};
use commands::Commands;
use config::{load_config, match_network};
use core::str::FromStr;
use goat::transactions::base::Input;
use handles::{
    handle_challenger_sign_disprove, handle_federation_presign, handle_generate_bitvm_instance,
    handle_generate_disprove_scripts, handle_generate_pegin_tx, handle_generate_prekickoff_tx,
    handle_generate_wots_keys, handle_operator_presign, handle_operator_sign_assert,
    handle_operator_sign_kickoff, handle_operator_sign_take1, handle_operator_sign_take2,
    handle_sign_proof, handle_verify_proof,
};

#[derive(Parser)]
#[command(about = "goat bitvm cli-tools", long_about = None)]
struct Cli {
    /// config file path
    #[arg(short = 'c', long = "conf")]
    config_file: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug)]
struct TxInputValue(Txid, u32, u64);

impl FromStr for TxInputValue {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return Err(format!("invalid format: `{s}`,should be `string:u32:u64`"));
        }

        let txid = parts[0]
            .parse::<Txid>()
            .map_err(|e| format!("fail to parse input.txid: `{}`: {:?}", parts[0], e))?;
        let vout = parts[1]
            .parse::<u32>()
            .map_err(|e| format!("fail to parse input.vout: `{}`: {:?}", parts[1], e))?;
        let amount = parts[2]
            .parse::<u64>()
            .map_err(|e| format!("fail to parse input.amount: `{}`: {:?}", parts[2], e))?;

        Ok(TxInputValue(txid, vout, amount))
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateDisproveScripts {} => {
            let conf = load_config(&cli.config_file);
            handle_generate_disprove_scripts(conf);
        }
        Commands::GenerateWotsKeys { secret_seed } => {
            let conf = load_config(&cli.config_file);
            handle_generate_wots_keys(conf, secret_seed);
        }
        Commands::SignProof { skip_validation } => {
            let conf = load_config(&cli.config_file);
            handle_sign_proof(conf, *skip_validation);
        }
        Commands::VerifyProof {} => {
            let conf = load_config(&cli.config_file);
            handle_verify_proof(conf);
        }
        Commands::GeneratePeginTx {
            tx_inputs,
            deposit_amount,
            fee_amount,
            change_address,
        } => {
            let conf = load_config(&cli.config_file);
            let network = match_network(&conf.general.network).unwrap();
            let inputs = tx_inputs
                .iter()
                .map(|input| {
                    let txin = TxInputValue::from_str(input).expect("fail to parse tx inputs");
                    Input {
                        outpoint: OutPoint {
                            txid: txin.0,
                            vout: txin.1,
                        },
                        amount: Amount::from_sat(txin.2),
                    }
                })
                .collect();
            let deposit_amount = Amount::from_sat(*deposit_amount);
            let fee_amount = Amount::from_sat(*fee_amount);
            let change_address = Address::from_str(change_address)
                .expect("fail to parse change address")
                .require_network(network)
                .expect("address failed the network check");
            handle_generate_pegin_tx(conf, inputs, deposit_amount, fee_amount, change_address);
        }
        Commands::GeneratePrekickoffTx {
            tx_inputs,
            stake_amount,
            fee_amount,
            change_address,
        } => {
            let conf = load_config(&cli.config_file);
            let network = match_network(&conf.general.network).unwrap();
            let inputs = tx_inputs
                .iter()
                .map(|input| {
                    let txin = TxInputValue::from_str(input).expect("fail to parse tx inputs");
                    Input {
                        outpoint: OutPoint {
                            txid: txin.0,
                            vout: txin.1,
                        },
                        amount: Amount::from_sat(txin.2),
                    }
                })
                .collect();
            let stake_amount = Amount::from_sat(*stake_amount);
            let fee_amount = Amount::from_sat(*fee_amount);
            let change_address = Address::from_str(change_address)
                .expect("fail to parse change address")
                .require_network(network)
                .expect("address fail to pass network check");
            handle_generate_prekickoff_tx(conf, inputs, stake_amount, fee_amount, change_address);
        }
        Commands::GenerateBitvmInstanace {} => {
            let conf = load_config(&cli.config_file);
            handle_generate_bitvm_instance(conf);
        }
        Commands::FederationPresign {} => {
            let conf = load_config(&cli.config_file);
            handle_federation_presign(conf);
        }
        Commands::OperatorPresign {} => {
            let conf = load_config(&cli.config_file);
            handle_operator_presign(conf);
        }
        Commands::OperatorSign {
            kickoff,
            evm_withdraw_txid,
            take_1,
            assert,
            take_2,
        } => {
            let conf = load_config(&cli.config_file);
            if *kickoff {
                let evm_withdraw_txid = evm_withdraw_txid
                    .clone()
                    .expect("please provide --evm-withdraw-txid when signing kickoff tx");
                let evm_withdraw_txid = hex::decode(evm_withdraw_txid.trim_start_matches("0x"))
                    .expect("fail to decode evm_txid");
                let evm_withdraw_txid: [u8; 32] = evm_withdraw_txid
                    .try_into()
                    .expect("invalid evm txid length");
                handle_operator_sign_kickoff(conf.clone(), evm_withdraw_txid);
            }
            if *take_1 {
                handle_operator_sign_take1(conf.clone());
            }
            if *assert {
                handle_operator_sign_assert(conf.clone());
            }
            if *take_2 {
                handle_operator_sign_take2(conf);
            }
        }
        Commands::Disprove { reward_address } => {
            let conf = load_config(&cli.config_file);
            let network = match_network(&conf.general.network).unwrap();
            let reward_address = Address::from_str(reward_address)
                .expect("fail to parse reward address")
                .require_network(network)
                .expect("address fail to pass network check");
            handle_challenger_sign_disprove(conf, reward_address);
        }
    }
}

#[test]
fn generate_test_keys() {
    use bitcoin::{Network, PublicKey};
    use goat::contexts::{
        base::generate_keys_from_secret, depositor::DepositorContext, operator::OperatorContext,
        verifier::VerifierContext,
    };

    let source_network = Network::Regtest;
    const OPERATOR_SECRET: &str =
        "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac";
    const VERIFIER_0_SECRET: &str =
        "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2";
    const VERIFIER_1_SECRET: &str =
        "fc294c70faf210d4d0807ea7a3dba8f7e41700d90c119e1ae82a0687d89d297f";
    const DEPOSITOR_SECRET: &str =
        "b8f17ea979be24199e7c3fec71ee88914d92fd4ca508443f765d56ce024ef1d7";

    let (_, verifier_0_public_key) = generate_keys_from_secret(source_network, VERIFIER_0_SECRET);
    let (_, verifier_1_public_key) = generate_keys_from_secret(source_network, VERIFIER_1_SECRET);
    let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
    n_of_n_public_keys.push(verifier_0_public_key);
    n_of_n_public_keys.push(verifier_1_public_key);

    let depositor_context =
        DepositorContext::new(source_network, DEPOSITOR_SECRET, &n_of_n_public_keys);
    let operator_context =
        OperatorContext::new(source_network, OPERATOR_SECRET, &n_of_n_public_keys);
    let verifier_0_context =
        VerifierContext::new(source_network, VERIFIER_0_SECRET, &n_of_n_public_keys);
    // let verifier_1_context =
    //     VerifierContext::new(source_network, VERIFIER_1_SECRET, &n_of_n_public_keys);

    dbg!(depositor_context.depositor_taproot_public_key.to_string());
    dbg!(depositor_context.depositor_public_key.to_string());
    dbg!(DEPOSITOR_SECRET);
    dbg!("");
    dbg!(operator_context.operator_taproot_public_key.to_string());
    dbg!(operator_context.operator_public_key.to_string());
    dbg!(OPERATOR_SECRET);
    dbg!("");
    dbg!(verifier_0_context.n_of_n_taproot_public_key.to_string());
    dbg!(verifier_0_context.n_of_n_public_key.to_string());
    dbg!(verifier_0_context.n_of_n_public_keys[0].to_string());
    dbg!(verifier_0_context.n_of_n_public_keys[1].to_string());
    dbg!(VERIFIER_0_SECRET);
    dbg!(VERIFIER_1_SECRET);
    // dbg!("");
    // dbg!(verifier_1_context.n_of_n_taproot_public_key.to_string());
    // dbg!(verifier_1_context.n_of_n_public_key.to_string());
    // dbg!(verifier_1_context.n_of_n_public_keys[0].to_string());
    // dbg!(verifier_1_context.n_of_n_public_keys[1].to_string());
    // dbg!(VERIFIER_1_SECRET);
}

#[test]
#[ignore]
fn generate_corrupt_proof() {
    let conf_file = "./src/bin/goat-bridge/example.config.toml";
    let conf = load_config(&conf_file);
    // let target_script_index: u32 = 8;
    let target_bitcom_index: usize = 8;

    println!("loading operator wots secret keys ...");
    assert!(
        files::file_exists(&conf.operator.operator_wots_seckey_file),
        "operator_wots_seckey_file not provided"
    );
    let wots_sec = files::load_wots_seckeys(&conf.operator.operator_wots_seckey_file);

    println!("loading proof signatures ...");
    assert!(
        files::file_exists(&conf.general.proof_file),
        "proof-sigs not provided"
    );
    let mut proof_sigs =
        files::load_signed_assertions_from_file(&conf.general.signed_assertions_file);

    handles::corrupt(&mut proof_sigs, &wots_sec.1, target_bitcom_index);

    println!("loading vkey ...");
    assert!(
        files::file_exists(&conf.general.vkey_file),
        "vkey not provided"
    );
    let ark_vkey = files::load_groth16_vk(&conf.general.vkey_file);

    println!("loading operator wots public-key...");
    assert!(
        files::file_exists(&conf.general.operator_wots_pubkey_file),
        "operator wots public key is not provided"
    );
    let pubkey = files::load_wots_pubkeys(&conf.general.operator_wots_pubkey_file);

    println!("loading disprove scripts...");
    assert!(
        files::file_exists(&conf.general.disprove_scripts_file),
        "disprove scripts is not provided"
    );
    let disprove_scripts = files::load_scripts_from_file(&conf.general.disprove_scripts_file)
        .try_into()
        .unwrap();

    let res =
        bitvm::chunk::api::validate_assertions(&ark_vkey, proof_sigs, pubkey.1, &disprove_scripts);
    match res {
        Some((index, witness)) => {
            files::write_disprove_witness(&conf.challenger.disprove_witness_file, index, witness);
            println!(
                "\nProof is invalid! Disprove witness is written to: {}",
                &conf.challenger.disprove_witness_file
            );
        }
        _ => {
            println!("\nProof is Ok.");
        }
    };
}

#[test]
#[ignore]
fn test_disprove_scripts_size() {
    let conf_file = "./src/bin/goat-bridge/example.config.toml";
    let conf = load_config(&conf_file);

    assert!(
        files::file_exists(&conf.general.disprove_scripts_file),
        "disprove scripts not provided"
    );
    let disprove_scripts_bytes =
        files::load_scripts_bytes_from_file(&conf.general.disprove_scripts_file);

    let scr_num = disprove_scripts_bytes.len();
    let mut sum_bytes = 0;
    let mut min_scr = (0, 10000000000);
    for i in 0..disprove_scripts_bytes.len() {
        let scr_len = disprove_scripts_bytes[i].len();
        min_scr = if min_scr.1 > scr_len {
            (i, scr_len)
        } else {
            min_scr
        };
        sum_bytes += scr_len;
        println!("script {i} size: {scr_len}");
    }
    println!("total {scr_num} scripts");
    println!("total {sum_bytes} bytes");
    println!("min script: {:?} , size: {:?}", min_scr.0, min_scr.1);
}

#[test]
#[ignore]
fn generate_test_fund_address() {
    use goat::contexts::base::generate_keys_from_secret;
    use goat::scripts::generate_pay_to_pubkey_script_address;

    let conf_file = "./src/bin/goat-bridge/example.config.toml";
    let conf = load_config(&conf_file);
    let network = match_network(&conf.general.network).unwrap();
    let fund_address_sec = conf.operator.operator_seckey.unwrap();
    let (_, fund_address_pub) = generate_keys_from_secret(network, &fund_address_sec);
    let fund_address = generate_pay_to_pubkey_script_address(network, &fund_address_pub);
    let pegin_fund_amount = Amount::from_sat(100_000);
    let kickoff_fund_amount = Amount::from_sat(5_000_000);
    let challenge_fund_amount = Amount::from_sat(100_000);
    println!(
        "Pegin Fund Address: {fund_address} Amount: {} btc",
        pegin_fund_amount.to_btc()
    );
    println!(
        "Kickoff Fund Address: {fund_address} Amount: {} btc",
        kickoff_fund_amount.to_btc()
    );
    println!(
        "Challenge Fund Address: {fund_address} Amount: {} btc",
        challenge_fund_amount.to_btc()
    );
}

#[test]
#[ignore]
#[allow(unused_imports)]
fn sign_test_fund_tx() {
    use bitcoin::secp256k1::Keypair;
    use bitcoin::{
        consensus, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, Transaction, Txid,
        Wtxid,
    };
    use config::*;
    use files::*;
    use goat::contexts::base::generate_keys_from_secret;
    use goat::scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address};
    use goat::transactions::signing::populate_p2wsh_witness;
    use goat::transactions::{
        peg_in::peg_in::PegInTransaction, peg_out_confirm::PreKickoffTransaction,
        pre_signed::PreSignedTransaction,
    };
    use std::fs::File;
    use std::io::BufReader;

    fn sign_p2wsh_tx(
        tx_mut: &mut Transaction,
        input_index: usize,
        script: ScriptBuf,
        value: Amount,
        sighash_type: EcdsaSighashType,
        keypairs: &Vec<&Keypair>,
    ) {
        populate_p2wsh_witness(tx_mut, input_index, sighash_type, &script, value, keypairs);
    }

    let conf_file = "./src/bin/goat-bridge/example.config.toml";
    let conf = load_config(&conf_file);
    let network = match_network(&conf.general.network).unwrap();
    let pegin_fund_amount = Amount::from_sat(100_000);
    let kickoff_fund_amount = Amount::from_sat(5_000_000);
    // let challenge_fund_amount = Amount::from_sat(100_000);
    let fund_address_sec = conf.operator.operator_seckey.unwrap();
    let (keypair, fund_address_pub) = generate_keys_from_secret(network, &fund_address_sec);
    let fund_script = generate_pay_to_pubkey_script(&fund_address_pub);

    {
        let pegin_file = format!("{}{}", &conf.general.txns_dir, PEGIN_FILE_NAME);
        if file_exists(&pegin_file) {
            let file = File::open(&pegin_file).expect(&format!("fail to open {:?}", pegin_file));
            let reader = BufReader::new(file);
            let mut pegin_tx: PegInTransaction = serde_json::from_reader(reader).unwrap();
            sign_p2wsh_tx(
                pegin_tx.tx_mut(),
                0,
                fund_script.clone(),
                pegin_fund_amount,
                EcdsaSighashType::All,
                &vec![&keypair],
            );
            let signed_pegin_tx_bytes =
                serde_json::to_vec_pretty(&SignedTransaction::new(pegin_tx.tx().clone())).unwrap();
            let signed_pegin_tx_file =
                format!("{}{}", &conf.general.signed_txns_dir, PEGIN_FILE_NAME);
            write_bytes_to_file(&signed_pegin_tx_bytes, &signed_pegin_tx_file);
            println!("signed pegin tx written to {}", signed_pegin_tx_file);
        } else {
            println!("pegin tx not provided, skipped")
        };
    }

    {
        let pre_kickoff_file = format!("{}{}", &conf.general.txns_dir, PRE_KICKOFF_FILE_NAME);
        if file_exists(&pre_kickoff_file) {
            let file = File::open(&pre_kickoff_file)
                .expect(&format!("fail to open {:?}", pre_kickoff_file));
            let reader = BufReader::new(file);
            let mut pre_kickoff_tx: PreKickoffTransaction =
                serde_json::from_reader(reader).unwrap();
            sign_p2wsh_tx(
                pre_kickoff_tx.tx_mut(),
                0,
                fund_script,
                kickoff_fund_amount,
                EcdsaSighashType::All,
                &vec![&keypair],
            );
            let signed_prekickoff_tx_bytes =
                serde_json::to_vec_pretty(&SignedTransaction::new(pre_kickoff_tx.tx().clone()))
                    .unwrap();
            let signed_prekickoff_tx_file =
                format!("{}{}", &conf.general.signed_txns_dir, PRE_KICKOFF_FILE_NAME);
            write_bytes_to_file(&signed_prekickoff_tx_bytes, &signed_prekickoff_tx_file);
            println!(
                "signed pre-kickoff tx written to {}",
                signed_prekickoff_tx_file
            );
        } else {
            println!("pre-kickoff tx not provided, skipped")
        };
    }
}

#[test]
#[ignore]
#[allow(unused_imports)]
fn sign_test_challenge_tx() {
    use bitcoin::secp256k1::Keypair;
    use bitcoin::{
        consensus, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, Transaction, Txid,
        Wtxid,
    };
    use config::*;
    use files::*;
    use goat::contexts::base::generate_keys_from_secret;
    use goat::scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address};
    use goat::transactions::signing::populate_p2wsh_witness;
    use goat::transactions::{
        base::InputWithScript, challenge::ChallengeTransaction, pre_signed::PreSignedTransaction,
    };
    use std::fs::File;
    use std::io::BufReader;

    let conf_file = "./src/bin/goat-bridge/example.config.toml";
    let conf = load_config(&conf_file);
    let network = match_network(&conf.general.network).unwrap();
    let challenge_fund_amount = Amount::from_sat(100_000);
    let fund_address_sec = conf.operator.operator_seckey.unwrap();
    let (keypair, fund_address_pub) = generate_keys_from_secret(network, &fund_address_sec);
    let fund_script = generate_pay_to_pubkey_script(&fund_address_pub);
    let fund_address = generate_pay_to_pubkey_script_address(network, &fund_address_pub);

    let challenge_file = format!("{}{}", &conf.general.txns_dir, CHALLENGE_FILE_NAME);
    if file_exists(&challenge_file) {
        let file =
            File::open(&challenge_file).expect(&format!("fail to open {:?}", challenge_file));
        let reader = BufReader::new(file);
        let mut challenge_tx: ChallengeTransaction = serde_json::from_reader(reader).unwrap();
        let challenge_input = InputWithScript {
            outpoint: OutPoint {
                txid: Txid::from_str("TODO").unwrap(),
                vout: 0,
            },
            amount: challenge_fund_amount,
            script: &fund_script,
        };
        challenge_tx.add_inputs_and_output(
            &vec![challenge_input],
            &keypair,
            fund_address.script_pubkey(),
        );
        let signed_challenge_tx_bytes =
            serde_json::to_vec_pretty(&SignedTransaction::new(challenge_tx.tx().clone())).unwrap();
        let signed_challenge_tx_file =
            format!("{}{}", &conf.general.signed_txns_dir, CHALLENGE_FILE_NAME);
        write_bytes_to_file(&signed_challenge_tx_bytes, &signed_challenge_tx_file);
        println!(
            "signed challenge tx written to {}",
            signed_challenge_tx_file
        );
    } else {
        println!("challenge tx not provided, skipped")
    };
}
