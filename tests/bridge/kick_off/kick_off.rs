use bitcoin::{consensus::encode::serialize_hex, Amount, OutPoint};

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, HIGH_FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        kick_off::{self, KickOffTransaction}, pre_kickoff::PreKickOffTransaction,
    },
};

use crate::bridge::helper::generate_stub_outpoint;

use super::super::setup::setup_test;

#[tokio::test]
async fn test_kick_off_tx() {
    let (client, _, operator_context, _, _, _, _, _, _, _, _, _, _, _, _, statement) = setup_test().await;

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT + HIGH_FEE_AMOUNT;
    let input_amount = Amount::from_sat(input_amount_raw);
    let funding_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    let funding_outpoint_0 = generate_stub_outpoint(&client, &funding_address, input_amount).await;

    let input = Input {
        outpoint: funding_outpoint_0,
        amount: input_amount,
    };

    // pre-kickoff
    let pre_kickoff = PreKickOffTransaction::new(&operator_context, input);
    let pre_kickoff_tx = pre_kickoff.finalize();
    let pre_kickoff_txid = pre_kickoff_tx.compute_txid();
    println!("\n-----------Pre-kickoff-----------:");
    // println!("Script Path Spend Transaction: {:?}\n", pre_kickoff_tx);
    let result = client.esplora.broadcast(&pre_kickoff_tx).await;
    println!("Txid: {:?}", pre_kickoff_txid);
    println!("Broadcast result: {:?}\n", result);
    // println!("Transaction hex: \n{}", serialize_hex(&pre_kickoff_tx));
    assert!(result.is_ok());

    // kick off
    let kick_off_input = Input {
        outpoint: OutPoint {
            txid: pre_kickoff_txid,
            vout: 0,
        },
        amount: pre_kickoff_tx.output[0].value,
    };
    let kick_off = KickOffTransaction::new(&operator_context, kick_off_input, &statement);
    // let kick_off_tx = kick_off.finalize();
    // println!("\n\n-----------Kickoff-----------:");
    // // println!("Script Path Spend Transaction: {:?}\n", kick_off_tx);
    // let result = client.esplora.broadcast(&kick_off_tx).await;
    // println!("Txid: {:?}", kick_off_tx.compute_txid());
    // println!("Broadcast result: {:?}\n", result);
    // // println!("Transaction hex: \n{}", serialize_hex(&kick_off_tx));
    // assert!(result.is_ok());
}
