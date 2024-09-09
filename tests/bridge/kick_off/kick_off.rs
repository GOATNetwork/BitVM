use bitcoin::{consensus::encode::serialize_hex, Amount, OutPoint};

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
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
    let (client, _, operator_context, _, _, _, _, _, _, _, _, _, _, _, _, compressed_statement) = setup_test().await;

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT;
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
    let pre_kickoff_tx = PreKickOffTransaction::new(&operator_context, input);
    let tx = pre_kickoff_tx.finalize();
    let pre_kickoff_txid = tx.compute_txid();
    println!("\n-----------Pre-kickoff-----------:");
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());

    // kick off
    let kick_off_input = Input {
        outpoint: OutPoint {
            txid: pre_kickoff_txid,
            vout: 0,
        },
        amount: input_amount,
    };
    let kick_off_tx = KickOffTransaction::new(&operator_context, kick_off_input, &compressed_statement);
    let tx = pre_kickoff_tx.finalize();
    println!("\n\n-----------Kickoff-----------:");
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());

}
