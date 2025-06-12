use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// -GENERAL----: generate disprove scripts
    GenerateDisproveScripts {},

    /// -GENERAL----: generate all necessary bitvm2 transactions (unsigned)
    GenerateBitvmInstanace {},

    /// -DEPOSITOR--: generate pegin-prepare, pegin-comfirm & pegin-refund txns
    GeneratePeginTx {
        /// (sats)  deposit amount of pegin tx
        #[arg(long = "amount")]
        deposit_amount: u64,

        /// (sats)  fee amount of pegin tx
        #[arg(long = "fee")]
        fee_amount: u64,

        /// (Address) address to receive change
        #[arg(long = "change")]
        change_address: String,

        /// (array of strings) input utxos for pegin tx
        /// format: "txid:vout:amount"
        /// example: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16:0:10000000000"
        #[arg(long="inputs", num_args = 1.., value_delimiter = ',', required = true)]
        tx_inputs: Vec<String>,
    },

    /// -FEDERATION-: push federation members' pre-signature for necessary txns, include: pegin_comfirm, take_1, take_2, assert_final, disprove
    FederationPresign {},

    /// -OPERATOR---: generate winternitz public-keys & secret-keys
    /// (⚠ Warning: This feature is for testing and development purposes only. It may not be secure enough for production use.)
    GenerateWotsKeys {
        /// (String) a random seed used to generate wots keypairs
        // #[arg(short = 's', long = "seed")]
        secret_seed: String,
    },

    /// -OPERATOR---: generate winternitz signatures for groth16-proof & intermediate-values
    SignProof {
        /// skip verifying the correctness of generated sigs
        #[arg(long)]
        skip_validation: bool,
    },

    /// -OPERATOR---: generate pre-kickoff(pegout-confirm) tx
    GeneratePrekickoffTx {
        /// (sats)  stake amount of pre-kickof tx
        #[arg(long = "amount")]
        stake_amount: u64,

        /// (sats)  fee amount of pre-kickof tx
        #[arg(long = "fee")]
        fee_amount: u64,

        /// (Address) address to receive change
        #[arg(long = "change")]
        change_address: String,

        /// (array of formatted strings) input utxos for prekickoff tx
        /// format: txid:vout:amount
        /// example: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16:0:10000000000
        #[arg(long="inputs", num_args = 1.., value_delimiter = ',', required = true)]
        tx_inputs: Vec<String>,
    },

    /// -OPERATOR---: push operator's pre-signature necessary txns, include: challenge
    OperatorPresign {},

    /// -OPERATOR---: operator sign txns: include: kickoff, take-1, assert, take-2
    OperatorSign {
        /// sign kickoff txn; evm-withdraw-txid is required
        #[arg(long)]
        kickoff: bool,

        /// will be commited in kickoff
        #[arg(long)]
        evm_withdraw_txid: Option<String>,

        /// sign take-1 txn
        #[arg(long)]
        take_1: bool,

        /// sign assert txn; include: assert-inital, assert-commit, assert-final; proof is required
        #[arg(long)]
        assert: bool,

        /// sign take-2 txn
        #[arg(long)]
        take_2: bool,
    },

    /// -CHALLENGER-: check if the groth16-proof(bitcommitments) is valid
    VerifyProof {},

    /// -CHALLENGER-: send disprove tx
    Disprove {
        /// address that will receive challenger success reward
        reward_address: String,
    },
    /*
    /// -FEDERATION-: generate psbt for federation members
    GenerateFederationPsbt {
        /// (hex String) federation member's public-key
        // #[arg(long)]
        pubkey: String,
    },

    /// -OPERATOR---: generate psbt for operator
    GenerateOperatorPsbt {
        // #[arg(long)]
        presign: bool,

        // #[arg(long)]
        kickoff: bool,

        // #[arg(long)]
        take1: bool,

        // #[arg(long)]
        take2: bool,
    },

    /// -CHALLENGER-: check if kickoff-tx is valid
    ValidateKickoff {
    },

    /// -CHALLENGER-: check if the groth16-proof(bitcommitments) submitted by operator in assert-tx is valid
    ValidateAssert {
    },
    */
}
