use bitcoin::Network;
use serde::Deserialize;

pub const DEFAULT_WOTS_SECRET_FILE: &str = "data/private/wots_sec.json";
pub const DEFAULT_WOTS_PUBKEY_FILE: &str = "data/public/wots_pub.json";

pub const DEFAULT_VKEY_FILE: &str = "data/public/groth16/vkey.bin";
pub const DEFAULT_PROOF_FILE: &str = "data/public/groth16/proof.bin";
pub const DEFAULT_PUBIN_FILE: &str = "data/public/groth16/pubin.bin";

pub const DEFAULT_PARTIAL_SCRIPTS_FILE: &str = "data/public/partial_scripts.json";
pub const DEFAULT_DISPROVE_SCRIPTS_FILE: &str = "data/public/disprove_scripts.json";
pub const DEFAULT_SIGNED_ASSERTION_FILE: &str = "data/public/signed_assertions.json";

pub const DFFAULT_DISPROVE_WITNESS_FILE: &str = "data/public/disprove_witness.json";

pub const DEFAULT_TXNS_DIR: &str = "data/public/txns/";
pub const DEFAULT_SIGNED_TXNS_DIR: &str = "data/public/signed_txns/";
pub const PEGIN_FILE_NAME: &str = "pegin.json";
pub const PEGIN_DEPOSIT_FILE_NAME: &str = "pegin-deposit.json";
pub const PEGIN_REFUND_FILE_NAME: &str = "pegin-refund.json";
pub const PEGIN_CONFIRM_FILE_NAME: &str = "pegin-confirm.json";
pub const PRE_KICKOFF_FILE_NAME: &str = "pre-kickoff.json";
pub const KICKOFF_FILE_NAME: &str = "kickoff.json";
pub const TAKE1_FILE_NAME: &str = "take-1.json";
pub const CHALLENGE_FILE_NAME: &str = "challenge.json";
pub const ASSERT_INIT_FILE_NAME: &str = "assert-init.json";
pub const ASSERT_COMMIT_FILE_NAME: &str = "assert-commit.json";
pub const ASSERT_FINAL_FILE_NAME: &str = "assert-final.json";
pub const TAKE2_FILE_NAME: &str = "take-2.json";
pub const DISPROVE_FILE_NAME: &str = "disprove.json";

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub depositor: DepositorConfig,
    #[serde(default)]
    pub operator: OperatorConfig,
    #[serde(default)]
    pub federation: FederationConfig,
    #[serde(default)]
    pub challenger: ChallengerConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GeneralConfig {
    #[serde(default = "default_network")]
    pub network: String,

    pub federation_pubkeys: Option<Vec<String>>,
    pub federation_taproot_pubkey: Option<String>,
    pub operator_pubkey: Option<String>,
    // pub operator_taproot_pubkey: Option<String>,
    #[serde(default = "default_txns_dir")]
    pub txns_dir: String,
    #[serde(default = "default_signed_txns_dir")]
    pub signed_txns_dir: String,

    #[serde(default = "default_operator_wots_pubkey_file")]
    pub operator_wots_pubkey_file: String,

    #[serde(default = "default_vkey_file")]
    pub vkey_file: String,
    #[serde(default = "default_proof_file")]
    pub proof_file: String,
    #[serde(default = "default_pubin_file")]
    pub pubin_file: String,

    #[serde(default = "default_partial_scripts_file")]
    pub partial_scripts_file: String,
    #[serde(default = "default_disprove_scripts_file")]
    pub disprove_scripts_file: String,
    #[serde(default = "default_signed_assertions_file")]
    pub signed_assertions_file: String,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct DepositorConfig {
    pub depositor_evm_address: Option<String>,
    // pub depositor_taproot_public_key: Option<String>,
    pub depositor_pubkey: Option<String>,
    pub depositor_seckey: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OperatorConfig {
    #[serde(default = "default_operator_wots_secret_file")]
    pub operator_wots_seckey_file: String,
    pub operator_seckey: Option<String>,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct FederationConfig {
    pub federation_seckeys: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ChallengerConfig {
    #[serde(default = "default_disprove_witness_file")]
    pub disprove_witness_file: String,
}

pub fn load_config(file: &str) -> Config {
    let config_str = std::fs::read_to_string(file).expect("fail to read config file");
    toml::from_str(&config_str).expect("fail to decode toml")
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            network: "mainnet".to_string(),
            federation_pubkeys: None,
            federation_taproot_pubkey: None,
            operator_pubkey: None,
            // operator_taproot_pubkey: None,
            txns_dir: default_txns_dir(),
            signed_txns_dir: default_signed_txns_dir(),
            operator_wots_pubkey_file: default_operator_wots_pubkey_file(),
            vkey_file: default_vkey_file(),
            proof_file: default_proof_file(),
            pubin_file: default_pubin_file(),
            partial_scripts_file: default_partial_scripts_file(),
            disprove_scripts_file: default_disprove_scripts_file(),
            signed_assertions_file: default_signed_assertions_file(),
        }
    }
}
impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            operator_wots_seckey_file: default_operator_wots_secret_file(),
            operator_seckey: None,
        }
    }
}
impl Default for ChallengerConfig {
    fn default() -> Self {
        Self {
            disprove_witness_file: default_disprove_witness_file(),
        }
    }
}

pub(crate) fn match_network(network: &str) -> Result<Network, String> {
    match network {
        "Mainnet" => Ok(Network::Bitcoin),
        "Bitcoin" => Ok(Network::Bitcoin),
        "Testnet" => Ok(Network::Testnet),
        "Testnet3" => Ok(Network::Testnet),
        "Testnet4" => Ok(Network::Testnet4),
        "Regtest" => Ok(Network::Regtest),
        "Signet" => Ok(Network::Signet),

        "mainnet" => Ok(Network::Bitcoin),
        "bitcoin" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "testnet3" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "regtest" => Ok(Network::Regtest),
        "signet" => Ok(Network::Signet),

        _ => Err("unknow network: {network}, please choose from: Mainnet, Testne3, Testnet4, Regtest, Signet".to_string()),
    }
}
fn default_network() -> String {
    "Mainnet".to_string()
}
fn default_txns_dir() -> String {
    DEFAULT_TXNS_DIR.to_string()
}
fn default_signed_txns_dir() -> String {
    DEFAULT_SIGNED_TXNS_DIR.to_string()
}
fn default_operator_wots_secret_file() -> String {
    DEFAULT_WOTS_SECRET_FILE.to_string()
}
fn default_operator_wots_pubkey_file() -> String {
    DEFAULT_WOTS_PUBKEY_FILE.to_string()
}
fn default_vkey_file() -> String {
    DEFAULT_VKEY_FILE.to_string()
}
fn default_proof_file() -> String {
    DEFAULT_PROOF_FILE.to_string()
}
fn default_pubin_file() -> String {
    DEFAULT_PUBIN_FILE.to_string()
}
fn default_partial_scripts_file() -> String {
    DEFAULT_PARTIAL_SCRIPTS_FILE.to_string()
}
fn default_disprove_scripts_file() -> String {
    DEFAULT_DISPROVE_SCRIPTS_FILE.to_string()
}
fn default_signed_assertions_file() -> String {
    DEFAULT_SIGNED_ASSERTION_FILE.to_string()
}
fn default_disprove_witness_file() -> String {
    DFFAULT_DISPROVE_WITNESS_FILE.to_string()
}
