use serde::{Deserialize, Serialize};

pub const NUM_BLOCKS_PER_HOUR: u32 = 6;
pub const NUM_BLOCKS_PER_DAY: u32 = NUM_BLOCKS_PER_HOUR * 24;
pub const NUM_BLOCKS_PER_WEEK: u32 = NUM_BLOCKS_PER_DAY * 7;

pub const N_SEQUENCE_FOR_LOCK_TIME: u32 = 0xFFFFFFFE; // The nSequence field must be set to less than 0xffffffff, usually 0xffffffff-1 to avoid confilcts with relative timelocks.

// connectors' locktime
// TBD: adjust these timelocks
pub const CONNECTOR_Z_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY; // pegin-cancel timelock
pub const CONNECTOR_A_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY; // take-1 timelock
pub const PROVER_CONNECTOR_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY; // disprove timelock for the prover connector
pub const CONNECTOR_D_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 3; // take-2 timelock
pub const WATCHTOWER_CHALLENGE_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY; // watchtower challenge timeout
pub const OPERATOR_ACK_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 2; // operator challenge ACK timeout
pub const OPERATOR_COMMIT_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 3; // operator public-input commitment timeout
pub const CONNECTOR_F_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 4; // take-2 watchtower flow timelock

/// Configurable mainnet timelock values that are scaled for the selected bitcoin network.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelockConfig {
    pub connector_z: u32,
    pub connector_a: u32,
    pub prover_connector: u32,
    pub connector_d: u32,
    pub watchtower_challenge: u32,
    pub operator_ack: u32,
    pub operator_commit: u32,
    pub connector_f: u32,
}

impl TimelockConfig {
    pub const fn new(
        connector_z: u32,
        connector_a: u32,
        prover_connector: u32,
        connector_d: u32,
        watchtower_challenge: u32,
        operator_ack: u32,
        operator_commit: u32,
        connector_f: u32,
    ) -> Self {
        TimelockConfig {
            connector_z,
            connector_a,
            prover_connector,
            connector_d,
            watchtower_challenge,
            operator_ack,
            operator_commit,
            connector_f,
        }
    }
}

impl Default for TimelockConfig {
    fn default() -> Self {
        TimelockConfig {
            connector_z: CONNECTOR_Z_TIMELOCK,
            connector_a: CONNECTOR_A_TIMELOCK,
            prover_connector: PROVER_CONNECTOR_TIMELOCK,
            connector_d: CONNECTOR_D_TIMELOCK,
            watchtower_challenge: WATCHTOWER_CHALLENGE_TIMELOCK,
            operator_ack: OPERATOR_ACK_TIMELOCK,
            operator_commit: OPERATOR_COMMIT_TIMELOCK,
            connector_f: CONNECTOR_F_TIMELOCK,
        }
    }
}

pub const DEFAULT_TIMELOCK_CONFIG: TimelockConfig = TimelockConfig {
    connector_z: CONNECTOR_Z_TIMELOCK,
    connector_a: CONNECTOR_A_TIMELOCK,
    prover_connector: PROVER_CONNECTOR_TIMELOCK,
    connector_d: CONNECTOR_D_TIMELOCK,
    watchtower_challenge: WATCHTOWER_CHALLENGE_TIMELOCK,
    operator_ack: OPERATOR_ACK_TIMELOCK,
    operator_commit: OPERATOR_COMMIT_TIMELOCK,
    connector_f: CONNECTOR_F_TIMELOCK,
};

// Commitment message parameters. Hardcoded number of bytes per message.
pub const BITCOIN_TXID_LENGTH: usize = 32;
