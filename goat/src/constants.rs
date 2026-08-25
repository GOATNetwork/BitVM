pub const NUM_BLOCKS_PER_HOUR: u32 = 6;
pub const NUM_BLOCKS_PER_6_HOURS: u32 = NUM_BLOCKS_PER_HOUR * 6;

pub const NUM_BLOCKS_PER_DAY: u32 = NUM_BLOCKS_PER_HOUR * 24;
pub const NUM_BLOCKS_PER_3_DAYS: u32 = NUM_BLOCKS_PER_DAY * 3;

pub const NUM_BLOCKS_PER_WEEK: u32 = NUM_BLOCKS_PER_DAY * 7;
pub const NUM_BLOCKS_PER_2_WEEKS: u32 = NUM_BLOCKS_PER_WEEK * 2;
pub const NUM_BLOCKS_PER_4_WEEKS: u32 = NUM_BLOCKS_PER_WEEK * 4;

pub const N_SEQUENCE_FOR_LOCK_TIME: u32 = 0xFFFFFFFE; // The nSequence field must be set to less than 0xffffffff, usually 0xffffffff-1 to avoid confilcts with relative timelocks.

// connectors' locktime
// TBD: adjust these timelocks
pub const CONNECTOR_Z_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 1; // pegin-cancel timelock
pub const CONNECTOR_A_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 2; // take-1 timelock
pub const WATCHTOWER_CHALLENGE_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 2; // watchtower challenge timelock
pub const ACK_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 3; // operator ack timelock
pub const CONNECTOR_G_TIMELOCK: u32 = WATCHTOWER_CHALLENGE_TIMELOCK + NUM_BLOCKS_PER_HOUR * 6; // operator commit blockhash timelock
pub const CONNECTOR_F_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 5; // take-2 timelock
pub const ASSERT_COMMIT_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 2; // assert-init timelock
pub const CONNECTOR_D_TIMELOCK: u32 = NUM_BLOCKS_PER_DAY * 5; // take-2 timelock

// Commitment message parameters. Hardcoded number of bytes per message.
pub const BITCOIN_TXID_LENGTH: usize = 32;
