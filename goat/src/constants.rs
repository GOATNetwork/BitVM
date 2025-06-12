pub const NUM_BLOCKS_PER_HOUR: u32 = 6;
pub const NUM_BLOCKS_PER_6_HOURS: u32 = NUM_BLOCKS_PER_HOUR * 6;

pub const NUM_BLOCKS_PER_DAY: u32 = NUM_BLOCKS_PER_HOUR * 24;
pub const NUM_BLOCKS_PER_3_DAYS: u32 = NUM_BLOCKS_PER_DAY * 3;

pub const NUM_BLOCKS_PER_WEEK: u32 = NUM_BLOCKS_PER_DAY * 7;
pub const NUM_BLOCKS_PER_2_WEEKS: u32 = NUM_BLOCKS_PER_WEEK * 2;
pub const NUM_BLOCKS_PER_4_WEEKS: u32 = NUM_BLOCKS_PER_WEEK * 4;

pub const N_SEQUENCE_FOR_LOCK_TIME: u32 = 0xFFFFFFFE; // The nSequence field must be set to less than 0xffffffff, usually 0xffffffff-1 to avoid confilcts with relative timelocks.

// connectors' locktime
pub const CONNECTOR_3_TIMELOCK: u32 = NUM_BLOCKS_PER_2_WEEKS;
pub const CONNECTOR_4_TIMELOCK: u32 = NUM_BLOCKS_PER_2_WEEKS;
pub const CONNECTOR_Z_TIMELOCK: u32 = NUM_BLOCKS_PER_2_WEEKS;

// Commitment message parameters. Hardcoded number of bytes per message.
pub const EVM_TXID_LENGTH: usize = 64;
pub const BITCOIN_TXID_LENGTH: usize = 64;
