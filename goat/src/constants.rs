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

// Commitment message parameters. Hardcoded number of bytes per message.
pub const BITCOIN_TXID_LENGTH: usize = 32;
