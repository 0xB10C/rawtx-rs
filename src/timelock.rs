//! Information about Bitcoin Time-Locks.

use bitcoin::{Transaction, PackedLockTime};

#[derive(Debug)]
pub struct LocktimeInfo {
    pub locktime: PackedLockTime,
    is_enforced: bool,
}

impl LocktimeInfo {
    pub fn new(tx: &Transaction) -> LocktimeInfo {
        LocktimeInfo {
            locktime: tx.lock_time,
            is_enforced: tx.input.iter().any(|i| i.sequence.enables_absolute_lock_time()) && tx.lock_time > PackedLockTime::ZERO,
        }
    }

    /// Returns true if the locktime is enforced. The locktime of a Bitcoin
    /// transaction is only enforced when at least one of the inputs sequences
    /// is lower than 0xFFFF_FFFF.
    pub fn is_enforced(&self) -> bool {
        self.is_enforced
    }

    /// Is true when the locktime represents a block height. The locktime value
    /// must larger than zero and smaller than 500_000_000.
    pub fn is_height(&self) -> bool {
        self.locktime > PackedLockTime::ZERO && self.locktime.to_u32() < 500_000_000
    }

    /// Is true when the locktime represents a timestamp. The locktime value
    /// must be larger than or equal to 500_000_000.
    pub fn is_timestamp(&self) -> bool {
        self.locktime.to_u32() > 500_000_000
    }
}
