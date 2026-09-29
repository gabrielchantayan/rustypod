//! `hash_table_visit` — original: `FUN_082d7bb8` @ **0x082d7bb8**
//! (**28 bytes**, exactly `0x082d7bb8..0x082d7bd3`; the next independent
//! function begins `push {r3,lr}` @ `0x082d7bd4`).
//!
//! Raw A32 decoding finds two inbound direct, unconditional plain `bl` calls
//! (`0x080782f8` and `0x082d9020`) and no predicated inbound calls. The body
//! contains one plain `bl`, to the unported bucket-chain visitor
//! `FUN_080846f4` @ `0x080846f4`, and no predicated calls.
//!
//! Algorithm: forwards `table` and `callback` to the resident bucket-chain
//! visitor with mode zero; the mode-one callback and context are fixed to NULL
//! and zero respectively.
//!
//! ## Deliberate deviations
//!
//! The unported visitor remains a volatile fixed-address target seam. Host
//! builds replace it with a recording seam; target builds call `0x080846f4`.

use core::ptr::addr_of;

use super::hash_table_visit_with_context::{
    HashTableBucketChainVisitor, HASH_TABLE_BUCKET_CHAIN_VISITOR,
};

/// Callback ABI selected by this wrapper's fixed mode-zero argument.
pub type HashTableVisitCallback = unsafe extern "C" fn(u32);

/// `hash_table_visit` — original `FUN_082d7bb8` @ `0x082d7bb8`.
///
/// Invokes `callback(value)` for each value selected by the table's resident
/// bucket-chain visitor. `table` and `callback` must be valid for that visitor;
/// retailOS performs no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_visit(
    table: *mut u8,
    callback: HashTableVisitCallback,
) {
    let visit: HashTableBucketChainVisitor =
        core::ptr::read_volatile(addr_of!(HASH_TABLE_BUCKET_CHAIN_VISITOR));
    visit(table, 0, Some(callback), None, 0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::hash_table_visit_with_context::HASH_TABLE_VISITOR_SEAM_LOCK;

    static mut CALLS: std::vec::Vec<(usize, u32, usize, bool, u32)> = std::vec::Vec::new();

    unsafe extern "C" fn recording_visitor(
        table: *mut u8,
        mode: u32,
        mode_zero_callback: Option<HashTableVisitCallback>,
        callback: Option<unsafe extern "C" fn(u32, u32)>,
        context: u32,
    ) {
        (*core::ptr::addr_of_mut!(CALLS)).push((
            table as usize,
            mode,
            mode_zero_callback.map_or(0, |callback| callback as usize),
            callback.is_some(),
            context,
        ));
    }

    unsafe extern "C" fn callback(_value: u32) {}

    struct SeamGuard(HashTableBucketChainVisitor);

    impl SeamGuard {
        unsafe fn install() -> Self {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            let previous = core::ptr::read_volatile(addr_of!(HASH_TABLE_BUCKET_CHAIN_VISITOR));
            core::ptr::addr_of_mut!(HASH_TABLE_BUCKET_CHAIN_VISITOR)
                .write_volatile(recording_visitor);
            Self(previous)
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(HASH_TABLE_BUCKET_CHAIN_VISITOR).write_volatile(self.0);
            }
        }
    }

    #[test]
    fn fixes_mode_one_callback_and_context_and_forwards_table_callback() {
        let _lock = HASH_TABLE_VISITOR_SEAM_LOCK.lock();
        let _seam = unsafe { SeamGuard::install() };
        for table in [core::ptr::null_mut(), 0x1234_5678usize as *mut u8] {
            unsafe { hash_table_visit(table, callback) };
        }
        let calls = unsafe { (*core::ptr::addr_of!(CALLS)).clone() };
        assert_eq!(
            calls,
            std::vec![
                (0, 0, callback as usize, false, 0),
                (0x1234_5678, 0, callback as usize, false, 0),
            ]
        );
    }
}
