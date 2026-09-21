//! `hash_table_visit_with_context` — original: `FUN_082d7bd4` @
//! **0x082d7bd4** (**28 bytes**, exactly `0x082d7bd4..0x082d7bef`; the next
//! independent function begins `push {r4-r6,lr}` @ `0x082d7bf0`).
//!
//! Raw ARM decoding finds two inbound direct, unconditional plain `bl` calls
//! (`0x08073394` and `0x080733a4`) and no predicated inbound calls. The body
//! contains one plain `bl`, to the unported bucket-chain visitor
//! `FUN_080846f4` @ `0x080846f4`, and no predicated calls.
//!
//! Algorithm: forwards `table`, `callback`, and `context` to the bucket-chain
//! visitor with its mode fixed to one and its mode-zero callback fixed to NULL.
//!
//! ## Deliberate deviations
//!
//! The unported visitor remains a volatile fixed-address target seam. Host
//! builds replace it with a recording seam; target builds call 0x080846f4.

use core::ptr::addr_of;

/// Firmware load address of the unported bucket-chain visitor `FUN_080846f4`.
pub const HASH_TABLE_BUCKET_CHAIN_VISITOR_ADDRESS: usize = 0x0808_46f4;

/// Callback ABI selected by this wrapper's fixed mode-one argument.
pub type HashTableValueCallback = unsafe extern "C" fn(u32, u32);

/// ABI of the unported bucket-chain visitor. `mode_zero_callback` is NULL when
/// `mode` is nonzero; `callback` and `context` are passed through verbatim.
pub type HashTableBucketChainVisitor = unsafe extern "C" fn(
    *mut u8,
    u32,
    Option<unsafe extern "C" fn(u32)>,
    HashTableValueCallback,
    u32,
);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_hash_table_bucket_chain_visitor(
    table: *mut u8,
    mode: u32,
    mode_zero_callback: Option<unsafe extern "C" fn(u32)>,
    callback: HashTableValueCallback,
    context: u32,
) {
    let visit: HashTableBucketChainVisitor =
        core::mem::transmute(HASH_TABLE_BUCKET_CHAIN_VISITOR_ADDRESS);
    visit(table, mode, mode_zero_callback, callback, context);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_hash_table_bucket_chain_visitor(
    _table: *mut u8,
    _mode: u32,
    _mode_zero_callback: Option<unsafe extern "C" fn(u32)>,
    _callback: HashTableValueCallback,
    _context: u32,
) {
    panic!("hash_table_visit_with_context requires visitor 0x080846f4")
}

/// Boundary for the unported bucket-chain visitor. Device builds call its fixed
/// load address; host tests replace this seam to inspect the target ABI.
#[cfg(target_os = "none")]
pub static mut HASH_TABLE_BUCKET_CHAIN_VISITOR: HashTableBucketChainVisitor =
    firmware_hash_table_bucket_chain_visitor;

#[cfg(not(target_os = "none"))]
pub static mut HASH_TABLE_BUCKET_CHAIN_VISITOR: HashTableBucketChainVisitor =
    missing_hash_table_bucket_chain_visitor;

/// `hash_table_visit_with_context` — original `FUN_082d7bd4` @ `0x082d7bd4`.
///
/// Invokes `callback(value, context)` for each value selected by the table's
/// resident bucket-chain visitor. `table` and `callback` must be valid for that
/// visitor; retailOS performs no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_table_visit_with_context(
    table: *mut u8,
    callback: HashTableValueCallback,
    context: u32,
) {
    let visit = core::ptr::read_volatile(addr_of!(HASH_TABLE_BUCKET_CHAIN_VISITOR));
    visit(table, 1, None, callback, context);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: std::vec::Vec<(usize, u32, bool, usize, u32)> = std::vec::Vec::new();

    unsafe extern "C" fn recording_visitor(
        table: *mut u8,
        mode: u32,
        mode_zero_callback: Option<unsafe extern "C" fn(u32)>,
        callback: HashTableValueCallback,
        context: u32,
    ) {
        (*core::ptr::addr_of_mut!(CALLS)).push((
            table as usize,
            mode,
            mode_zero_callback.is_some(),
            callback as usize,
            context,
        ));
    }

    unsafe extern "C" fn callback(_value: u32, _context: u32) {}

    struct SeamGuard;

    impl SeamGuard {
        unsafe fn install() -> Self {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(HASH_TABLE_BUCKET_CHAIN_VISITOR)
                .write_volatile(recording_visitor);
            Self
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(HASH_TABLE_BUCKET_CHAIN_VISITOR)
                    .write_volatile(missing_hash_table_bucket_chain_visitor);
            }
        }
    }

    #[test]
    fn fixes_mode_and_forwards_callback_context_and_table() {
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { SeamGuard::install() };
        for (table, context) in [(core::ptr::null_mut(), 0), (0x1234_5678usize as *mut u8, u32::MAX)] {
            unsafe { hash_table_visit_with_context(table, callback, context) };
        }
        let calls = unsafe { (*core::ptr::addr_of!(CALLS)).clone() };
        assert_eq!(
            calls,
            std::vec![
                (0, 1, false, callback as usize, 0),
                (0x1234_5678, 1, false, callback as usize, u32::MAX),
            ]
        );
    }
}
