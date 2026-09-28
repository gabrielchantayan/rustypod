//! Fetching an index b-tree cursor's in-page key pointer.
//!
//! `btree_key_fetch` — original: `FUN_08370e54` @ 0x08370e54 (24 bytes;
//! 2 direct `bl` callers; 0 plain and 0 predicated `bl` instructions,
//! decoded from `osos.dec`).
//!
//! SQLite 3.5.x's `sqlite3BtreeKeyFetch` returns null unless the cursor is
//! valid. For a valid cursor it tail-calls `fetchPayload(cursor, out, 1)` at
//! 0x082cdedc; one selects index-key rather than table-data payload.
//!
//! Deliberate deviation: `fetchPayload` is not ported, so its direct branch is
//! represented by the existing volatile dispatch seam. The seam preserves the
//! target's three register arguments and has a null default; it does not
//! emulate payload parsing or pointer arithmetic.

use crate::sqlite::data_fetch::BTREE_FETCH_PAYLOAD_OPS;

/// `BtCursor.eState`: `CURSOR_VALID` is exactly one.
const CUR_E_STATE: usize = 0x43;
const CURSOR_VALID: u8 = 1;

#[inline(always)]
unsafe fn fetch_payload_op() -> unsafe extern "C" fn(*mut u8, *mut u32, u32) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_FETCH_PAYLOAD_OPS.fetch_payload))
}

/// btree_key_fetch — original: `FUN_08370e54` @ 0x08370e54 (24 bytes; 2
/// direct `bl` callers; 0 plain and 0 predicated `bl` instructions in body).
///
/// SQLite's `sqlite3BtreeKeyFetch`: return a pointer to the current index
/// entry's local key and write its available byte count through `out`.
/// Invalid, REQUIRESEEK, and FAULT cursors return null without touching `out`.
/// A VALID cursor tail-calls `fetchPayload(cursor, out, 1)`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_key_fetch(cursor: *mut u8, out: *mut u32) -> *mut u8 {
    if *cursor.add(CUR_E_STATE) != CURSOR_VALID {
        return core::ptr::null_mut();
    }
    fetch_payload_op()(cursor, out, 1)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::data_fetch::{BtreeFetchPayloadOps, DEFAULT_BTREE_FETCH_PAYLOAD_OPS};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DISPATCH_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    static SEEN_CURSOR: AtomicUsize = AtomicUsize::new(0);
    static SEEN_OUT: AtomicUsize = AtomicUsize::new(0);
    static SEEN_SKIP_KEY: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn fetch_fixture(cursor: *mut u8, out: *mut u32, skip_key: u32) -> *mut u8 {
        SEEN_CURSOR.store(cursor as usize, Ordering::Relaxed);
        SEEN_OUT.store(out as usize, Ordering::Relaxed);
        SEEN_SKIP_KEY.store(skip_key as usize, Ordering::Relaxed);
        0x1234_5678usize as *mut u8
    }

    #[test]
    fn non_valid_cursor_returns_null_without_dispatching() {
        let _guard = DISPATCH_LOCK.lock();
        let mut cursor = [0u8; CUR_E_STATE + 1];
        let mut out = 0xfeed_beefu32;
        SEEN_SKIP_KEY.store(usize::MAX, Ordering::Relaxed);

        unsafe {
            BTREE_FETCH_PAYLOAD_OPS = BtreeFetchPayloadOps { fetch_payload: fetch_fixture };
            for state in [0, 2, 3, 0xff] {
                cursor[CUR_E_STATE] = state;
                assert!(btree_key_fetch(cursor.as_mut_ptr(), &mut out).is_null());
                assert_eq!(out, 0xfeed_beef);
            }
            BTREE_FETCH_PAYLOAD_OPS = DEFAULT_BTREE_FETCH_PAYLOAD_OPS;
        }

        assert_eq!(SEEN_SKIP_KEY.load(Ordering::Relaxed), usize::MAX);
    }

    #[test]
    fn valid_cursor_tail_dispatches_index_key_arguments() {
        let _guard = DISPATCH_LOCK.lock();
        let mut cursor = [0u8; CUR_E_STATE + 1];
        let mut out = 0u32;
        cursor[CUR_E_STATE] = CURSOR_VALID;

        unsafe {
            BTREE_FETCH_PAYLOAD_OPS = BtreeFetchPayloadOps { fetch_payload: fetch_fixture };
            assert_eq!(btree_key_fetch(cursor.as_mut_ptr(), &mut out), 0x1234_5678usize as *mut u8);
            BTREE_FETCH_PAYLOAD_OPS = DEFAULT_BTREE_FETCH_PAYLOAD_OPS;
        }

        assert_eq!(SEEN_CURSOR.load(Ordering::Relaxed), cursor.as_mut_ptr() as usize);
        assert_eq!(SEEN_OUT.load(Ordering::Relaxed), &mut out as *mut u32 as usize);
        assert_eq!(SEEN_SKIP_KEY.load(Ordering::Relaxed), 1);
    }
}
