//! Copying table payload bytes from a B-tree cursor.
//!
//! `btree_data` — retailOS `FUN_08370dfc` @ `0x08370dfc` (88 bytes;
//! 2 unconditional plain `bl` instructions and no predicated `bl`
//! instructions, decoded from `osos.dec`).
//!
//! SQLite 3.5.9's `sqlite3BtreeData`: a VALID or INVALID cursor dispatches
//! table-data mode to `accessPayload`; a REQUIRESEEK or FAULT cursor is first
//! restored, and a restore failure is returned without accessing payload.
//!
//! Deliberate deviation: the unported `accessPayload` @ `0x082b2994` remains
//! the volatile dispatch seam owned by `key`; target builds consequently use a
//! seam call rather than the retail direct `bl`.

use crate::sqlite::key::access_payload_op;
use crate::sqlite::restore_cursor_position::btree_restore_cursor_position;

/// `BtCursor.eState` (+0x43): 2 is CURSOR_REQUIRESEEK.
const CUR_E_STATE: usize = 0x43;
const CURSOR_REQUIRESEEK: u8 = 2;

/// `sqlite3BtreeData` — retailOS `FUN_08370dfc` @ `0x08370dfc` (88 bytes;
/// 2 unconditional plain `bl` instructions, no predicated calls).
///
/// Copies `amt` bytes at `offset` from the current table entry into `buf`.
/// Cursors below REQUIRESEEK skip restoration; higher states restore first.
/// A nonzero restoration result is returned unchanged. Successful paths call
/// `accessPayload(cursor, offset, amt, buf, 1, 0)`, where one selects table
/// data instead of index-key payload.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_data(
    cursor: *mut u8,
    offset: u32,
    amt: u32,
    buf: *mut u8,
) -> i32 {
    let rc = if *cursor.add(CUR_E_STATE) < CURSOR_REQUIRESEEK {
        0
    } else {
        btree_restore_cursor_position(cursor)
    };
    if rc != 0 {
        return rc;
    }
    access_payload_op()(cursor, offset, amt, buf, 1, 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::key::{BtreeAccessPayloadOps, BTREE_ACCESS_PAYLOAD_OPS, DEFAULT_BTREE_ACCESS_PAYLOAD_OPS};
    use crate::testing::BTREE_CELL_TEST_LOCK;
    use std::sync::Mutex;

    static SEEN: Mutex<Option<(usize, u32, u32, usize, u32, u32)>> = Mutex::new(None);

    unsafe extern "C" fn payload_fixture(
        cursor: *mut u8,
        offset: u32,
        amt: u32,
        buf: *mut u8,
        e_op: u32,
        skip_next: u32,
    ) -> i32 {
        *SEEN.lock().unwrap_or_else(|error| error.into_inner()) =
            Some((cursor as usize, offset, amt, buf as usize, e_op, skip_next));
        -17
    }

    struct PayloadSeam;

    impl PayloadSeam {
        unsafe fn install() -> Self {
            BTREE_ACCESS_PAYLOAD_OPS = BtreeAccessPayloadOps { access_payload: payload_fixture };
            Self
        }
    }

    impl Drop for PayloadSeam {
        fn drop(&mut self) {
            unsafe { BTREE_ACCESS_PAYLOAD_OPS = DEFAULT_BTREE_ACCESS_PAYLOAD_OPS; }
        }
    }

    #[test]
    fn valid_cursor_forwards_table_mode_and_payload_arguments() {
        let _lock = BTREE_CELL_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut cursor = [0u8; CUR_E_STATE + 1];
        let mut buf = [0u8; 7];
        cursor[CUR_E_STATE] = 1;
        *SEEN.lock().unwrap_or_else(|error| error.into_inner()) = None;
        let _seam = unsafe { PayloadSeam::install() };

        assert_eq!(unsafe { btree_data(cursor.as_mut_ptr(), 0x1234_5678, 7, buf.as_mut_ptr()) }, -17);
        assert_eq!(
            *SEEN.lock().unwrap_or_else(|error| error.into_inner()),
            Some((cursor.as_mut_ptr() as usize, 0x1234_5678, 7, buf.as_mut_ptr() as usize, 1, 0)),
        );
    }

    #[test]
    fn cursor_fault_returns_saved_error_without_payload_access() {
        let _lock = BTREE_CELL_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut cursor = [0u8; 0x54];
        cursor[CUR_E_STATE] = 3;
        cursor[0x50..0x54].copy_from_slice(&(-9i32).to_le_bytes());
        *SEEN.lock().unwrap_or_else(|error| error.into_inner()) = None;
        let _seam = unsafe { PayloadSeam::install() };

        assert_eq!(unsafe { btree_data(cursor.as_mut_ptr(), 0, 0, core::ptr::null_mut()) }, -9);
        assert_eq!(*SEEN.lock().unwrap_or_else(|error| error.into_inner()), None);
    }
}
