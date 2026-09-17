//! The B-tree write-transaction probe — SQLite's per-handle query for an
//! open write transaction, used by halt/reset paths that iterate the
//! `sqlite3.aDb` table and act on handles still mid-write.
//!
//! - `btree_in_write_trans` — original: `FUN_08371bdc` @ 0x08371bdc
//!   (32 bytes; 4 `bl` call sites, binary-scanned: 0x082d6ce0,
//!   0x083824e8, 0x08397100, 0x08397304, all unconditional plain `bl`;
//!   no data word in the image references this address).
//!
//! The body is eight words, verified from osos.dec:
//!
//! ```text
//! cmp r0, #0            ; null handle?
//! beq return_zero
//! ldrb r0, [r0, #8]     ; Btree.inTrans
//! cmp r0, #2            ; TRANS_WRITE
//! moveq r0, #1
//! bxeq lr
//! return_zero:
//! mov r0, #0
//! bx lr
//! ```
//!
//! `Btree` layout pins byte +0x08 as `inTrans` (see sqlite/btree_lock):
//! TRANS_NONE = 0, TRANS_READ = 1, TRANS_WRITE = 2. The original is a
//! strict equality probe: it returns 1 only when `inTrans == TRANS_WRITE`
//! and 0 for every other state, null handle included. All four callers
//! consume the result purely as a nonzero test.

/// Byte offset of `Btree.inTrans` (original: `ldrb r0, [r0, #8]`).
const IN_TRANS_OFFSET: usize = 0x08;
/// SQLite's `TRANS_WRITE` transaction state.
const TRANS_WRITE: u8 = 2;

/// btree_in_write_trans — original: `FUN_08371bdc` @ 0x08371bdc
/// (32 bytes; 4 `bl` call sites, binary-scanned).
///
/// Return 1 when the handle is in a write transaction
/// (`inTrans == TRANS_WRITE`), else 0. A null handle returns 0 without a
/// load.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_in_write_trans(btree: *const u8) -> u32 {
    if btree.is_null() {
        return 0;
    }
    u32::from(btree.add(IN_TRANS_OFFSET).read() == TRANS_WRITE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Btree` handle large enough for the +0x08 byte, word-aligned as
    /// on target.
    #[repr(align(4))]
    struct Handle([u8; 0x10]);

    impl Handle {
        fn new(in_trans: u8) -> Self {
            let mut handle = Handle([0xa5; 0x10]);
            handle.0[IN_TRANS_OFFSET] = in_trans;
            handle
        }
        fn ptr(&self) -> *const u8 {
            self.0.as_ptr()
        }
    }

    #[test]
    fn a_null_handle_reports_no_transaction() {
        assert_eq!(unsafe { btree_in_write_trans(core::ptr::null()) }, 0);
    }

    #[test]
    fn idle_and_read_states_return_zero() {
        for state in [0u8, 1] {
            let handle = Handle::new(state);
            assert_eq!(unsafe { btree_in_write_trans(handle.ptr()) }, 0, "state {state}");
        }
    }

    #[test]
    fn exactly_write_state_returns_one() {
        let handle = Handle::new(TRANS_WRITE);
        assert_eq!(unsafe { btree_in_write_trans(handle.ptr()) }, 1);
    }

    #[test]
    fn states_beyond_write_are_not_write_transactions() {
        // The original is a strict `moveq` equality probe, not a range
        // test: values past TRANS_WRITE still return 0.
        for state in [3u8, 0x7f, 0xff] {
            let handle = Handle::new(state);
            assert_eq!(
                unsafe { btree_in_write_trans(handle.ptr()) },
                0,
                "state {state:#x}"
            );
        }
    }

    #[test]
    fn nothing_is_written() {
        let handle = Handle::new(TRANS_WRITE);
        unsafe { btree_in_write_trans(handle.ptr()) };
        for (i, byte) in handle.0.iter().enumerate() {
            if i != IN_TRANS_OFFSET {
                assert_eq!(*byte, 0xa5, "byte {i:#x} was clobbered");
            }
        }
    }
}
