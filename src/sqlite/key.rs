//! Fetching the key payload bytes of an index b-tree cursor.
//!
//! `btree_key` — original: `FUN_08371c40` @ 0x08371c40 (108 bytes,
//! extent 0x08371c40..0x08371cac ending at the next function's
//! `ldrb r2,[r0,#0x43]` prologue; 2 `bl` instructions in its body,
//! both decoded from osos.dec: `bl 0x08372ae0` and `bl 0x082b2994`;
//! 4 direct `bl` callers, binary-scanned: 0x0836857c, 0x083720b8,
//! 0x08389a7c, 0x0838bd78).
//!
//! SQLite 3.5.x's `sqlite3BtreeKey`:
//!
//! ```c
//! int sqlite3BtreeKey(BtCursor *pCur, u32 offset, u32 amt, void *pBuf);
//! ```
//!
//! IDENTIFICATION — the wrapper restores a REQUIRESEEK/FAULT cursor,
//! rejects table-btree pages, then reads the entry's payload through
//! the still-unported `accessPayload` @ 0x082b2994 with a zeroed
//! `(eOp, skipNext)` stack pair. The callers agree: 0x0836857c is the
//! cursor-saving loop that `bl 0x08371cc4`s [`btree_key_size`], checks
//! `pPage->intKey == 0`, mallocs `nKey` bytes and copies them here —
//! upstream `saveCursorPosition`'s index branch (`sqlite3BtreeKeySize`
//! + `sqlite3BtreeKey`); 0x0838bd78 is `vdbeExec`'s `OP_Column`,
//! where the `beq` selects 0x08370dfc for table cursors and this
//! function for index cursors.
//!
//! Algorithm (verified instruction-by-instruction against osos.dec;
//! Ghidra's `decomp/c/033/08371c40_FUN_08371c40.c` matches, though it
//! misdecodes the second branch target as `FUN_082b2994` — close, but
//! the raw `ebfd033a` resolves to 0x082b2994, so it agrees after all):
//!
//! 1. `ldrb r0,[r0,#0x43]` — cursor `eState` (0 = CURSOR_INVALID, 1 =
//!    CURSOR_VALID, 2 = CURSOR_REQUIRESEEK, 3 = CURSOR_FAULT). Below
//!    CURSOR_REQUIRESEEK (`cmp r0,#2; movcc r0,#0; bcc`) the restore
//!    is skipped and rc = 0 — the body DOES continue, it does not
//!    return early. Otherwise the ported
//!    [`btree_restore_cursor_position`] @ 0x08372ae0 is called
//!    directly.
//! 2. rc != 0 (`cmp r0,#0; bne` to the epilogue) — the restore code
//!    is returned unchanged.
//! 3. `ldr r0,[r4,#0x18]; ldrb r0,[r0,#3]` — `pPage->intKey`
//!    (MemPage +0x03). A table-btree page cannot serve key bytes:
//!    `movne r0,#0xb; bne` returns SQLITE_CORRUPT (11).
//! 4. Otherwise the callee's two stack arguments are zeroed
//!    (`str r3,[sp]; str r3,[sp,#4]` — `eOp = 0`, `skipNext = 0`),
//!    the four register arguments are the originals
//!    (`cursor, offset, amt, buf`), and the result of the
//!    [`BTREE_ACCESS_PAYLOAD_OPS`] dispatch is returned.
//!
//! Deviations: the target `pPage` pointer field is decoded as a `u32`
//! word so the BtCursor layout stays correct on 64-bit hosts. The
//! unported `accessPayload` callee is a volatile dispatch rather than
//! the original direct `bl`; its default reports success without
//! copying any payload, the same constrained stand-in the other
//! unported-seam modules ship. `match.py` consequently shows a resolved
//! slot read in place of the original `bl 0x082b2994`.

use crate::sqlite::restore_cursor_position::btree_restore_cursor_position;

/// `BtCursor.pPage` (+0x18): target MemPage pointer, held as a u32 word.
const CUR_P_PAGE: usize = 0x18;
/// `BtCursor.eState` (+0x43): 0 = CURSOR_INVALID, 1 = CURSOR_VALID,
/// 2 = CURSOR_REQUIRESEEK, 3 = CURSOR_FAULT.
const CUR_E_STATE: usize = 0x43;
/// `MemPage.intKey` (+0x03): nonzero on table-btree pages.
const MP_INT_KEY: usize = 0x03;

const CURSOR_REQUIRESEEK: u8 = 2;
const SQLITE_CORRUPT: i32 = 11;

/// Raw call shape of unported `accessPayload` @ 0x082b2994.
///
/// Four register arguments (`cursor, offset, amt, buf`) plus two
/// outgoing stack words (`eOp`, `skipNext`) that the original zeros
/// with `str r3,[sp]` / `str r3,[sp,#4]`. Modeled here as six scalar
/// parameters; the seam's only job is to preserve the argument values.
#[derive(Clone, Copy)]
pub struct BtreeAccessPayloadOps {
    pub access_payload: unsafe extern "C" fn(
        cursor: *mut u8,
        offset: u32,
        amt: u32,
        buf: *mut u8,
        e_op: u32,
        skip_next: u32,
    ) -> i32,
}

unsafe extern "C" fn missing_access_payload(
    _cursor: *mut u8,
    _offset: u32,
    _amt: u32,
    _buf: *mut u8,
    _e_op: u32,
    _skip_next: u32,
) -> i32 {
    0
}

/// Default while `accessPayload` @ 0x082b2994 remains unported.
pub const DEFAULT_BTREE_ACCESS_PAYLOAD_OPS: BtreeAccessPayloadOps =
    BtreeAccessPayloadOps {
        access_payload: missing_access_payload,
    };

/// Active payload-access service. Tests replace this slot to verify the
/// recovered ABI without dereferencing host pointers stored as target
/// `u32` fields.
pub static mut BTREE_ACCESS_PAYLOAD_OPS: BtreeAccessPayloadOps =
    DEFAULT_BTREE_ACCESS_PAYLOAD_OPS;

#[inline(always)]
unsafe fn access_payload_op() -> unsafe extern "C" fn(
    *mut u8,
    u32,
    u32,
    *mut u8,
    u32,
    u32,
) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_ACCESS_PAYLOAD_OPS.access_payload))
}

#[inline(always)]
unsafe fn rd_u8(base: *const u8, off: usize) -> u8 {
    *base.add(off)
}

#[inline(always)]
unsafe fn rd_u32(base: *const u8, off: usize) -> u32 {
    u32::from_le(base.add(off).cast::<u32>().read_unaligned())
}

/// btree_key — original: `FUN_08371c40` @ 0x08371c40 (108 bytes; 4
/// direct `bl` callers).
///
/// SQLite's `sqlite3BtreeKey`: copy `amt` bytes of the current index
/// entry's key payload, starting at `offset`, into `buf`. Returns a
/// SQLite result code — the restore routine's code when a
/// REQUIRESEEK/FAULT cursor could not be repositioned, SQLITE_CORRUPT
/// (11) when the cursor's page is a table-btree page (`intKey != 0`),
/// and the payload reader's code otherwise.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_key(
    cursor: *mut u8,
    offset: u32,
    amt: u32,
    buf: *mut u8,
) -> i32 {
    // `cmp r0,#0x2; movcc r0,#0x0; bcc` — the restore only runs from
    // CURSOR_REQUIRESEEK up; VALID/INVALID cursors skip it with rc = 0
    // and fall through to the intKey gate.
    let rc = if rd_u8(cursor, CUR_E_STATE) < CURSOR_REQUIRESEEK {
        0
    } else {
        btree_restore_cursor_position(cursor)
    };
    if rc == 0 {
        // `ldr r0,[r4,#0x18]; ldrb r0,[r0,#3]`: key bytes only exist
        // on index pages.
        let page = rd_u32(cursor, CUR_P_PAGE) as usize as *const u8;
        if rd_u8(page, MP_INT_KEY) != 0 {
            return SQLITE_CORRUPT;
        }
        // `str r3,[sp]; str r3,[sp,#4]`: eOp = 0, skipNext = 0.
        return access_payload_op()(cursor, offset, amt, buf, 0, 0);
    }
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::restore_cursor_position::{
        BTREE_MOVETO_OPS, DEFAULT_BTREE_MOVETO_OPS,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, BTREE_CELL_TEST_LOCK};
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec;
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x10000;
    const OFF_PAGE: usize = 0x0000; // 0x60 — fake MemPage
    const OFF_CURSOR: usize = 0x1000; // 0x60 — fake BtCursor
    const OFF_BUF: usize = 0x2000; // payload destination passed verbatim

    /// Restore-routine cursor fields the failing paths touch.
    const CUR_SAVED_KEY: usize = 0x44;
    const CUR_SAVED_RC: usize = 0x50;

    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::BTREE_KEY, SLAB_LEN).map(|p| p as usize));

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct PayloadCall {
        cursor: usize,
        offset: u32,
        amt: u32,
        buf: usize,
        e_op: u32,
        skip_next: u32,
    }

    /// Calls the mock payload reader observed, and the code it returns.
    static PAYLOAD_CALLS: Mutex<Vec<PayloadCall>> = Mutex::new(Vec::new());
    static PAYLOAD_RC: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn mock_access_payload(
        cursor: *mut u8,
        offset: u32,
        amt: u32,
        buf: *mut u8,
        e_op: u32,
        skip_next: u32,
    ) -> i32 {
        PAYLOAD_CALLS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(PayloadCall {
                cursor: cursor as usize,
                offset,
                amt,
                buf: buf as usize,
                e_op,
                skip_next,
            });
        PAYLOAD_RC.load(Ordering::Relaxed)
    }

    /// Movement mock for the restore routine (REQUIRESEEK/FAULT paths).
    static MOVETO_SEEN: Mutex<Vec<usize>> = Mutex::new(Vec::new());
    static MOVETO_RC: AtomicI32 = AtomicI32::new(0);
    static MOVETO_NEW_STATE: AtomicI32 = AtomicI32::new(1);

    unsafe extern "C" fn mock_btree_moveto(
        cursor: *mut u8,
        _saved_key: *mut u8,
        _zero: u32,
        _result: *mut i32,
        _saved_n_key_lo: u32,
        _saved_n_key_hi: u32,
        _bias: u32,
        _result_again: *mut i32,
    ) -> i32 {
        MOVETO_SEEN
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(cursor as usize);
        let new_state = MOVETO_NEW_STATE.load(Ordering::Relaxed);
        if new_state >= 0 {
            *cursor.add(CUR_E_STATE) = new_state as u8;
        }
        MOVETO_RC.load(Ordering::Relaxed)
    }

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        base: *mut u8,
    }

    impl Fixture {
        fn new() -> Option<Self> {
            let guard = BTREE_CELL_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let base = match *SLAB {
                Some(base) => base as *mut u8,
                None => {
                    note_missing_u32_fixture("sqlite::key_tests");
                    return None;
                }
            };
            PAYLOAD_CALLS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            PAYLOAD_RC.store(0, Ordering::Relaxed);
            MOVETO_SEEN
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            MOVETO_RC.store(0, Ordering::Relaxed);
            MOVETO_NEW_STATE.store(1, Ordering::Relaxed);
            unsafe {
                (*core::ptr::addr_of_mut!(BTREE_ACCESS_PAYLOAD_OPS)).access_payload =
                    mock_access_payload;
                (*core::ptr::addr_of_mut!(BTREE_MOVETO_OPS)).moveto = mock_btree_moveto;
                core::ptr::write_bytes(base, 0, SLAB_LEN);
            }
            Some(Fixture { _guard: guard, base })
        }

        fn page(&self) -> *mut u8 {
            unsafe { self.base.add(OFF_PAGE) }
        }

        fn cursor(&self) -> *mut u8 {
            unsafe { self.base.add(OFF_CURSOR) }
        }

        fn buf(&self) -> *mut u8 {
            unsafe { self.base.add(OFF_BUF) }
        }

        /// Wires the cursor fields `btree_key` (and, on REQUIRESEEK,
        /// the restore routine) reads: pPage, eState, a NULL saved key
        /// and a zero saved rc.
        fn wire_cursor(&self, state: u8, int_key: u8) {
            unsafe {
                *self.page().add(MP_INT_KEY) = int_key;
                let cursor = self.cursor();
                cursor
                    .add(CUR_P_PAGE)
                    .cast::<u32>()
                    .write_unaligned((self.page() as usize as u32).to_le());
                *cursor.add(CUR_E_STATE) = state;
                cursor
                    .add(CUR_SAVED_KEY)
                    .cast::<u32>()
                    .write_unaligned(0u32.to_le());
                cursor
                    .add(CUR_SAVED_RC)
                    .cast::<u32>()
                    .write_unaligned(0u32.to_le());
            }
        }

        fn payload_calls(&self) -> Vec<PayloadCall> {
            PAYLOAD_CALLS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        fn moveto_seen(&self) -> Vec<usize> {
            MOVETO_SEEN
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(BTREE_ACCESS_PAYLOAD_OPS)).access_payload =
                    DEFAULT_BTREE_ACCESS_PAYLOAD_OPS.access_payload;
                (*core::ptr::addr_of_mut!(BTREE_MOVETO_OPS)).moveto =
                    DEFAULT_BTREE_MOVETO_OPS.moveto;
            }
        }
    }

    /// CURSOR_INVALID skips the restore routine entirely (`movcc r0,#0;
    /// bcc`) and dispatches the payload reader with the arguments
    /// verbatim and both stack words zeroed.
    #[test]
    fn invalid_state_skips_restore_and_reads_payload() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(0, 0);
        let rc = unsafe { btree_key(f.cursor(), 7, 0x40, f.buf()) };
        assert_eq!(rc, 0);
        assert!(
            f.moveto_seen().is_empty(),
            "state < 2 must not invoke movement through the restore routine"
        );
        assert_eq!(
            f.payload_calls(),
            vec![PayloadCall {
                cursor: f.cursor() as usize,
                offset: 7,
                amt: 0x40,
                buf: f.buf() as usize,
                e_op: 0,
                skip_next: 0,
            }],
            "the original's zeroed eOp/skipNext stack words are part of the ABI"
        );
    }

    /// CURSOR_VALID (1) is also below REQUIRESEEK — the restore is a
    /// state < 2 gate, not a state == 0 gate.
    #[test]
    fn valid_state_skips_restore_too() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(1, 0);
        let rc = unsafe { btree_key(f.cursor(), 0, 3, f.buf()) };
        assert_eq!(rc, 0);
        assert!(f.moveto_seen().is_empty());
        assert_eq!(f.payload_calls().len(), 1);
        assert_eq!(f.payload_calls()[0].amt, 3);
    }

    /// A REQUIRESEEK cursor goes through the ported restore routine; a
    /// failing movement operation propagates and the payload reader is
    /// never reached (`cmp r0,#0; bne` to the epilogue).
    #[test]
    fn restore_failure_propagates_and_skips_payload() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(2, 0);
        MOVETO_RC.store(6, Ordering::Relaxed);
        let rc = unsafe { btree_key(f.cursor(), 0, 0x10, f.buf()) };
        assert_eq!(rc, 6, "the movement result is the return value");
        assert_eq!(
            f.moveto_seen(),
            vec![f.cursor() as usize],
            "movement receives the cursor, once"
        );
        assert!(
            f.payload_calls().is_empty(),
            "rc != 0 must not reach the payload reader"
        );
    }

    /// A REQUIRESEEK cursor that the restore routine repositions
    /// successfully continues to the payload reader.
    #[test]
    fn restore_success_reads_payload() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(2, 0);
        MOVETO_NEW_STATE.store(1, Ordering::Relaxed);
        let rc = unsafe { btree_key(f.cursor(), 0, 0x20, f.buf()) };
        assert_eq!(rc, 0);
        assert_eq!(f.moveto_seen(), vec![f.cursor() as usize]);
        assert_eq!(f.payload_calls().len(), 1);
    }

    /// CURSOR_FAULT (3) also enters the restore routine; it returns the
    /// saved rc without movement, and a nonzero saved rc skips the
    /// payload reader.
    #[test]
    fn fault_state_returns_saved_rc() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(3, 0);
        unsafe {
            f.cursor()
                .add(CUR_SAVED_RC)
                .cast::<u32>()
                .write_unaligned(9u32.to_le());
        }
        let rc = unsafe { btree_key(f.cursor(), 0, 0x10, f.buf()) };
        assert_eq!(rc, 9, "a FAULT cursor reports its saved error");
        assert!(f.moveto_seen().is_empty());
        assert!(f.payload_calls().is_empty());
    }

    /// A table-btree page (`intKey != 0`) cannot serve key bytes:
    /// SQLITE_CORRUPT (11) from `movne r0,#0xb; bne`, with no payload
    /// reader call. Holds even when no restore ran (VALID state).
    #[test]
    fn table_page_is_corrupt_without_reading_payload() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(1, 1);
        let rc = unsafe { btree_key(f.cursor(), 0, 0x10, f.buf()) };
        assert_eq!(rc, SQLITE_CORRUPT);
        assert!(f.payload_calls().is_empty());
    }

    /// The intKey gate runs after a successful restore as well: a
    /// REQUIRESEEK cursor repositioned onto a table page is corrupt.
    #[test]
    fn table_page_after_restore_is_corrupt() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(2, 1);
        let rc = unsafe { btree_key(f.cursor(), 0, 0x10, f.buf()) };
        assert_eq!(rc, SQLITE_CORRUPT);
        assert_eq!(f.moveto_seen(), vec![f.cursor() as usize]);
        assert!(f.payload_calls().is_empty());
    }

    /// The payload reader's own result (e.g. SQLITE_DONE's 1 on a
    /// short payload) is returned unchanged.
    #[test]
    fn payload_reader_rc_propagates() {
        let Some(f) = Fixture::new() else { return };
        f.wire_cursor(1, 0);
        PAYLOAD_RC.store(1, Ordering::Relaxed);
        let rc = unsafe { btree_key(f.cursor(), 0, 0x10, f.buf()) };
        assert_eq!(rc, 1);
        assert_eq!(f.payload_calls().len(), 1);
    }
}
