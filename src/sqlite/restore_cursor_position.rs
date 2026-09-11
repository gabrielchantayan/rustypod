//! Restoring a b-tree cursor's saved position.
//!
//! `btree_restore_cursor_position` — original: `FUN_08372ae0` @
//! 0x08372ae0 (112 bytes; 8 direct `bl` callers, binary-scanned:
//! 0x08370e24, 0x08370e8c, 0x08370f74, 0x08371c68, 0x08371ce4,
//! 0x083722a8, 0x08372934, plus the caller-gated `blcs` at 0x08371314).
//!
//! The function returns the saved error for a FAULT cursor (`eState == 3`),
//! returns SQLITE_ABORT (4) for an incremental-blob cursor, or otherwise
//! invalidates the cursor, repositions it through `sqlite3BtreeMoveto`, and
//! releases the saved key only after a successful reposition. The movement
//! callee at 0x08371e54 is not yet ported; its raw eight-word ABI is exposed
//! through [`BTREE_MOVETO_OPS`]. Its default reports success without moving a
//! cursor, the same constrained stand-in the prior unported wrapper used.
//!
//! Deliberate deviations: target pointer fields are decoded as `u32` words so
//! the BtCursor offsets remain correct on 64-bit hosts. The unported movement
//! call is a volatile dispatch rather than the original direct `bl`.

use crate::heap::tracked::tracked_free;

const CUR_E_STATE: usize = 0x43;
const CUR_SAVED_KEY: usize = 0x44;
const CUR_SAVED_N_KEY: usize = 0x48;
const CUR_SAVED_RC: usize = 0x50;
const CUR_IS_INCRBLOB_HANDLE: usize = 0x54;
const CURSOR_FAULT: u8 = 3;
const SQLITE_ABORT: i32 = 4;

/// Raw call shape of unported `sqlite3BtreeMoveto` @ 0x08371e54.
///
/// The caller passes `cursor`, saved key, zero, and `cursor + 0x50` in r0-r3;
/// its 16-byte outgoing stack area contains saved `nKey` low/high, zero, and
/// `cursor + 0x50` again. Ghidra presents this as eight word arguments, and
/// the raw ARM setup verifies each one.
#[derive(Clone, Copy)]
pub struct BtreeMovetoOps {
    pub moveto: unsafe extern "C" fn(
        cursor: *mut u8,
        saved_key: *mut u8,
        zero: u32,
        result: *mut i32,
        saved_n_key_lo: u32,
        saved_n_key_hi: u32,
        bias: u32,
        result_again: *mut i32,
    ) -> i32,
}

unsafe extern "C" fn missing_btree_moveto(
    _cursor: *mut u8,
    _saved_key: *mut u8,
    _zero: u32,
    _result: *mut i32,
    _saved_n_key_lo: u32,
    _saved_n_key_hi: u32,
    _bias: u32,
    _result_again: *mut i32,
) -> i32 {
    0
}

/// Default while `sqlite3BtreeMoveto` @ 0x08371e54 remains unported.
pub const DEFAULT_BTREE_MOVETO_OPS: BtreeMovetoOps = BtreeMovetoOps {
    moveto: missing_btree_moveto,
};

/// Active movement service. Tests replace this slot to verify the recovered
/// ABI without dereferencing host pointers stored as target `u32` fields.
pub static mut BTREE_MOVETO_OPS: BtreeMovetoOps = DEFAULT_BTREE_MOVETO_OPS;

#[inline(always)]
unsafe fn btree_moveto_op() -> unsafe extern "C" fn(
    *mut u8,
    *mut u8,
    u32,
    *mut i32,
    u32,
    u32,
    u32,
    *mut i32,
) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_MOVETO_OPS.moveto))
}

#[inline(always)]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le(base.add(offset).cast::<u32>().read())
}

/// btree_restore_cursor_position — original: `FUN_08372ae0` @ 0x08372ae0
/// (112 bytes; 8 direct `bl` callers).
///
/// SQLite's `sqlite3BtreeRestoreOrClearCursorPosition`: return a saved fault
/// result or SQLITE_ABORT without mutation; otherwise clear `eState`, invoke
/// the saved-position movement operation, and on success free and clear the
/// saved key pointer. The movement result is returned unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_restore_cursor_position(cursor: *mut u8) -> i32 {
    if *cursor.add(CUR_E_STATE) == CURSOR_FAULT {
        return read_u32(cursor, CUR_SAVED_RC) as i32;
    }
    if *cursor.add(CUR_IS_INCRBLOB_HANDLE) != 0 {
        return SQLITE_ABORT;
    }

    *cursor.add(CUR_E_STATE) = 0;
    let saved_key = read_u32(cursor, CUR_SAVED_KEY) as usize as *mut u8;
    let result = cursor.add(CUR_SAVED_RC).cast::<i32>();
    let rc = btree_moveto_op()(
        cursor,
        saved_key,
        0,
        result,
        read_u32(cursor, CUR_SAVED_N_KEY),
        read_u32(cursor, CUR_SAVED_N_KEY + 4),
        0,
        result,
    );
    if rc == 0 {
        tracked_free(saved_key.cast());
        cursor.add(CUR_SAVED_KEY).cast::<u32>().write(0);
    }
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, BTREE_CELL_TEST_LOCK};
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec::Vec;
    use std::vec;

    const SLAB_LEN: usize = 0x10000;
    const OFF_CURSOR: usize = 0x1000;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_RESTORE_CURSOR, SLAB_LEN).map(|p| p as usize)
    });
    static MOVETO_RC: AtomicI32 = AtomicI32::new(0);
    static MOVETO_CALLS: Mutex<Vec<MovetoCall>> = Mutex::new(Vec::new());

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct MovetoCall {
        cursor: usize,
        saved_key: usize,
        zero: u32,
        result: usize,
        saved_n_key_lo: u32,
        saved_n_key_hi: u32,
        bias: u32,
        result_again: usize,
    }

    unsafe extern "C" fn mock_moveto(
        cursor: *mut u8,
        saved_key: *mut u8,
        zero: u32,
        result: *mut i32,
        saved_n_key_lo: u32,
        saved_n_key_hi: u32,
        bias: u32,
        result_again: *mut i32,
    ) -> i32 {
        MOVETO_CALLS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(MovetoCall {
                cursor: cursor as usize,
                saved_key: saved_key as usize,
                zero,
                result: result as usize,
                saved_n_key_lo,
                saved_n_key_hi,
                bias,
                result_again: result_again as usize,
            });
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
                    note_missing_u32_fixture("sqlite::restore_cursor_position_tests");
                    return None;
                }
            };
            MOVETO_CALLS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            MOVETO_RC.store(0, Ordering::Relaxed);
            unsafe {
                core::ptr::write_bytes(base, 0, SLAB_LEN);
                (*core::ptr::addr_of_mut!(BTREE_MOVETO_OPS)).moveto = mock_moveto;
            }
            Some(Self { _guard: guard, base })
        }

        fn cursor(&self) -> *mut u8 {
            unsafe { self.base.add(OFF_CURSOR) }
        }

        fn calls(&self) -> Vec<MovetoCall> {
            MOVETO_CALLS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        unsafe fn write_u32(&self, offset: usize, value: u32) {
            self.cursor().add(offset).cast::<u32>().write(value.to_le());
        }

        unsafe fn read_u32(&self, offset: usize) -> u32 {
            u32::from_le(self.cursor().add(offset).cast::<u32>().read())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(BTREE_MOVETO_OPS)).moveto =
                    DEFAULT_BTREE_MOVETO_OPS.moveto;
            }
        }
    }

    #[test]
    fn fault_returns_saved_code_without_calling_moveto() {
        let Some(fixture) = Fixture::new() else { return };
        unsafe {
            *fixture.cursor().add(CUR_E_STATE) = CURSOR_FAULT;
            *fixture.cursor().add(CUR_IS_INCRBLOB_HANDLE) = 1;
            fixture.write_u32(CUR_SAVED_RC, (-19i32) as u32);
            fixture.write_u32(CUR_SAVED_KEY, 0x1234_5678);
        }

        assert_eq!(unsafe { btree_restore_cursor_position(fixture.cursor()) }, -19);
        assert!(fixture.calls().is_empty());
        assert_eq!(unsafe { *fixture.cursor().add(CUR_E_STATE) }, CURSOR_FAULT);
        assert_eq!(unsafe { fixture.read_u32(CUR_SAVED_KEY) }, 0x1234_5678);
    }

    #[test]
    fn incremental_blob_returns_abort_without_invalidating_cursor() {
        let Some(fixture) = Fixture::new() else { return };
        unsafe {
            *fixture.cursor().add(CUR_E_STATE) = 2;
            *fixture.cursor().add(CUR_IS_INCRBLOB_HANDLE) = 1;
        }

        assert_eq!(unsafe { btree_restore_cursor_position(fixture.cursor()) }, SQLITE_ABORT);
        assert!(fixture.calls().is_empty());
        assert_eq!(unsafe { *fixture.cursor().add(CUR_E_STATE) }, 2);
    }

    #[test]
    fn successful_restore_passes_the_recovered_eight_word_abi_and_clears_key() {
        let Some(fixture) = Fixture::new() else { return };
        unsafe {
            *fixture.cursor().add(CUR_E_STATE) = 2;
            fixture.write_u32(CUR_SAVED_KEY, 0);
            fixture.write_u32(CUR_SAVED_N_KEY, 0x89ab_cdef);
            fixture.write_u32(CUR_SAVED_N_KEY + 4, 0x0123_4567);
            fixture.write_u32(CUR_SAVED_RC, 0x7654_3210);
        }

        assert_eq!(unsafe { btree_restore_cursor_position(fixture.cursor()) }, 0);
        assert_eq!(unsafe { *fixture.cursor().add(CUR_E_STATE) }, 0);
        assert_eq!(unsafe { fixture.read_u32(CUR_SAVED_KEY) }, 0);
        assert_eq!(
            fixture.calls(),
            vec![MovetoCall {
                cursor: fixture.cursor() as usize,
                saved_key: 0,
                zero: 0,
                result: unsafe { fixture.cursor().add(CUR_SAVED_RC) as usize },
                saved_n_key_lo: 0x89ab_cdef,
                saved_n_key_hi: 0x0123_4567,
                bias: 0,
                result_again: unsafe { fixture.cursor().add(CUR_SAVED_RC) as usize },
            }]
        );
    }

    #[test]
    fn failed_restore_keeps_saved_key_but_leaves_cursor_invalid() {
        let Some(fixture) = Fixture::new() else { return };
        MOVETO_RC.store(5, Ordering::Relaxed);
        unsafe {
            *fixture.cursor().add(CUR_E_STATE) = 1;
            fixture.write_u32(CUR_SAVED_KEY, 0x1000_2000);
        }

        assert_eq!(unsafe { btree_restore_cursor_position(fixture.cursor()) }, 5);
        assert_eq!(unsafe { *fixture.cursor().add(CUR_E_STATE) }, 0);
        assert_eq!(unsafe { fixture.read_u32(CUR_SAVED_KEY) }, 0x1000_2000);
        assert_eq!(fixture.calls().len(), 1);
    }
}
