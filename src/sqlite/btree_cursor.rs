//! Open a cursor on a SQLite B-tree.
//!
//! `btree_cursor` — retailOS `FUN_08370db4` at `0x08370db4` (72 bytes;
//! `0x08370db4..0x08370df8`, followed by the distinct function beginning at
//! `0x08370dfc`). Five unconditional plain-`bl` call sites reach it
//! (`0x08368704`, `0x0837b6f0`, `0x08388c88`, `0x08388f08`, and
//! `0x08388f5c`); decoding every ARM B/BL word in `osos.dec` found no
//! predicated calls.
//!
//! This is SQLite's `sqlite3BtreeCursor`: enter the B-tree, associate its
//! shared B-tree object with the caller's connection, open the internal
//! cursor, then leave the B-tree and return the internal cursor status. The
//! internal `btreeCursor` implementation at `0x082bdba0` is unported, so the
//! target calls it at its original address. Host tests use a dispatch seam to
//! model that unavailable boundary and the existing enter/leave ports, whose
//! target byte-offset layout cannot compose with widened host pointers.

use crate::sqlite::btree_get_meta::{Btree, BtreeShared};
use crate::sqlite::btree_lock::{btree_enter, btree_leave};

type BtreeCursorInner = unsafe extern "C" fn(*mut Btree, i64, i32, *mut u8, *mut u8) -> i32;
type BtreeBoundary = unsafe extern "C" fn(*mut Btree);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn open_cursor_inner(
    btree: *mut Btree,
    table: i64,
    write: i32,
    key_info: *mut u8,
    cursor: *mut u8,
) -> i32 {
    let open_cursor: BtreeCursorInner = core::mem::transmute(0x082b_dba0usize);
    open_cursor(btree, table, write, key_info, cursor)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_open_cursor(
    _btree: *mut Btree,
    _table: i64,
    _write: i32,
    _key_info: *mut u8,
    _cursor: *mut u8,
) -> i32 {
    11
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_btree_boundary(_btree: *mut Btree) {}

/// Host models for the three target call boundaries. The direct target calls
/// preserve the original order; host indirection prevents widened pointers
/// from being interpreted through the target-only lock helper offsets.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeCursorOps {
    enter: BtreeBoundary,
    open_cursor: BtreeCursorInner,
    leave: BtreeBoundary,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_BTREE_CURSOR_OPS: BtreeCursorOps = BtreeCursorOps {
    enter: unavailable_btree_boundary,
    open_cursor: unavailable_open_cursor,
    leave: unavailable_btree_boundary,
};

#[cfg(not(target_os = "none"))]
static mut BTREE_CURSOR_OPS: BtreeCursorOps = DEFAULT_BTREE_CURSOR_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeCursorOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CURSOR_OPS))
}

/// `sqlite3BtreeCursor` — retailOS `FUN_08370db4` @ `0x08370db4` (72 bytes;
/// 5 direct unconditional plain-`bl` call sites).
///
/// Opens `cursor` on `table`, forwarding the signed 64-bit table number,
/// write flag, and key-info pointer to the internal cursor constructor. The
/// shared B-tree's `db` pointer is refreshed before that constructor runs.
/// The leave operation always executes, including when opening returns an
/// error. `btree`, its shared object, and every pointer passed to the internal
/// constructor must be live: the retail code dereferences them without guards.
///
/// Deliberate host-only deviation: enter, leave, and the unported internal
/// constructor use a test dispatch table. The device build directly calls the
/// existing ports and absolute retail address `0x082bdba0`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.btree_cursor")]
#[inline(never)]
pub unsafe extern "C" fn btree_cursor(
    btree: *mut Btree,
    table: i64,
    write: i32,
    key_info: *mut u8,
    cursor: *mut u8,
) -> i32 {
    #[cfg(target_os = "none")]
    btree_enter(btree.cast());
    #[cfg(not(target_os = "none"))]
    (host_ops().enter)(btree);

    let shared: *mut BtreeShared = (*btree).shared;
    (*shared).db = (*btree).db;

    #[cfg(target_os = "none")]
    let status = open_cursor_inner(btree, table, write, key_info, cursor);
    #[cfg(not(target_os = "none"))]
    let status = (host_ops().open_cursor)(btree, table, write, key_info, cursor);

    #[cfg(target_os = "none")]
    btree_leave(btree.cast());
    #[cfg(not(target_os = "none"))]
    (host_ops().leave)(btree);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 3] = [0; 3];
    static mut EVENT_COUNT: usize = 0;
    static mut STATUS: i32 = 0;
    static mut EXPECTED_BTREE: *mut Btree = core::ptr::null_mut();
    static mut EXPECTED_TABLE: i64 = 0;
    static mut EXPECTED_WRITE: i32 = 0;
    static mut EXPECTED_KEY_INFO: *mut u8 = core::ptr::null_mut();
    static mut EXPECTED_CURSOR: *mut u8 = core::ptr::null_mut();

    unsafe fn record(event: u8) {
        EVENTS[EVENT_COUNT] = event;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn recording_enter(btree: *mut Btree) {
        assert_eq!(btree, EXPECTED_BTREE);
        assert_ne!((*btree).shared, core::ptr::null_mut());
        assert_eq!((*(*btree).shared).db, core::ptr::null_mut());
        record(1);
    }

    unsafe extern "C" fn recording_open_cursor(
        btree: *mut Btree,
        table: i64,
        write: i32,
        key_info: *mut u8,
        cursor: *mut u8,
    ) -> i32 {
        assert_eq!(btree, EXPECTED_BTREE);
        assert_eq!(table, EXPECTED_TABLE);
        assert_eq!(write, EXPECTED_WRITE);
        assert_eq!(key_info, EXPECTED_KEY_INFO);
        assert_eq!(cursor, EXPECTED_CURSOR);
        assert_eq!((*(*btree).shared).db, (*btree).db);
        record(2);
        STATUS
    }

    unsafe extern "C" fn recording_leave(btree: *mut Btree) {
        assert_eq!(btree, EXPECTED_BTREE);
        record(3);
    }

    struct Bench {
        _guard: MutexGuard<'static, ()>,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(BTREE_CURSOR_OPS),
                    DEFAULT_BTREE_CURSOR_OPS,
                );
            }
        }
    }

    fn bench(
        btree: *mut Btree,
        table: i64,
        write: i32,
        key_info: *mut u8,
        cursor: *mut u8,
        status: i32,
    ) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            EVENTS = [0; 3];
            EVENT_COUNT = 0;
            STATUS = status;
            EXPECTED_BTREE = btree;
            EXPECTED_TABLE = table;
            EXPECTED_WRITE = write;
            EXPECTED_KEY_INFO = key_info;
            EXPECTED_CURSOR = cursor;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(BTREE_CURSOR_OPS),
                BtreeCursorOps {
                    enter: recording_enter,
                    open_cursor: recording_open_cursor,
                    leave: recording_leave,
                },
            );
        }
        Bench { _guard: guard }
    }

    struct Fixture {
        btree: Btree,
        shared: BtreeShared,
        db: [u8; 1],
        key_info: [u8; 1],
        cursor: [u8; 1],
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                btree: Btree {
                    db: core::ptr::null_mut(),
                    shared: core::ptr::null_mut(),
                },
                shared: BtreeShared {
                    page_cache: core::ptr::null_mut(),
                    db: core::ptr::null_mut(),
                },
                db: [0; 1],
                key_info: [0; 1],
                cursor: [0; 1],
            }
        }

        fn wire(&mut self) {
            self.btree.db = self.db.as_mut_ptr();
            self.btree.shared = &mut self.shared;
        }
    }

    #[test]
    fn opens_cursor_after_enter_and_refreshes_shared_connection() {
        let mut fixture = Fixture::new();
        fixture.wire();
        let table = -0x0123_4567_89ab_cdefi64;
        let _bench = bench(
            &mut fixture.btree,
            table,
            1,
            fixture.key_info.as_mut_ptr(),
            fixture.cursor.as_mut_ptr(),
            0,
        );

        let status = unsafe {
            btree_cursor(
                &mut fixture.btree,
                table,
                1,
                fixture.key_info.as_mut_ptr(),
                fixture.cursor.as_mut_ptr(),
            )
        };

        assert_eq!(status, 0);
        assert_eq!(fixture.shared.db, fixture.btree.db);
        unsafe {
            assert_eq!(EVENT_COUNT, 3);
            assert_eq!(EVENTS, [1, 2, 3]);
        }
    }

    #[test]
    fn leaves_after_internal_cursor_error() {
        let mut fixture = Fixture::new();
        fixture.wire();
        let _bench = bench(
            &mut fixture.btree,
            0x1_0000_0001,
            0,
            fixture.key_info.as_mut_ptr(),
            fixture.cursor.as_mut_ptr(),
            8,
        );

        let status = unsafe {
            btree_cursor(
                &mut fixture.btree,
                0x1_0000_0001,
                0,
                fixture.key_info.as_mut_ptr(),
                fixture.cursor.as_mut_ptr(),
            )
        };

        assert_eq!(status, 8);
        unsafe {
            assert_eq!(EVENT_COUNT, 3);
            assert_eq!(EVENTS, [1, 2, 3]);
        }
    }
}
