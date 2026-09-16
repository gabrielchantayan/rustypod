//! Update a B-tree's persistent metadata — retailOS `FUN_08372dd4` at
//! `0x08372dd4` (128 bytes).
//!
//! Raw ARM establishes the exact extent: `push {r4-r10,lr}` begins at
//! `0x08372dd4`, its `pop {r4-r10,pc}` is at `0x08372e50`, and the distinct
//! next function's `push {r3-r7,lr}` prologue begins at `0x08372e54`. The
//! body is exactly 32 words (128 bytes), matching Ghidra. Decoding every ARM
//! B/BL word in `osos.dec` finds four plain-`bl` callers of this entry
//! (`0x082bdb38`, `0x082bde68`, `0x08382a88`, `0x08388ad0`), and the body
//! itself makes exactly four `bl` calls, all unconditional (`btree_enter`,
//! `pager_write` @ `0x0837ef64`, `store_be32`, `btree_leave`); no
//! predicated call reaches or leaves this function.
//!
//! This is SQLite's `sqlite3BtreeUpdateMeta`. It enters the B-tree, records
//! the caller's connection in the shared page-cache object (`pBt->db = p->db`),
//! then either writes or fails:
//!
//! - If the handle is not in a write transaction (`p->inTrans != TRANS_WRITE`),
//!   the result is `SQLITE_ERROR` (1) when the shared cache is writable and
//!   `SQLITE_READONLY` (8) when its `readOnly` byte is set.
//! - Otherwise it marks root page one dirty via `sqlite3PagerWrite` on the
//!   page's `DbPage`, and on success stores the new value big-endian at page
//!   offset `0x24 + index * 4` (database header words 9..15). Index 7
//!   additionally latches the value's low byte into the shared cache's
//!   `incrVacuum` flag at +0x17.
//!
//! The B-tree is left on every path and the status returned.
//!
//! Deliberate host-only deviation: on target the ported `btree_enter` /
//! `btree_leave` are called directly and the still-unported
//! `sqlite3PagerWrite` is an absolute call at `0x0837ef64`. Host builds route
//! all three service boundaries through a private dispatch table: a host
//! `Btree` widens its adjacent pointer fields, while the older lock port
//! intentionally uses target byte offsets, so direct host composition would
//! make `inTrans` overlap `pBt`. The dispatch preserves the observable call
//! order and lets tests model the pager without inventing a second host
//! layout. `store_be32` is a pure helper and links directly on both targets.

use crate::sqlite::btree_lock::{btree_enter, btree_leave};
use crate::util::beload::store_be32;

/// `p->inTrans` value for a write transaction.
const TRANS_WRITE: u8 = 2;
/// `SQLITE_ERROR` — generic error, returned when a meta update is attempted
/// outside a transaction on a writable database.
const SQLITE_ERROR: u32 = 1;
/// `SQLITE_READONLY` — returned when the shared cache is read-only.
const SQLITE_READONLY: u32 = 8;

/// SQLite's B-tree handle fields used by `sqlite3BtreeUpdateMeta`.
///
/// On target, `shared` is at +0x04 and `in_trans` at +0x08. Named pointer
/// fields deliberately widen together on host fixtures rather than
/// overlapping at literal byte offsets.
#[repr(C)]
pub struct Btree {
    /// +0x00: current SQLite connection.
    pub db: *mut u8,
    /// +0x04: shared page-cache object.
    pub shared: *mut BtreeShared,
    /// +0x08: transaction state (0 = none, 1 = read, 2 = write).
    pub in_trans: u8,
}

/// The shared B-tree object fields this function touches.
#[repr(C)]
pub struct BtreeShared {
    /// +0x00: pager context (unused here, kept for layout parity with
    /// `btree_get_meta`).
    pub page_cache: *mut u8,
    /// +0x04: current SQLite connection, refreshed on entry.
    pub db: *mut u8,
    /// +0x08: padding up to `page_one`.
    pub _reserved0: [u8; 4],
    /// +0x0c: root page one (`pBt->pPage1`).
    pub page_one: *mut MemPage,
    /// +0x10: padding before `read_only`.
    pub _reserved1: u8,
    /// +0x11: non-zero when the shared cache is read-only.
    pub read_only: u8,
    /// +0x12: padding before `incr_vacuum`.
    pub _reserved2: [u8; 5],
    /// +0x17: incremental-vacuum flag latched from meta index 7.
    pub incr_vacuum: u8,
}

/// The recovered fields of a resolved page (`MemPage`).
#[repr(C)]
pub struct MemPage {
    /// +0x00..+0x44: fields this function does not touch.
    pub _reserved0: [u8; 0x44],
    /// +0x44: raw page image (`aData`).
    pub data: *mut u8,
    /// +0x48: pager handle for the dirty-mark call (`pDbPage`).
    pub db_page: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(Btree, shared) == 0x04);
    assert!(core::mem::offset_of!(Btree, in_trans) == 0x08);
    assert!(core::mem::offset_of!(BtreeShared, db) == 0x04);
    assert!(core::mem::offset_of!(BtreeShared, page_one) == 0x0c);
    assert!(core::mem::offset_of!(BtreeShared, read_only) == 0x11);
    assert!(core::mem::offset_of!(BtreeShared, incr_vacuum) == 0x17);
    assert!(core::mem::offset_of!(MemPage, data) == 0x44);
    assert!(core::mem::offset_of!(MemPage, db_page) == 0x48);
};

type PagerWrite = unsafe extern "C" fn(*mut u8) -> u32;
type BtreeBoundary = unsafe extern "C" fn(*mut Btree);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_write(db_page: *mut u8) -> u32 {
    let write: PagerWrite = core::mem::transmute(0x0837_ef64usize);
    write(db_page)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_pager_write(_db_page: *mut u8) -> u32 {
    11
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_btree_boundary(_btree: *mut Btree) {}

/// Host models of the three target call boundaries. They remain private
/// because only this module's fixtures need to substitute unavailable
/// firmware calls.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeUpdateMetaOps {
    enter: BtreeBoundary,
    pager_write: PagerWrite,
    leave: BtreeBoundary,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_BTREE_UPDATE_META_OPS: BtreeUpdateMetaOps = BtreeUpdateMetaOps {
    enter: unavailable_btree_boundary,
    pager_write: unavailable_pager_write,
    leave: unavailable_btree_boundary,
};

#[cfg(not(target_os = "none"))]
static mut BTREE_UPDATE_META_OPS: BtreeUpdateMetaOps = DEFAULT_BTREE_UPDATE_META_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeUpdateMetaOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_UPDATE_META_OPS))
}

/// `sqlite3BtreeUpdateMeta` — original: `FUN_08372dd4` @ `0x08372dd4`
/// (128 bytes; 4 direct plain-`bl` call sites).
///
/// Writes metadata word `index` (0..=7) of the database header on root page
/// one. Returns 0 (`SQLITE_OK`) on success, `SQLITE_ERROR` outside a write
/// transaction on a writable database, `SQLITE_READONLY` on a read-only
/// shared cache, or the `sqlite3PagerWrite` status unchanged. The B-tree
/// leave runs on every path. `btree`, its shared object, and page one must be
/// live and non-NULL, exactly as the raw ARM dereferences them without
/// guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.btree_update_meta")]
#[inline(never)]
pub unsafe extern "C" fn btree_update_meta(btree: *mut Btree, index: u32, value: u32) -> u32 {
    #[cfg(target_os = "none")]
    btree_enter(btree.cast());
    #[cfg(not(target_os = "none"))]
    (host_ops().enter)(btree);

    let shared = (*btree).shared;
    (*shared).db = (*btree).db;

    let status;
    if (*btree).in_trans == TRANS_WRITE {
        let page_one = (*shared).page_one;
        let data = (*page_one).data;
        #[cfg(target_os = "none")]
        {
            status = pager_write((*page_one).db_page);
        }
        #[cfg(not(target_os = "none"))]
        {
            status = (host_ops().pager_write)((*page_one).db_page);
        }
        if status == 0 {
            store_be32(data.add(0x24 + index as usize * 4), value);
            if index == 7 {
                (*shared).incr_vacuum = value as u8;
            }
        }
    } else if (*shared).read_only == 0 {
        status = SQLITE_ERROR;
    } else {
        status = SQLITE_READONLY;
    }

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
    static mut WRITE_STATUS: u32 = 0;
    static mut ENTERS: u32 = 0;
    static mut LEAVES: u32 = 0;
    static mut WRITES: u32 = 0;
    static mut LAST_DB_PAGE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_enter(_btree: *mut Btree) {
        ENTERS += 1;
    }

    unsafe extern "C" fn recording_pager_write(db_page: *mut u8) -> u32 {
        WRITES += 1;
        LAST_DB_PAGE = db_page;
        WRITE_STATUS
    }

    unsafe extern "C" fn recording_leave(_btree: *mut Btree) {
        LEAVES += 1;
    }

    struct Bench {
        _guard: MutexGuard<'static, ()>,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(BTREE_UPDATE_META_OPS),
                    DEFAULT_BTREE_UPDATE_META_OPS,
                );
            }
        }
    }

    fn bench(write_status: u32) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            WRITE_STATUS = write_status;
            ENTERS = 0;
            LEAVES = 0;
            WRITES = 0;
            LAST_DB_PAGE = core::ptr::null_mut();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(BTREE_UPDATE_META_OPS),
                BtreeUpdateMetaOps {
                    enter: recording_enter,
                    pager_write: recording_pager_write,
                    leave: recording_leave,
                },
            );
        }
        Bench { _guard: guard }
    }

    struct Fixture {
        btree: Btree,
        shared: BtreeShared,
        page_one: MemPage,
        page: [u8; 0x80],
        db_page: [u8; 4],
        db: [u8; 4],
    }

    impl Fixture {
        fn new(in_trans: u8, read_only: u8) -> Self {
            Self {
                btree: Btree {
                    db: core::ptr::null_mut(),
                    shared: core::ptr::null_mut(),
                    in_trans,
                },
                shared: BtreeShared {
                    page_cache: core::ptr::null_mut(),
                    db: core::ptr::null_mut(),
                    _reserved0: [0; 4],
                    page_one: core::ptr::null_mut(),
                    _reserved1: 0,
                    read_only,
                    _reserved2: [0; 5],
                    incr_vacuum: 0,
                },
                page_one: MemPage {
                    _reserved0: [0; 0x44],
                    data: core::ptr::null_mut(),
                    db_page: core::ptr::null_mut(),
                },
                page: [0; 0x80],
                db_page: [0; 4],
                db: [0; 4],
            }
        }

        fn wire(&mut self) {
            self.btree.db = self.db.as_mut_ptr();
            self.btree.shared = &mut self.shared;
            self.shared.page_one = &mut self.page_one;
            self.page_one.data = self.page.as_mut_ptr();
            self.page_one.db_page = self.db_page.as_mut_ptr();
        }
    }

    #[test]
    fn write_transaction_stores_big_endian_word_and_returns_ok() {
        let mut fixture = Fixture::new(TRANS_WRITE, 0);
        fixture.wire();
        let _bench = bench(0);

        let status = unsafe { btree_update_meta(&mut fixture.btree, 3, 0x89ab_cdef) };

        assert_eq!(status, 0);
        assert_eq!(&fixture.page[0x24 + 12..0x28 + 12], &0x89ab_cdefu32.to_be_bytes());
        assert_eq!(fixture.shared.db, fixture.btree.db, "pBt->db refreshed");
        assert_eq!(fixture.shared.incr_vacuum, 0, "index 3 must not latch incrVacuum");
        unsafe {
            assert_eq!(ENTERS, 1);
            assert_eq!(WRITES, 1);
            assert_eq!(LEAVES, 1);
            assert_eq!(LAST_DB_PAGE, fixture.db_page.as_mut_ptr());
        }
    }

    #[test]
    fn index_seven_latches_incr_vacuum_byte() {
        let mut fixture = Fixture::new(TRANS_WRITE, 0);
        fixture.wire();
        let _bench = bench(0);

        let status = unsafe { btree_update_meta(&mut fixture.btree, 7, 1) };

        assert_eq!(status, 0);
        assert_eq!(&fixture.page[0x40..0x44], &1u32.to_be_bytes());
        assert_eq!(fixture.shared.incr_vacuum, 1);
    }

    #[test]
    fn index_seven_latches_only_low_byte() {
        let mut fixture = Fixture::new(TRANS_WRITE, 0);
        fixture.wire();
        fixture.shared.incr_vacuum = 0x5a;
        let _bench = bench(0);

        let status = unsafe { btree_update_meta(&mut fixture.btree, 7, 0xffff_ff00) };

        assert_eq!(status, 0);
        assert_eq!(fixture.shared.incr_vacuum, 0, "raw ARM stores r9's low byte");
    }

    #[test]
    fn pager_write_failure_skips_store_and_latch() {
        let mut fixture = Fixture::new(TRANS_WRITE, 0);
        fixture.wire();
        fixture.shared.incr_vacuum = 0x5a;
        let _bench = bench(14);

        let status = unsafe { btree_update_meta(&mut fixture.btree, 7, 1) };

        assert_eq!(status, 14, "pager status passes through unchanged");
        assert!(fixture.page.iter().all(|b| *b == 0), "no store on pager failure");
        assert_eq!(fixture.shared.incr_vacuum, 0x5a);
        unsafe {
            assert_eq!(WRITES, 1);
            assert_eq!(LEAVES, 1);
        }
    }

    #[test]
    fn outside_write_transaction_on_writable_cache_is_error() {
        let mut fixture = Fixture::new(0, 0);
        fixture.wire();
        let _bench = bench(0);

        let status = unsafe { btree_update_meta(&mut fixture.btree, 0, 1) };

        assert_eq!(status, SQLITE_ERROR);
        assert_eq!(fixture.shared.db, fixture.btree.db);
        unsafe {
            assert_eq!(ENTERS, 1);
            assert_eq!(WRITES, 0, "pager untouched outside a transaction");
            assert_eq!(LEAVES, 1);
        }
    }

    #[test]
    fn read_transaction_on_read_only_cache_is_readonly() {
        let mut fixture = Fixture::new(1, 1);
        fixture.wire();
        let _bench = bench(0);

        let status = unsafe { btree_update_meta(&mut fixture.btree, 0, 1) };

        assert_eq!(status, SQLITE_READONLY);
        assert!(fixture.page.iter().all(|b| *b == 0));
        unsafe {
            assert_eq!(WRITES, 0);
            assert_eq!(LEAVES, 1);
        }
    }
}
