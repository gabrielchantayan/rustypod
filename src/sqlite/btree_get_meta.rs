//! Read a B-tree's persistent metadata — retailOS `FUN_08371380` at
//! `0x08371380` (152 bytes).
//!
//! Raw ARM establishes the exact extent: `push {r3-r9,lr}` begins at
//! `0x08371380`, its `pop {r3-r9,pc}` is at `0x08371414`, and the distinct
//! `context_child_handle_acquire` prologue begins at `0x08371418`. Decoding
//! every ARM B/BL word in `osos.dec` finds seven direct call sites, all
//! unconditional plain `bl`; no predicated call reaches this function. No
//! image data word equals the entry address, so it is statically bound.
//!
//! This is SQLite's `sqlite3BtreeGetMeta`. It enters the B-tree, records the
//! caller's connection in the shared page-cache object, checks a read lock on
//! root page 1, resolves that page with flags zero, reads the selected
//! big-endian metadata word at page offset `0x24 + index * 4`, releases the
//! page, installs the shared-cache lock, then always leaves the B-tree.
//!
//! Deliberate host-only deviation: the target directly calls the already
//! ported enter/leave, page resolver, page release, and big-endian loader.
//! The two unported lock helpers (`0x082e8980`, `0x082d8574`) are absolute
//! target calls. Host builds route the six non-loader boundaries through a
//! dispatch table: a host `Btree` widens its adjacent pointer fields while the older
//! enter/leave port intentionally uses target byte offsets, so direct host
//! composition would make `sharable` overlap `pBt`. The dispatch preserves
//! the port's observable call order and lets tests model the real page cache
//! without inventing a second host layout.

use crate::sqlite::btree_lock::{btree_enter, btree_leave};
use crate::util::beload::load_be32;

/// SQLite's B-tree handle fields used by `sqlite3BtreeGetMeta`.
///
/// On target, `shared` is at +0x04. Named pointer fields deliberately widen
/// together on host fixtures rather than overlapping at literal byte offsets.
#[repr(C)]
pub struct Btree {
    pub db: *mut u8,
    pub shared: *mut BtreeShared,
}

/// The two recovered words of the shared B-tree object.
#[repr(C)]
pub struct BtreeShared {
    /// +0x00: context passed to the page resolver.
    pub page_cache: *mut u8,
    /// +0x04: current SQLite connection.
    pub db: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(Btree, shared) == 0x04);
    assert!(core::mem::offset_of!(BtreeShared, db) == 0x04);
};

type QueryTableLock = unsafe extern "C" fn(*mut Btree, u32, u32) -> u32;
type ResolvePage = unsafe extern "C" fn(*mut u8, u32, *mut *mut u8, u32) -> u32;
type ReleasePage = unsafe extern "C" fn(*mut u8);
type SetTableLock = unsafe extern "C" fn(*mut Btree, u32, u32) -> u32;
type BtreeBoundary = unsafe extern "C" fn(*mut Btree);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn query_table_lock(btree: *mut Btree, root_page: u32, lock: u32) -> u32 {
    let query: QueryTableLock = core::mem::transmute(0x082e_8980usize);
    query(btree, root_page, lock)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resolve_page(
    page_cache: *mut u8,
    page_number: u32,
    out_page: *mut *mut u8,
    flags: u32,
) -> u32 {
    crate::cxx::context_record_resolve::context_record_resolve_leased(
        page_cache,
        page_number,
        out_page,
        flags,
    )
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_page(page: *mut u8) {
    let _ = crate::cxx::release::release_object(page);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn set_table_lock(btree: *mut Btree, root_page: u32, lock: u32) -> u32 {
    let set: SetTableLock = core::mem::transmute(0x082d_8574usize);
    set(btree, root_page, lock)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_query_table_lock(
    _btree: *mut Btree,
    _root_page: u32,
    _lock: u32,
) -> u32 {
    11
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_resolve_page(
    _page_cache: *mut u8,
    _page_number: u32,
    _out_page: *mut *mut u8,
    _flags: u32,
) -> u32 {
    11
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_release_page(_page: *mut u8) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_set_table_lock(
    _btree: *mut Btree,
    _root_page: u32,
    _lock: u32,
) -> u32 {
    11
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_btree_boundary(_btree: *mut Btree) {}

/// Host models of the five target call boundaries. They remain private because
/// only this module's fixtures need to substitute unavailable firmware calls.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeGetMetaOps {
    enter: BtreeBoundary,
    query_table_lock: QueryTableLock,
    resolve_page: ResolvePage,
    release_page: ReleasePage,
    set_table_lock: SetTableLock,
    leave: BtreeBoundary,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_BTREE_GET_META_OPS: BtreeGetMetaOps = BtreeGetMetaOps {
    enter: unavailable_btree_boundary,
    query_table_lock: unavailable_query_table_lock,
    resolve_page: unavailable_resolve_page,
    release_page: unavailable_release_page,
    set_table_lock: unavailable_set_table_lock,
    leave: unavailable_btree_boundary,
};

#[cfg(not(target_os = "none"))]
static mut BTREE_GET_META_OPS: BtreeGetMetaOps = DEFAULT_BTREE_GET_META_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeGetMetaOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_GET_META_OPS))
}

/// `sqlite3BtreeGetMeta` — original: `FUN_08371380` @ `0x08371380`
/// (152 bytes; 7 direct plain-`bl` call sites).
///
/// Reads metadata word `index` from root page one into `out_meta`. The first
/// lock-query or page-resolve error passes through unchanged; after a
/// successful page read, the result of installing the read lock is returned.
/// The B-tree leave operation runs on every path. `btree`, its shared object,
/// and page resolver result must be live and non-NULL, exactly as the raw ARM
/// dereferences them without guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.btree_get_meta")]
#[inline(never)]
pub unsafe extern "C" fn btree_get_meta(
    btree: *mut Btree,
    index: u32,
    out_meta: *mut u32,
) -> u32 {
    #[cfg(target_os = "none")]
    btree_enter(btree.cast());
    #[cfg(not(target_os = "none"))]
    (host_ops().enter)(btree);

    let shared = (*btree).shared;
    (*shared).db = (*btree).db;

    #[cfg(target_os = "none")]
    let mut status = query_table_lock(btree, 1, 1);
    #[cfg(not(target_os = "none"))]
    let mut status = (host_ops().query_table_lock)(btree, 1, 1);

    if status == 0 {
        let mut page = core::ptr::null_mut();
        #[cfg(target_os = "none")]
        {
            status = resolve_page((*shared).page_cache, 1, &mut page, 0);
        }
        #[cfg(not(target_os = "none"))]
        {
            status = (host_ops().resolve_page)((*shared).page_cache, 1, &mut page, 0);
        }
        if status == 0 {
            out_meta.write(load_be32(page.add(0x24 + index as usize * 4)));
            #[cfg(target_os = "none")]
            release_page(page);
            #[cfg(not(target_os = "none"))]
            (host_ops().release_page)(page);
            #[cfg(target_os = "none")]
            {
                status = set_table_lock(btree, 1, 1);
            }
            #[cfg(not(target_os = "none"))]
            {
                status = (host_ops().set_table_lock)(btree, 1, 1);
            }
        }
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
    static mut QUERY_STATUS: u32 = 0;
    static mut RESOLVE_STATUS: u32 = 0;
    static mut SET_STATUS: u32 = 0;
    static mut PAGE: *mut u8 = core::ptr::null_mut();
    static mut ENTERS: u32 = 0;
    static mut LEAVES: u32 = 0;
    static mut QUERIES: u32 = 0;
    static mut RESOLVES: u32 = 0;
    static mut RELEASES: u32 = 0;
    static mut SETS: u32 = 0;
    static mut LAST_PAGE_CACHE: *mut u8 = core::ptr::null_mut();
    static mut LAST_RELEASED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_enter(_btree: *mut Btree) {
        ENTERS += 1;
    }

    unsafe extern "C" fn recording_query(
        _btree: *mut Btree,
        root_page: u32,
        lock: u32,
    ) -> u32 {
        assert_eq!(root_page, 1);
        assert_eq!(lock, 1);
        QUERIES += 1;
        QUERY_STATUS
    }

    unsafe extern "C" fn recording_resolve(
        page_cache: *mut u8,
        page_number: u32,
        out_page: *mut *mut u8,
        flags: u32,
    ) -> u32 {
        assert_eq!(page_number, 1);
        assert_eq!(flags, 0);
        RESOLVES += 1;
        LAST_PAGE_CACHE = page_cache;
        if RESOLVE_STATUS == 0 {
            out_page.write(PAGE);
        }
        RESOLVE_STATUS
    }

    unsafe extern "C" fn recording_release(page: *mut u8) {
        RELEASES += 1;
        LAST_RELEASED = page;
    }

    unsafe extern "C" fn recording_set(
        _btree: *mut Btree,
        root_page: u32,
        lock: u32,
    ) -> u32 {
        assert_eq!(root_page, 1);
        assert_eq!(lock, 1);
        SETS += 1;
        SET_STATUS
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
                    core::ptr::addr_of_mut!(BTREE_GET_META_OPS),
                    DEFAULT_BTREE_GET_META_OPS,
                );
            }
        }
    }

    fn bench(page: *mut u8, query_status: u32, resolve_status: u32, set_status: u32) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            QUERY_STATUS = query_status;
            RESOLVE_STATUS = resolve_status;
            SET_STATUS = set_status;
            PAGE = page;
            ENTERS = 0;
            LEAVES = 0;
            QUERIES = 0;
            RESOLVES = 0;
            RELEASES = 0;
            SETS = 0;
            LAST_PAGE_CACHE = core::ptr::null_mut();
            LAST_RELEASED = core::ptr::null_mut();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(BTREE_GET_META_OPS),
                BtreeGetMetaOps {
                    enter: recording_enter,
                    query_table_lock: recording_query,
                    resolve_page: recording_resolve,
                    release_page: recording_release,
                    set_table_lock: recording_set,
                    leave: recording_leave,
                },
            );
        }
        Bench { _guard: guard }
    }

    struct Fixture {
        btree: Btree,
        shared: BtreeShared,
        page_cache: [u8; 4],
        page: [u8; 0x80],
        db: [u8; 4],
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
                page_cache: [0; 4],
                page: [0; 0x80],
                db: [0; 4],
            }
        }

        fn wire(&mut self) {
            self.btree.db = self.db.as_mut_ptr();
            self.btree.shared = &mut self.shared;
            self.shared.page_cache = self.page_cache.as_mut_ptr();
        }
    }

    #[test]
    fn reads_big_endian_metadata_then_releases_and_locks() {
        let mut fixture = Fixture::new();
        fixture.wire();
        let index = 3;
        fixture.page[0x24 + index * 4..0x28 + index * 4]
            .copy_from_slice(&0x89ab_cdefu32.to_be_bytes());
        let _bench = bench(fixture.page.as_mut_ptr(), 0, 0, 7);
        let mut out_meta = 0;

        let status = unsafe { btree_get_meta(&mut fixture.btree, index as u32, &mut out_meta) };

        assert_eq!(status, 7, "post-read lock status is returned");
        assert_eq!(out_meta, 0x89ab_cdef);
        assert_eq!(fixture.shared.db, fixture.btree.db);
        unsafe {
            assert_eq!(ENTERS, 1);
            assert_eq!(QUERIES, 1);
            assert_eq!(RESOLVES, 1);
            assert_eq!(RELEASES, 1);
            assert_eq!(SETS, 1);
            assert_eq!(LEAVES, 1);
            assert_eq!(LAST_PAGE_CACHE, fixture.shared.page_cache);
            assert_eq!(LAST_RELEASED, fixture.page.as_mut_ptr());
        }
    }

    #[test]
    fn query_failure_leaves_without_touching_output_or_page() {
        let mut fixture = Fixture::new();
        fixture.wire();
        let _bench = bench(fixture.page.as_mut_ptr(), 6, 0, 0);
        let mut out_meta = 0xa5a5_a5a5;

        let status = unsafe { btree_get_meta(&mut fixture.btree, 0, &mut out_meta) };

        assert_eq!(status, 6);
        assert_eq!(out_meta, 0xa5a5_a5a5);
        assert_eq!(fixture.shared.db, fixture.btree.db);
        unsafe {
            assert_eq!(ENTERS, 1);
            assert_eq!(QUERIES, 1);
            assert_eq!(RESOLVES, 0);
            assert_eq!(RELEASES, 0);
            assert_eq!(SETS, 0);
            assert_eq!(LEAVES, 1);
        }
    }

    #[test]
    fn page_failure_leaves_without_releasing_or_installing_lock() {
        let mut fixture = Fixture::new();
        fixture.wire();
        let _bench = bench(fixture.page.as_mut_ptr(), 0, 13, 0);
        let mut out_meta = 0x5a5a_5a5a;

        let status = unsafe { btree_get_meta(&mut fixture.btree, 15, &mut out_meta) };

        assert_eq!(status, 13);
        assert_eq!(out_meta, 0x5a5a_5a5a);
        unsafe {
            assert_eq!(ENTERS, 1);
            assert_eq!(QUERIES, 1);
            assert_eq!(RESOLVES, 1);
            assert_eq!(RELEASES, 0);
            assert_eq!(SETS, 0);
            assert_eq!(LEAVES, 1);
        }
    }
}
