//! Set a B-tree's page size — retailOS `FUN_08372cf0` at `0x08372cf0`
//! (156 bytes).
//!
//! Raw ARM establishes the exact extent: `push {r4,r5,r6,r7,r8,lr}` begins at
//! `0x08372cf0`, its `pop {r4,r5,r6,r7,r8,pc}` is at `0x08372d88`, and the
//! distinct next function's `push {r4,r5,r6,r7,r8,lr}` prologue begins at
//! `0x08372d8c`. The body is exactly 39 words (156 bytes), matching Ghidra.
//! Decoding every ARM B/BL word in `osos.dec` finds four plain-`bl` callers
//! of this entry (`0x0837f4f8`, `0x0838294c`, `0x08382964`, `0x08382b08`),
//! all unconditional with no predicated form. The body itself contains five
//! `bl` instructions to four unique callees, all unconditional plain `bl`:
//! `btree_enter` @ `0x0837118c`, `btree_leave` @ `0x08371da4` (twice),
//! `tracked_free` @ `0x083906f4`, and `pager_set_page_size` @ `0x0837ebf8`.
//!
//! This is SQLite 3.5.x's `sqlite3BtreeSetPageSize` (the three-argument form,
//! before `iFix` was added). It enters the B-tree and immediately returns
//! `SQLITE_READONLY` (8) when the shared cache's `readOnly` byte (+0x15) is
//! set. Otherwise:
//!
//! - A negative `n_reserve` defaults to the current
//!   `pageSize - usableSize` (the reserve bytes in use).
//! - When `page_size` is a power of two in `512..=0x8000` (the raw ARM's
//!   unsigned `page_size - 512 <= 0x7e00` window plus the predicated
//!   `(page_size - 1) & page_size == 0` test), the new size is latched into
//!   `pBt->pageSize` (+0x1c), the old temporary space `pBt->pTmpSpace`
//!   (+0x60) is freed and cleared, and `sqlite3PagerSetPagesize` runs on
//!   `pBt->pPager` (+0x00) with a pointer to the `pageSize` halfword — the
//!   pager writes the installed size back through it.
//! - On every non-readonly path `pBt->usableSize` (+0x1e) is recomputed as
//!   the low 16 bits of `pageSize - nReserve` (the raw ARM's 32-bit `sub`
//!   truncated by `strh`).
//!
//! The B-tree is left on every path and the status (0, 8, or the pager's)
//! returned.
//!
//! Deliberate host-only deviation: on target the ported `btree_enter`,
//! `btree_leave`, `tracked_free`, and `pager_set_page_size` are called
//! directly. Host builds route all four boundaries through a private
//! dispatch table: a host `Btree`/`BtreeShared` widens its pointer fields,
//! while the lock-counter port intentionally reads target byte offsets, and
//! host tests must observe the free and pager calls without fabricating a
//! full tracked allocation or Pager. The dispatch preserves the observable
//! call order; it does not change target codegen.

/// `SQLITE_READONLY` — returned when the shared cache is read-only.
const SQLITE_READONLY: u32 = 8;

/// SQLite's B-tree handle fields used by `sqlite3BtreeSetPageSize`.
///
/// On target, `shared` is at +0x04. Named pointer fields deliberately widen
/// together on host fixtures rather than overlapping at literal byte
/// offsets.
#[repr(C)]
pub struct Btree {
    /// +0x00: current SQLite connection (unused here, kept for layout
    /// parity with the sibling btree ports).
    pub db: *mut u8,
    /// +0x04: shared page-cache object.
    pub shared: *mut BtreeShared,
}

/// The shared B-tree object fields this function touches.
#[repr(C)]
pub struct BtreeShared {
    /// +0x00: pager context (`pBt->pPager`).
    pub pager: *mut u8,
    /// +0x04..+0x15: fields this function does not touch.
    pub _reserved0: [u8; 0x11],
    /// +0x15: non-zero when the shared cache is read-only.
    pub read_only: u8,
    /// +0x16..+0x1c: padding before `page_size`.
    pub _reserved1: [u8; 6],
    /// +0x1c: page size in bytes (`pBt->pageSize`).
    pub page_size: u16,
    /// +0x1e: usable bytes per page (`pBt->usableSize`).
    pub usable_size: u16,
    /// +0x20..+0x60: fields this function does not touch.
    pub _reserved2: [u8; 0x40],
    /// +0x60: temporary page space (`pBt->pTmpSpace`).
    pub tmp_space: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(Btree, shared) == 0x04);
    assert!(core::mem::offset_of!(BtreeShared, pager) == 0x00);
    assert!(core::mem::offset_of!(BtreeShared, read_only) == 0x15);
    assert!(core::mem::offset_of!(BtreeShared, page_size) == 0x1c);
    assert!(core::mem::offset_of!(BtreeShared, usable_size) == 0x1e);
    assert!(core::mem::offset_of!(BtreeShared, tmp_space) == 0x60);
};

type BtreeBoundary = unsafe extern "C" fn(*mut Btree);
type FreeBoundary = unsafe extern "C" fn(*mut u8);
type PagerSetPageSize = unsafe extern "C" fn(*mut u8, *mut u16) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_btree_boundary(_btree: *mut Btree) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_free_boundary(_payload: *mut u8) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_pager_set_page_size(
    _pager: *mut u8,
    _page_size: *mut u16,
) -> u32 {
    11
}

/// Host models of the four target call boundaries. They remain private
/// because only this module's fixtures need to substitute the byte-offset
/// lock ports and observe the free/pager calls.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeSetPageSizeOps {
    enter: BtreeBoundary,
    leave: BtreeBoundary,
    free: FreeBoundary,
    pager_set_page_size: PagerSetPageSize,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_BTREE_SET_PAGE_SIZE_OPS: BtreeSetPageSizeOps = BtreeSetPageSizeOps {
    enter: unavailable_btree_boundary,
    leave: unavailable_btree_boundary,
    free: unavailable_free_boundary,
    pager_set_page_size: unavailable_pager_set_page_size,
};

#[cfg(not(target_os = "none"))]
static mut BTREE_SET_PAGE_SIZE_OPS: BtreeSetPageSizeOps =
    DEFAULT_BTREE_SET_PAGE_SIZE_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeSetPageSizeOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_SET_PAGE_SIZE_OPS))
}

#[inline(always)]
unsafe fn enter(btree: *mut Btree) {
    #[cfg(target_os = "none")]
    crate::sqlite::btree_lock::btree_enter(btree.cast());
    #[cfg(not(target_os = "none"))]
    (host_ops().enter)(btree);
}

#[inline(always)]
unsafe fn leave(btree: *mut Btree) {
    #[cfg(target_os = "none")]
    crate::sqlite::btree_lock::btree_leave(btree.cast());
    #[cfg(not(target_os = "none"))]
    (host_ops().leave)(btree);
}

#[inline(always)]
unsafe fn free_tmp_space(payload: *mut u8) {
    #[cfg(target_os = "none")]
    crate::heap::tracked::tracked_free(payload);
    #[cfg(not(target_os = "none"))]
    (host_ops().free)(payload);
}

#[inline(always)]
unsafe fn set_pager_page_size(pager: *mut u8, page_size: *mut u16) -> u32 {
    #[cfg(target_os = "none")]
    return crate::sqlite::pager_set_page_size::pager_set_page_size(pager, page_size);
    #[cfg(not(target_os = "none"))]
    (host_ops().pager_set_page_size)(pager, page_size)
}

/// `sqlite3BtreeSetPageSize` — original: `FUN_08372cf0` @ `0x08372cf0`
/// (156 bytes; 4 direct plain-`bl` call sites).
///
/// Changes the shared cache's page size to `page_size` when it is a power of
/// two in `512..=0x8000`, returning 0 (`SQLITE_OK`) or the pager status.
/// `n_reserve < 0` keeps the current reserve (`pageSize - usableSize`).
/// `usableSize` is recomputed on every non-readonly path. Returns
/// `SQLITE_READONLY` (8) without touching the cache when it is read-only.
///
/// # Safety
/// `btree` and its shared object must be live and non-NULL, exactly as the
/// raw ARM dereferences them without guards. When the resize path runs,
/// `tmp_space` must be NULL or a tracked allocation payload, and `pager`
/// must be a valid Pager for `pager_set_page_size`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.btree_set_page_size")]
#[inline(never)]
pub unsafe extern "C" fn btree_set_page_size(
    btree: *mut Btree,
    page_size: i32,
    n_reserve: i32,
) -> u32 {
    let shared = (*btree).shared;
    let mut status = 0;
    enter(btree);
    if (*shared).read_only != 0 {
        leave(btree);
        return SQLITE_READONLY;
    }
    let mut reserve = n_reserve;
    if reserve < 0 {
        reserve = (*shared).page_size as i32 - (*shared).usable_size as i32;
    }
    if (page_size as u32).wrapping_sub(512) <= 0x7e00
        && (page_size.wrapping_sub(1) & page_size) == 0
    {
        (*shared).page_size = page_size as u16;
        free_tmp_space((*shared).tmp_space);
        (*shared).tmp_space = core::ptr::null_mut();
        status = set_pager_page_size((*shared).pager, &mut (*shared).page_size);
    }
    (*shared).usable_size = ((*shared).page_size as i32).wrapping_sub(reserve) as u16;
    leave(btree);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ENTERS: u32 = 0;
    static mut LEAVES: u32 = 0;
    static mut FREES: u32 = 0;
    static mut PAGER_CALLS: u32 = 0;
    static mut LAST_FREED: *mut u8 = core::ptr::null_mut();
    static mut LAST_PAGER: *mut u8 = core::ptr::null_mut();
    static mut PAGER_STATUS: u32 = 0;
    static mut PAGER_INSTALLED_SIZE: u16 = 0;

    unsafe extern "C" fn recording_enter(_btree: *mut Btree) {
        ENTERS += 1;
    }

    unsafe extern "C" fn recording_leave(_btree: *mut Btree) {
        LEAVES += 1;
    }

    unsafe extern "C" fn recording_free(payload: *mut u8) {
        FREES += 1;
        LAST_FREED = payload;
    }

    /// Models the ported `pager_set_page_size`: records the call, then
    /// writes the installed size back through `page_size` exactly as the
    /// real port does.
    unsafe extern "C" fn recording_pager_set_page_size(
        pager: *mut u8,
        page_size: *mut u16,
    ) -> u32 {
        PAGER_CALLS += 1;
        LAST_PAGER = pager;
        page_size.write(PAGER_INSTALLED_SIZE);
        PAGER_STATUS
    }

    struct Bench {
        _guard: MutexGuard<'static, ()>,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(BTREE_SET_PAGE_SIZE_OPS),
                    DEFAULT_BTREE_SET_PAGE_SIZE_OPS,
                );
            }
        }
    }

    fn bench(pager_status: u32, pager_installed_size: u16) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ENTERS = 0;
            LEAVES = 0;
            FREES = 0;
            PAGER_CALLS = 0;
            LAST_FREED = core::ptr::null_mut();
            LAST_PAGER = core::ptr::null_mut();
            PAGER_STATUS = pager_status;
            PAGER_INSTALLED_SIZE = pager_installed_size;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(BTREE_SET_PAGE_SIZE_OPS),
                BtreeSetPageSizeOps {
                    enter: recording_enter,
                    leave: recording_leave,
                    free: recording_free,
                    pager_set_page_size: recording_pager_set_page_size,
                },
            );
        }
        Bench { _guard: guard }
    }

    struct Fixture {
        btree: Btree,
        shared: BtreeShared,
        pager: [u8; 8],
        tmp_space: [u8; 8],
    }

    impl Fixture {
        fn new(read_only: u8, page_size: u16, usable_size: u16) -> Self {
            Self {
                btree: Btree {
                    db: core::ptr::null_mut(),
                    shared: core::ptr::null_mut(),
                },
                shared: BtreeShared {
                    pager: core::ptr::null_mut(),
                    _reserved0: [0; 0x11],
                    read_only,
                    _reserved1: [0; 6],
                    page_size,
                    usable_size,
                    _reserved2: [0; 0x40],
                    tmp_space: core::ptr::null_mut(),
                },
                pager: [0; 8],
                tmp_space: [0; 8],
            }
        }

        fn wire(&mut self) {
            self.btree.shared = &mut self.shared;
            self.shared.pager = self.pager.as_mut_ptr();
            self.shared.tmp_space = self.tmp_space.as_mut_ptr();
        }
    }

    #[test]
    fn valid_page_size_resizes_frees_tmp_and_updates_usable() {
        let mut fixture = Fixture::new(0, 512, 480);
        fixture.wire();
        let _bench = bench(0, 1024);

        let status = unsafe { btree_set_page_size(&mut fixture.btree, 1024, 16) };

        assert_eq!(status, 0);
        assert_eq!(fixture.shared.page_size, 1024, "pager-installed size latched back");
        assert_eq!(fixture.shared.usable_size, 1024 - 16);
        assert!(fixture.shared.tmp_space.is_null(), "tmp space cleared after free");
        unsafe {
            assert_eq!(ENTERS, 1);
            assert_eq!(LEAVES, 1);
            assert_eq!(FREES, 1);
            assert_eq!(LAST_FREED, fixture.tmp_space.as_mut_ptr());
            assert_eq!(PAGER_CALLS, 1);
            assert_eq!(LAST_PAGER, fixture.pager.as_mut_ptr());
        }
    }

    #[test]
    fn negative_reserve_keeps_current_reserve_bytes() {
        let mut fixture = Fixture::new(0, 512, 480);
        fixture.wire();
        let _bench = bench(0, 1024);

        let status = unsafe { btree_set_page_size(&mut fixture.btree, 1024, -1) };

        assert_eq!(status, 0);
        assert_eq!(fixture.shared.usable_size, 1024 - 32, "reserve stays 512-480=32");
    }

    #[test]
    fn read_only_cache_returns_readonly_without_side_effects() {
        let mut fixture = Fixture::new(1, 512, 480);
        fixture.wire();
        let _bench = bench(0, 1024);

        let status = unsafe { btree_set_page_size(&mut fixture.btree, 1024, 16) };

        assert_eq!(status, SQLITE_READONLY);
        assert_eq!(fixture.shared.page_size, 512);
        assert_eq!(fixture.shared.usable_size, 480);
        assert!(!fixture.shared.tmp_space.is_null());
        unsafe {
            assert_eq!(ENTERS, 1);
            assert_eq!(LEAVES, 1, "leave still runs on the readonly path");
            assert_eq!(FREES, 0);
            assert_eq!(PAGER_CALLS, 0);
        }
    }

    #[test]
    fn non_power_of_two_size_skips_resize_but_recomputes_usable() {
        let mut fixture = Fixture::new(0, 512, 480);
        fixture.wire();
        let _bench = bench(0, 1024);

        let status = unsafe { btree_set_page_size(&mut fixture.btree, 1000, 20) };

        assert_eq!(status, 0);
        assert_eq!(fixture.shared.page_size, 512, "page size untouched");
        assert_eq!(fixture.shared.usable_size, 512 - 20);
        assert!(!fixture.shared.tmp_space.is_null());
        unsafe {
            assert_eq!(FREES, 0);
            assert_eq!(PAGER_CALLS, 0);
        }
    }

    #[test]
    fn out_of_window_size_skips_resize() {
        let mut fixture = Fixture::new(0, 512, 480);
        fixture.wire();
        let _bench = bench(0, 1024);

        // 0x8400 is a power of two but above the 0x8000 ceiling; 256 is a
        // power of two below the 512 floor.
        for bad in [0x8400i32, 256, 0] {
            let status = unsafe { btree_set_page_size(&mut fixture.btree, bad, 0) };
            assert_eq!(status, 0);
            assert_eq!(fixture.shared.page_size, 512);
        }
        unsafe {
            assert_eq!(PAGER_CALLS, 0);
            assert_eq!(FREES, 0);
        }
    }

    #[test]
    fn pager_status_passes_through_and_usable_uses_installed_size() {
        let mut fixture = Fixture::new(0, 512, 500);
        fixture.wire();
        let _bench = bench(14, 512);

        // Pager "fails" (status 14) and reports the old 512 back through the
        // pageSize pointer, as the real pager_set_page_size does.
        let status = unsafe { btree_set_page_size(&mut fixture.btree, 2048, 12) };

        assert_eq!(status, 14, "pager status unchanged");
        assert_eq!(fixture.shared.page_size, 512, "installed size written back");
        assert_eq!(fixture.shared.usable_size, 512 - 12);
        assert!(fixture.shared.tmp_space.is_null(), "old tmp space still freed");
        unsafe {
            assert_eq!(FREES, 1);
            assert_eq!(LEAVES, 1);
        }
    }

    #[test]
    fn usable_size_store_truncates_to_low_halfword() {
        let mut fixture = Fixture::new(0, 4096, 4096);
        fixture.wire();
        let _bench = bench(0, 4096);

        // reserve larger than the page size: the raw ARM's 32-bit sub
        // truncated by strh keeps only the low 16 bits.
        let status = unsafe { btree_set_page_size(&mut fixture.btree, 4096, 0x1_0008) };

        assert_eq!(status, 0);
        assert_eq!(fixture.shared.usable_size, (4096u32.wrapping_sub(0x1_0008)) as u16);
    }
}
