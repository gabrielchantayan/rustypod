//! SQLite's auto-vacuum pointer-map reader.
//!
//! `ptrmap_get` — original: `FUN_082e85d8` @ `0x082e85d8` (148 bytes;
//! extent verified by the independent `push {r4-r6,lr}` at `0x082e866c`).
//! Decoding every ARM B/BL immediate in `osos.dec` finds five direct inbound
//! call sites, all unconditional `bl`: `0x082b33d4`, `0x082bda6c`,
//! `0x082c27f8`, `0x082d08d0`, and `0x082d4d30`; no predicated calls.
//!
//! This is SQLite 3.5.x's `ptrmapGet`: lease the pointer-map page for `pgno`,
//! find its five-byte `(type, big-endian parent-page)` record, copy its fields
//! to the requested outputs, release the page, then validate that type is in
//! `1..=6`. A resolver failure returns immediately without touching outputs or
//! releasing a page.
//!
//! Deliberate deviation: the target directly calls the already-ported leased
//! resolver and object release functions. Host tests replace only the resolver
//! boundary, because its retailOS-owned inner resolver has no host fixture.

use crate::cxx::release::release_object;
use crate::sqlite::ptrmap_pageno::ptrmap_pageno;
use crate::util::beload::load_be32;

const SQLITE_CORRUPT: u32 = 11;
const BT_CONTEXT: usize = 0;
const MAP_PAGE_DATA: usize = 0x34;

type ResolveMapPage = unsafe extern "C" fn(*mut u8, u32, *mut *mut u8, u32) -> u32;

/// Reads a target pointer by 32-bit-word index. Host fixtures expand each
/// target pointer to one native-width slot, so target fields cannot overlap.
#[inline(always)]
unsafe fn read_target_pointer(base: *const u8, target_offset: usize) -> *mut u8 {
    base.cast::<*mut u8>().add(target_offset / 4).read()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resolve_map_page(
    context: *mut u8,
    page_no: u32,
    out_page: *mut *mut u8,
) -> u32 {
    crate::cxx::context_record_resolve::context_record_resolve_leased(context, page_no, out_page, 0)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct PtrmapGetHostOps {
    resolve: ResolveMapPage,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_resolve(
    _context: *mut u8,
    _page_no: u32,
    _out_page: *mut *mut u8,
    _flags: u32,
) -> u32 {
    SQLITE_CORRUPT
}

#[cfg(not(target_os = "none"))]
const DEFAULT_PTRMAP_GET_HOST_OPS: PtrmapGetHostOps = PtrmapGetHostOps { resolve: unavailable_resolve };

#[cfg(not(target_os = "none"))]
static mut PTRMAP_GET_HOST_OPS: PtrmapGetHostOps = DEFAULT_PTRMAP_GET_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resolve_map_page(
    context: *mut u8,
    page_no: u32,
    out_page: *mut *mut u8,
) -> u32 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(PTRMAP_GET_HOST_OPS));
    (ops.resolve)(context, page_no, out_page, 0)
}

/// ptrmap_get — original: `FUN_082e85d8` @ `0x082e85d8` (148 bytes; five
/// direct, plain-`bl` call sites).
///
/// Reads `pgno`'s auto-vacuum pointer-map type and optional big-endian parent
/// page. The resolver failure is returned unchanged. On a successful lease,
/// the page is always released; type values outside `1..=6` return
/// `SQLITE_CORRUPT` after their outputs have been stored. RetailOS has no NULL
/// checks for `bt`, `out_type`, the resolved page, or its data field.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ptrmap_get(
    bt: *const u8,
    pgno: u32,
    out_type: *mut u8,
    out_parent_pgno: *mut u32,
) -> u32 {
    let ptrmap_page = ptrmap_pageno(bt, pgno);
    let mut map_page = core::ptr::null_mut();
    let status = resolve_map_page(read_target_pointer(bt, BT_CONTEXT), ptrmap_page, &mut map_page);
    if status != 0 {
        return status;
    }

    let entry_offset = pgno
        .wrapping_sub(ptrmap_page)
        .wrapping_sub(1)
        .wrapping_mul(5) as usize;
    let data = read_target_pointer(map_page, MAP_PAGE_DATA);
    let entry = data.add(entry_offset);
    let map_type = entry.read();
    out_type.write(map_type);
    if !out_parent_pgno.is_null() {
        out_parent_pgno.write(load_be32(entry.add(1)));
    }
    release_object(map_page);

    if (1..=6).contains(&map_type) { 0 } else { SQLITE_CORRUPT }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut RESOLVE_STATUS: u32 = 0;
    static mut RESOLVED_PAGE: *mut u8 = core::ptr::null_mut();
    static mut RESOLVE_CALLS: u32 = 0;
    static mut LAST_RESOLVE: Option<(*mut u8, u32, u32)> = None;

    unsafe extern "C" fn recording_resolve(
        context: *mut u8,
        page_no: u32,
        out_page: *mut *mut u8,
        flags: u32,
    ) -> u32 {
        RESOLVE_CALLS += 1;
        LAST_RESOLVE = Some((context, page_no, flags));
        if RESOLVE_STATUS == 0 {
            out_page.write(RESOLVED_PAGE);
        }
        RESOLVE_STATUS
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while OPS_LOCK.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        TestLock
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            OPS_LOCK.store(false, Ordering::Release);
        }
    }

    struct Bench {
        _lock: TestLock,
    }

    fn bench(page: *mut u8, status: u32) -> Bench {
        let lock = lock_ops();
        unsafe {
            RESOLVE_STATUS = status;
            RESOLVED_PAGE = page;
            RESOLVE_CALLS = 0;
            LAST_RESOLVE = None;
            core::ptr::addr_of_mut!(PTRMAP_GET_HOST_OPS).write_volatile(PtrmapGetHostOps {
                resolve: recording_resolve,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PTRMAP_GET_HOST_OPS)
                    .write_volatile(DEFAULT_PTRMAP_GET_HOST_OPS);
            }
        }
    }

    #[repr(align(8))]
    struct BtFixture {
        bytes: [u8; 0x24],
    }

    impl BtFixture {
        fn new(context: *mut u8) -> Self {
            let mut fixture = Self { bytes: [0; 0x24] };
            unsafe { (fixture.bytes.as_mut_ptr() as *mut *mut u8).write(context) };
            fixture.bytes[0x1c..0x1e].copy_from_slice(&1024u16.to_le_bytes());
            fixture.bytes[0x1e..0x20].copy_from_slice(&1024u16.to_le_bytes());
            fixture
        }
    }

    #[repr(align(8))]
    struct MapPageFixture {
        bytes: [u8; 0x70],
    }

    impl MapPageFixture {
        fn new(context: *mut u8, data: *mut u8) -> Self {
            let mut fixture = Self { bytes: [0; 0x70] };
            unsafe {
                (fixture.bytes.as_mut_ptr() as *mut *mut u8).write(context);
                (fixture.bytes.as_mut_ptr().cast::<*mut u8>().add(MAP_PAGE_DATA / 4)).write(data);
                (fixture.bytes.as_mut_ptr().add(0x22) as *mut u16).write(2);
            }
            fixture
        }

        fn refcount(&self) -> u16 {
            unsafe { (self.bytes.as_ptr().add(0x22) as *const u16).read() }
        }
    }

    #[test]
    fn resolver_failure_preserves_outputs_and_does_not_release_a_page() {
        let mut context = [0u8; 0xe4];
        let mut bt = BtFixture::new(context.as_mut_ptr());
        let _bench = bench(core::ptr::null_mut(), 7);
        let mut map_type = 0xa5;
        let mut parent = 0x1122_3344;

        let status = unsafe { ptrmap_get(bt.bytes.as_mut_ptr(), 3, &mut map_type, &mut parent) };

        assert_eq!(status, 7);
        assert_eq!(map_type, 0xa5);
        assert_eq!(parent, 0x1122_3344);
        assert_eq!(unsafe { RESOLVE_CALLS }, 1);
        assert_eq!(unsafe { LAST_RESOLVE }, Some((context.as_mut_ptr(), 2, 0)));
    }

    #[test]
    fn valid_entry_decodes_parent_and_releases_map_page() {
        let mut context = [0u8; 0xe4];
        let mut bt = BtFixture::new(context.as_mut_ptr());
        let mut data = [0u8; 1024];
        data[..5].copy_from_slice(&[5, 0xa1, 0xb2, 0xc3, 0xd4]);
        let mut page = MapPageFixture::new(context.as_mut_ptr(), data.as_mut_ptr());
        let _bench = bench(page.bytes.as_mut_ptr(), 0);
        let mut map_type = 0;
        let mut parent = 0;

        let status = unsafe { ptrmap_get(bt.bytes.as_mut_ptr(), 3, &mut map_type, &mut parent) };

        assert_eq!(status, 0);
        assert_eq!(map_type, 5);
        assert_eq!(parent, 0xa1b2_c3d4);
        assert_eq!(page.refcount(), 1);
    }

    #[test]
    fn invalid_type_is_stored_and_released_even_without_parent_output() {
        let mut context = [0u8; 0xe4];
        let mut bt = BtFixture::new(context.as_mut_ptr());
        let mut data = [0u8; 1024];
        data[..5].copy_from_slice(&[7, 0x12, 0x34, 0x56, 0x78]);
        let mut page = MapPageFixture::new(context.as_mut_ptr(), data.as_mut_ptr());
        let _bench = bench(page.bytes.as_mut_ptr(), 0);
        let mut map_type = 0;

        let status = unsafe { ptrmap_get(bt.bytes.as_mut_ptr(), 3, &mut map_type, core::ptr::null_mut()) };

        assert_eq!(status, SQLITE_CORRUPT);
        assert_eq!(map_type, 7);
        assert_eq!(page.refcount(), 1);
    }
}
