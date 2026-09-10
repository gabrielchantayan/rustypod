//! SQLite's auto-vacuum pointer-map writer.
//!
//! `ptrmap_put` — original: `FUN_082e86bc` @ `0x082e86bc` (184 bytes;
//! extent verified from the next independent `push {r4,lr}` at
//! `0x082e8774`). Decoding every ARM B/BL word in `osos.dec` finds 11
//! direct call sites, all unconditional `bl`: `0x082b5c64`, `0x082b69bc`,
//! `0x082bdb20`, `0x082ce0dc`, `0x082cf48c`, `0x082d6978`, `0x082e8804`,
//! `0x083677f4`, `0x0836783c`, `0x08368eec`, and `0x08368f34`.
//!
//! This is SQLite 3.5.x's `ptrmapPut`: reject page zero with
//! `SQLITE_CORRUPT` (11); lease the pointer-map page containing `pgno`; map
//! its `(pgno - ptrmap_pageno(bt, pgno) - 1) * 5` entry; and write its type
//! byte and big-endian parent page only when either differs. The page is
//! released after every successful lease, including a dirty-page failure.
//! The raw `bleq` at `0x082e8764` makes the stores conditional on a zero
//! dirty-page status; all 11 callers themselves are unpredicated.
//!
//! Deliberate deviations: `FUN_0837ef64` (the page dirty/write operation)
//! remains retailOS-owned, so target builds call it at its load address. Host
//! builds route that and the otherwise-unconfigurable record resolver through
//! test-only boundaries; target builds call the ported leased resolver
//! directly. Pointer fields use target word indices, preserving the 32-bit
//! layout while host fixtures carry native-width pointers.

use crate::cxx::release::release_object;
use crate::sqlite::ptrmap_pageno::ptrmap_pageno;
use crate::util::beload::{load_be32, store_be32};

const SQLITE_CORRUPT: u32 = 11;
const BT_CONTEXT: usize = 0;
const MAP_PAGE_DATA: usize = 0x34;

/// Reads a target pointer field by 32-bit-word index. On host fixtures each
/// target pointer expands to one native pointer-width slot, avoiding overlap.
#[inline(always)]
unsafe fn read_target_pointer(base: *const u8, target_offset: usize) -> *mut u8 {
    base.cast::<*mut u8>().add(target_offset / 4).read()
}

type ResolveMapPage = unsafe extern "C" fn(*mut u8, u32, *mut *mut u8, u32) -> u32;
type WriteMapPage = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resolve_map_page(
    context: *mut u8,
    page_no: u32,
    out_page: *mut *mut u8,
) -> u32 {
    crate::cxx::context_record_resolve::context_record_resolve_leased(
        context, page_no, out_page, 0,
    )
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn mark_map_page_writable(page: *mut u8) -> u32 {
    let write: WriteMapPage = core::mem::transmute(0x0837_ef64usize);
    write(page)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct PtrmapPutHostOps {
    resolve: ResolveMapPage,
    write: WriteMapPage,
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
unsafe extern "C" fn unavailable_write(_page: *mut u8) -> u32 {
    SQLITE_CORRUPT
}

#[cfg(not(target_os = "none"))]
const DEFAULT_PTRMAP_PUT_HOST_OPS: PtrmapPutHostOps = PtrmapPutHostOps {
    resolve: unavailable_resolve,
    write: unavailable_write,
};

#[cfg(not(target_os = "none"))]
static mut PTRMAP_PUT_HOST_OPS: PtrmapPutHostOps = DEFAULT_PTRMAP_PUT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> PtrmapPutHostOps {
    core::ptr::read_volatile(core::ptr::addr_of!(PTRMAP_PUT_HOST_OPS))
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resolve_map_page(
    context: *mut u8,
    page_no: u32,
    out_page: *mut *mut u8,
) -> u32 {
    (host_ops().resolve)(context, page_no, out_page, 0)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn mark_map_page_writable(page: *mut u8) -> u32 {
    (host_ops().write)(page)
}

/// ptrmap_put — original: `FUN_082e86bc` @ `0x082e86bc` (184 bytes; 11
/// direct, plain-`bl` call sites).
///
/// Writes `map_type` and `parent_pgno` into `pgno`'s five-byte auto-vacuum
/// pointer-map entry. Page zero returns `SQLITE_CORRUPT`; no NULL checks are
/// present for any other pointer, exactly as the ARM body. An already equal
/// entry skips the dirty-page operation; a dirty-page failure skips both
/// stores yet still releases the map page.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ptrmap_put(
    bt: *mut u8,
    pgno: u32,
    map_type: u32,
    parent_pgno: u32,
) -> u32 {
    if pgno == 0 {
        return SQLITE_CORRUPT;
    }

    let mut map_page = parent_pgno as usize as *mut u8;
    let ptrmap_page = ptrmap_pageno(bt, pgno);
    let mut status = resolve_map_page(read_target_pointer(bt, BT_CONTEXT), ptrmap_page, &mut map_page);
    if status != 0 {
        return status;
    }

    let entry_offset = pgno
        .wrapping_sub(ptrmap_page)
        .wrapping_sub(1)
        .wrapping_mul(5) as usize;
    let data = read_target_pointer(map_page, MAP_PAGE_DATA);
    let entry = data.add(entry_offset);

    if u32::from(entry.read()) != map_type || load_be32(entry.add(1)) != parent_pgno {
        status = mark_map_page_writable(map_page);
        if status == 0 {
            entry.write(map_type as u8);
            store_be32(entry.add(1), parent_pgno);
        }
    }

    release_object(map_page);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut RESOLVE_STATUS: u32 = 0;
    static mut RESOLVED_PAGE: *mut u8 = core::ptr::null_mut();
    static mut WRITE_STATUS: u32 = 0;
    static mut RESOLVE_CALLS: u32 = 0;
    static mut WRITE_CALLS: u32 = 0;
    static mut LAST_RESOLVE: Option<(*mut u8, u32, u32)> = None;
    static mut LAST_WRITTEN_PAGE: *mut u8 = core::ptr::null_mut();

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

    unsafe extern "C" fn recording_write(page: *mut u8) -> u32 {
        WRITE_CALLS += 1;
        LAST_WRITTEN_PAGE = page;
        WRITE_STATUS
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

    fn bench(page: *mut u8, resolve_status: u32, write_status: u32) -> Bench {
        let lock = lock_ops();
        unsafe {
            RESOLVE_STATUS = resolve_status;
            RESOLVED_PAGE = page;
            WRITE_STATUS = write_status;
            RESOLVE_CALLS = 0;
            WRITE_CALLS = 0;
            LAST_RESOLVE = None;
            LAST_WRITTEN_PAGE = core::ptr::null_mut();
            core::ptr::addr_of_mut!(PTRMAP_PUT_HOST_OPS).write_volatile(PtrmapPutHostOps {
                resolve: recording_resolve,
                write: recording_write,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PTRMAP_PUT_HOST_OPS)
                    .write_volatile(DEFAULT_PTRMAP_PUT_HOST_OPS);
            }
        }
    }

    #[repr(align(8))]
    struct BtFixture {
        bytes: [u8; 0x24],
    }

    impl BtFixture {
        fn new(context: *mut u8, page_size: u16, usable_size: u16) -> Self {
            let mut fixture = Self { bytes: [0; 0x24] };
            unsafe { (fixture.bytes.as_mut_ptr() as *mut *mut u8).write(context) };
            fixture.bytes[0x1c..0x1e].copy_from_slice(&page_size.to_le_bytes());
            fixture.bytes[0x1e..0x20].copy_from_slice(&usable_size.to_le_bytes());
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

    #[repr(align(8))]
    struct ContextFixture {
        bytes: [u8; 0x100],
    }

    impl ContextFixture {
        fn new() -> Self {
            Self { bytes: [0; 0x100] }
        }
    }

    fn map_page_for(bt: &BtFixture, pgno: u32) -> u32 {
        unsafe { ptrmap_pageno(bt.bytes.as_ptr(), pgno) }
    }

    #[test]
    fn zero_pgno_returns_corrupt_without_resolving_a_page() {
        let mut context = ContextFixture::new();
        let mut bt = BtFixture::new(context.bytes.as_mut_ptr(), 1024, 1024);
        let _bench = bench(core::ptr::null_mut(), 0, 0);

        let status = unsafe { ptrmap_put(bt.bytes.as_mut_ptr(), 0, 1, 2) };

        assert_eq!(status, SQLITE_CORRUPT);
        assert_eq!(unsafe { RESOLVE_CALLS }, 0);
        assert_eq!(unsafe { WRITE_CALLS }, 0);
    }

    #[test]
    fn resolver_failure_returns_without_releasing_or_writing() {
        let mut context = ContextFixture::new();
        let mut bt = BtFixture::new(context.bytes.as_mut_ptr(), 1024, 1024);
        let mut data = [0xa5u8; 1024];
        let mut page = MapPageFixture::new(context.bytes.as_mut_ptr(), data.as_mut_ptr());
        let _bench = bench(page.bytes.as_mut_ptr(), 7, 0);

        let status = unsafe { ptrmap_put(bt.bytes.as_mut_ptr(), 3, 1, 0) };

        assert_eq!(status, 7);
        assert_eq!(unsafe { RESOLVE_CALLS }, 1);
        assert_eq!(unsafe { WRITE_CALLS }, 0);
        assert_eq!(page.refcount(), 2, "failed lease must not be released");
    }

    #[test]
    fn matching_entry_skips_write_and_releases_the_page() {
        let mut context = ContextFixture::new();
        let mut bt = BtFixture::new(context.bytes.as_mut_ptr(), 1024, 1024);
        let pgno = 3;
        let offset = (pgno - map_page_for(&bt, pgno) - 1) as usize * 5;
        let mut data = [0xa5u8; 1024];
        data[offset] = 5;
        data[offset + 1..offset + 5].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        let mut page = MapPageFixture::new(context.bytes.as_mut_ptr(), data.as_mut_ptr());
        let _bench = bench(page.bytes.as_mut_ptr(), 0, 0);

        let status = unsafe { ptrmap_put(bt.bytes.as_mut_ptr(), pgno, 5, 0x1234_5678) };

        assert_eq!(status, 0);
        assert_eq!(unsafe { WRITE_CALLS }, 0);
        assert_eq!(page.refcount(), 1);
        assert_eq!(&data[offset..offset + 5], &[5, 0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn dirty_failure_preserves_mismatched_entry_but_releases_page() {
        let mut context = ContextFixture::new();
        let mut bt = BtFixture::new(context.bytes.as_mut_ptr(), 1024, 1024);
        let pgno = 3;
        let offset = (pgno - map_page_for(&bt, pgno) - 1) as usize * 5;
        let mut data = [0xa5u8; 1024];
        data[offset..offset + 5].copy_from_slice(&[2, 0, 0, 0, 4]);
        let mut page = MapPageFixture::new(context.bytes.as_mut_ptr(), data.as_mut_ptr());
        let _bench = bench(page.bytes.as_mut_ptr(), 0, 9);

        let status = unsafe { ptrmap_put(bt.bytes.as_mut_ptr(), pgno, 3, 0x1122_3344) };

        assert_eq!(status, 9);
        assert_eq!(unsafe { WRITE_CALLS }, 1);
        assert_eq!(unsafe { LAST_WRITTEN_PAGE }, page.bytes.as_mut_ptr());
        assert_eq!(page.refcount(), 1);
        assert_eq!(&data[offset..offset + 5], &[2, 0, 0, 0, 4]);
    }

    #[test]
    fn writes_big_endian_parent_after_type_mismatch_including_high_bits() {
        let mut context = ContextFixture::new();
        let mut bt = BtFixture::new(context.bytes.as_mut_ptr(), 1024, 1024);
        let pgno = 3;
        let map_page = map_page_for(&bt, pgno);
        let offset = (pgno - map_page - 1) as usize * 5;
        let mut data = [0xa5u8; 1024];
        data[offset..offset + 5].copy_from_slice(&[1, 0, 0, 0, 0]);
        let mut page = MapPageFixture::new(context.bytes.as_mut_ptr(), data.as_mut_ptr());
        let _bench = bench(page.bytes.as_mut_ptr(), 0, 0);

        let status = unsafe { ptrmap_put(bt.bytes.as_mut_ptr(), pgno, 0x101, 0xa1b2_c3d4) };

        assert_eq!(status, 0);
        assert_eq!(unsafe { RESOLVE_CALLS }, 1);
        assert_eq!(unsafe { LAST_RESOLVE }, Some((context.bytes.as_mut_ptr(), map_page, 0)));
        assert_eq!(unsafe { WRITE_CALLS }, 1, "ldrb compares against all map_type bits");
        assert_eq!(page.refcount(), 1);
        assert_eq!(&data[offset..offset + 5], &[1, 0xa1, 0xb2, 0xc3, 0xd4]);
    }
}
