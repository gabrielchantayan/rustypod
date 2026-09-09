//! The auto-vacuum pointer-map page locator — SQLite 3.5.x's
//! `ptrmapPageno`, the pure arithmetic every pointer-map reader and
//! writer (`ptrmapGet` @ 0x082e85d8, `ptrmapPut` @ 0x082e86bc, and the
//! b-tree balance/free routines) runs to find the 5-byte-entry map page
//! covering a given database page.
//!
//! `ptrmap_pageno` — original: `FUN_082e866c` @ 0x082e866c (80 bytes,
//! extent verified from raw bytes: the sibling `FUN_082e86bc` begins
//! with its own `push {r3-r9,lr}` exactly 0x50 bytes later; 16 genuine
//! `bl` call sites, binary-scanned: 0x082b3834, 0x082b58f0, 0x082b5944,
//! 0x082b5994, 0x082bd9d8, 0x082bde48, 0x082ce068, 0x082d088c,
//! 0x082d4cdc, 0x082d4e70, 0x082e85ec, 0x082e861c, 0x082e86e0,
//! 0x082e8710, 0x08371a0c, 0x08371a50 — plus one `blge` decode at
//! 0x088f9b78 that sits in a data region (ASCII "iPod" adjacent) and is
//! a false positive, so 0 predicated calls).
//!
//! ```c
//! static Pgno ptrmapPageno(BtShared *pBt, Pgno pgno){
//!   int nPagesPerMapPage = (pBt->usableSize/5)+1;
//!   int iPtrMap = (pgno-2)/nPagesPerMapPage;
//!   Pgno ret = nPagesPerMapPage*iPtrMap + 2;
//!   if( PENDING_BYTE/pBt->pageSize + 1 == ret ){
//!     ret++;
//!   }
//!   return ret;
//! }
//! ```
//!
//! Algorithm (verified against the raw words; Ghidra's C matches it
//! here): pointer-map pages carry 5-byte entries (one type byte plus a
//! big-endian u32, cf. `ptrmapGet`'s `load_be32` @ 0x0837a158), so each
//! map page covers `usableSize/5 + 1` database pages. The page number is
//! reduced to a map index by dividing `pgno - 2` (pages 1..2 are the
//! header/lock area ahead of the first map page) by that span, then
//! mapped back to the map page's own number with a multiply and the +2
//! bias. If the result lands exactly on the pending-byte page
//! (`PENDING_BYTE 0x40000000 / pageSize + 1`, the reserved lock page),
//! it is bumped one page higher. All three divides are UNSIGNED
//! `__rt_udiv` @ 0x08036f14 (ported in `runtime/rt_div.rs`), quotient
//! only; `pgno - 2` and the multiply wrap mod 2^32 exactly like the ARM
//! `sub`/`mul`.
//!
//! `BtShared` fields read (offsets from the disassembly — `ldrh
//! r1,[r4,#0x1c]`, `ldrh r0,[r0,#0x1e]`; halfword-aligned, read
//! aligned):
//!
//! ```text
//! +0x1c  pageSize    (u16)  bytes per database page
//! +0x1e  usableSize  (u16)  usable bytes per page (pageSize minus the
//!                           reserved region)
//! ```
//!
//! Deviations:
//!
//! - None structural. The ported `__rt_udiv` is called directly (house
//!   precedent for ported callees — see `sqlite/parse_cell.rs`); its
//!   `#[inline(never)]` export keeps the three `bl 0x08036f14` call
//!   boundaries visible to match.py. Division by zero follows the
//!   helper's `__rt_div0` path exactly as on device. Wrapping operators
//!   make the original's mod-2^32 arithmetic explicit so host debug
//!   builds cannot panic where the hardware wraps.

use crate::runtime::rt_div::__rt_udiv;

/// `BtShared` byte offsets the original reads.
/// `pageSize` (u16): bytes per database page.
const BT_PAGE_SIZE: usize = 0x1c;
/// `usableSize` (u16): usable bytes per database page.
const BT_USABLE_SIZE: usize = 0x1e;

/// SQLite's reserved lock-page byte offset (`PENDING_BYTE`).
const PENDING_BYTE: u32 = 0x4000_0000;

/// Aligned u16 load — both offsets are halfword-aligned in `BtShared`
/// and the original uses `ldrh`, so this compiles to one `ldrh` too.
#[inline(always)]
unsafe fn rd_u16(base: *const u8, off: usize) -> u16 {
    base.add(off).cast::<u16>().read()
}

/// ptrmap_pageno — original: `FUN_082e866c` @ 0x082e866c (80 bytes;
/// 16 `bl` call sites).
///
/// SQLite's `ptrmapPageno`: return the page number of the pointer-map
/// page whose 5-byte entries cover database page `pgno` of the
/// auto-vacuum b-tree `bt` (`BtShared *`).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ptrmap_pageno(bt: *const u8, pgno: u32) -> u32 {
    let usable = rd_u16(bt, BT_USABLE_SIZE) as u32;
    let pages_per_map = __rt_udiv(usable, 5).wrapping_add(1);
    let map_index = __rt_udiv(pgno.wrapping_sub(2), pages_per_map);
    let mut ret = pages_per_map.wrapping_mul(map_index).wrapping_add(2);
    let page_size = rd_u16(bt, BT_PAGE_SIZE) as u32;
    let pending_page = __rt_udiv(PENDING_BYTE, page_size).wrapping_add(1);
    if pending_page == ret {
        ret = ret.wrapping_add(1);
    }
    ret
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// Builds a minimal fake `BtShared` (pageSize @ +0x1c, usableSize
    /// @ +0x1e; the only fields the function reads).
    fn bt_shared(page_size: u16, usable_size: u16) -> [u8; 0x20] {
        let mut bt = [0u8; 0x20];
        bt[BT_PAGE_SIZE..BT_PAGE_SIZE + 2].copy_from_slice(&page_size.to_le_bytes());
        bt[BT_USABLE_SIZE..BT_USABLE_SIZE + 2].copy_from_slice(&usable_size.to_le_bytes());
        bt
    }

    /// Independent reference model of the original arithmetic.
    fn reference(page_size: u16, usable_size: u16, pgno: u32) -> u32 {
        let per_map = (usable_size as u32) / 5 + 1;
        let index = pgno.wrapping_sub(2) / per_map;
        let mut ret = per_map.wrapping_mul(index).wrapping_add(2);
        if PENDING_BYTE / (page_size as u32) + 1 == ret {
            ret = ret.wrapping_add(1);
        }
        ret
    }

    #[test]
    fn small_page_numbers() {
        // 512-byte pages, no reserved region: 103 pages per group.
        // The map page heads its own group: page 2 covers pages
        // 3..=104 (102 five-byte entries fill the usable span), page
        // 105 heads the next group covering 106..=207, and so on.
        let bt = bt_shared(512, 512);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 3) }, 2);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 104) }, 2);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 105) }, 105);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 207) }, 105);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 208) }, 208);
    }

    #[test]
    fn reserved_region_shrinks_span() {
        // 1024-byte page with a 24-byte reserved region: usable 1000,
        // 201 pages per group; page 2 maps 3..=202, page 203 heads the
        // next group.
        let bt = bt_shared(1024, 1000);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 2) }, 2);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 202) }, 2);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 203) }, 203);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 403) }, 203);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 404) }, 404);
    }

    #[test]
    fn pending_byte_page_is_skipped() {
        // Pick geometry so an unbumped result lands exactly on the
        // pending-byte page PENDING_BYTE/pageSize + 1: pageSize =
        // 0x8000 puts the pending page at 0x8001, and usableSize =
        // 1080 (usable/5 = 216) gives per_map = 217, so map index 151
        // yields 217*151 + 2 = 0x7fff + 2 == 0x8001 (0x7fff = 7*31*151
        // and 217 = 7*31, so the divide is exact).
        let bt = bt_shared(0x8000, 1080);
        // First page of map index 151 -> unbumped ret = 0x8001 ==
        // pending page -> bumped to 0x8002.
        let pgno = 217 * 151 + 2; // 0x8001
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), pgno) }, 0x8002);
        // Last page of group 0 stays at 2, no bump.
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 218) }, 2);
        // Map index 2 is far below the pending page: no bump.
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 436) }, 436);
    }

    #[test]
    fn wrapping_pgno_below_two() {
        // pgno < 2 wraps to a huge u32 (the ARM `sub r0, r6, #2`);
        // the divide then yields a huge map index, not a panic.
        let bt = bt_shared(512, 512);
        let expected = reference(512, 512, 0);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 0) }, expected);
        let expected = reference(512, 512, 1);
        assert_eq!(unsafe { ptrmap_pageno(bt.as_ptr(), 1) }, expected);
    }

    #[test]
    fn reference_sweep() {
        // Cross-check against the independent model over the geometry
        // and page-number edges: span boundaries, the pending page, and
        // u32 extremes.
        for &(ps, us) in &[(512u16, 512u16), (1024, 1000), (4096, 4096), (0x8000, 1080)] {
            let bt = bt_shared(ps, us);
            let per_map = (us as u32) / 5 + 1;
            let pending = PENDING_BYTE / (ps as u32) + 1;
            let pgnos = [
                0u32,
                1,
                2,
                3,
                per_map + 1,
                per_map + 2,
                per_map * 2 + 2,
                pending - 1,
                pending,
                pending + 1,
                0xffff_ffff,
            ];
            for &pgno in &pgnos {
                assert_eq!(
                    unsafe { ptrmap_pageno(bt.as_ptr(), pgno) },
                    reference(ps, us, pgno),
                    "page_size={ps:#x} usable={us:#x} pgno={pgno:#x}"
                );
            }
        }
    }
}
