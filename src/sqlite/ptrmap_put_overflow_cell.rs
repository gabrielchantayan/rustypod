//! SQLite auto-vacuum overflow-cell pointer-map wrapper.
//!
//! `ptrmap_put_overflow_cell` — original: `FUN_082e8774` @ `0x082e8774`
//! (28 bytes). Raw `osos.dec` establishes the extent through the fall-through
//! at `0x082e8790`: `push {r4,lr}` begins at `0x082e8774`, the next six words
//! resolve the cell, and `mov r0,r0` at `0x082e878c` deliberately falls into
//! the separately linked `ptrmapPutOvflPtr` body at `0x082e8790`. Decoding
//! every ARM `B`/`BL` immediate finds five direct inbound calls, all plain,
//! unconditional `bl`: `0x082b5c7c`, `0x082b6574`, `0x082b6704`,
//! `0x082b69d0`, and `0x082b6bc0`; no predicated forms.
//!
//! # Algorithm
//!
//! Resolve `cell_index` with the ported `segmented_entry_lookup` (SQLite's
//! `findOverflowCell`), then tail-transfer the page and resolved cell pointer
//! to retailOS' separately linked `ptrmapPutOvflPtr` at `0x082e8790`.
//!
//! # Deliberate deviations
//!
//! `ptrmapPutOvflPtr` is not yet ported. Target builds call its verified load
//! address directly; host tests substitute that single unported boundary to
//! observe the resolved pointer and returned SQLite status.

use crate::app::segmented_entry_lookup::{segmented_entry_lookup, SegmentedEntryTable};

const SQLITE_CORRUPT: u32 = 11;

#[cfg(target_os = "none")]
const PTRMAP_PUT_OVERFLOW_PTR_ADDRESS: usize = 0x082e_8790;

type PtrmapPutOverflowPtr = unsafe extern "C" fn(*mut SegmentedEntryTable, *mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn ptrmap_put_overflow_ptr(page: *mut SegmentedEntryTable, cell: *mut u8) -> u32 {
    let callee: PtrmapPutOverflowPtr = unsafe { core::mem::transmute(PTRMAP_PUT_OVERFLOW_PTR_ADDRESS) };
    unsafe { callee(page, cell) }
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct PtrmapPutOverflowCellHostOps {
    ptrmap_put_overflow_ptr: PtrmapPutOverflowPtr,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_ptrmap_put_overflow_ptr(
    _page: *mut SegmentedEntryTable,
    _cell: *mut u8,
) -> u32 {
    SQLITE_CORRUPT
}

#[cfg(not(target_os = "none"))]
const DEFAULT_PTRMAP_PUT_OVERFLOW_CELL_HOST_OPS: PtrmapPutOverflowCellHostOps =
    PtrmapPutOverflowCellHostOps { ptrmap_put_overflow_ptr: unavailable_ptrmap_put_overflow_ptr };

#[cfg(not(target_os = "none"))]
static mut PTRMAP_PUT_OVERFLOW_CELL_HOST_OPS: PtrmapPutOverflowCellHostOps =
    DEFAULT_PTRMAP_PUT_OVERFLOW_CELL_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn ptrmap_put_overflow_ptr(page: *mut SegmentedEntryTable, cell: *mut u8) -> u32 {
    let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PTRMAP_PUT_OVERFLOW_CELL_HOST_OPS)) };
    unsafe { (ops.ptrmap_put_overflow_ptr)(page, cell) }
}

/// `ptrmapPutOvfl` — original: `FUN_082e8774` @ `0x082e8774` (28 bytes; five
/// unconditional direct `bl` call sites, binary-scanned).
///
/// Resolves an indexed cell, accounting for overflow-cell overrides, then
/// returns the status from `ptrmapPutOvflPtr`. RetailOS supplies no NULL or
/// index-range validation; callers retain those preconditions.
///
/// # Safety
///
/// `page` must identify readable, aligned [`SegmentedEntryTable`] storage;
/// its lookup fields must meet [`segmented_entry_lookup`]'s safety contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ptrmap_put_overflow_cell")]
#[inline(never)]
pub unsafe extern "C" fn ptrmap_put_overflow_cell(
    page: *mut SegmentedEntryTable,
    cell_index: i32,
) -> u32 {
    let cell = unsafe { segmented_entry_lookup(page, cell_index) };
    unsafe { ptrmap_put_overflow_ptr(page, cell) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::segmented_entry_lookup::SegmentedEntryOverride;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static LAST_PAGE: AtomicUsize = AtomicUsize::new(0);
    static LAST_CELL: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_ptrmap_put_overflow_ptr(
        page: *mut SegmentedEntryTable,
        cell: *mut u8,
    ) -> u32 {
        LAST_PAGE.store(page as usize, Ordering::Relaxed);
        LAST_CELL.store(cell as usize, Ordering::Relaxed);
        0x5a
    }

    #[test]
    fn resolves_direct_override_and_adjusted_fallback_before_tail_call() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SQLITE_PTRMAP_PUT_OVERFLOW_CELL, 0x1000) else {
            assert!(note_missing_u32_fixture("sqlite::ptrmap_put_overflow_cell"));
            return;
        };
        let table = slab.cast::<SegmentedEntryTable>();
        let entry_data = unsafe { slab.add(0x100) };
        let direct_cell = unsafe { slab.add(0x200) };
        let fallback_cell = unsafe { slab.add(0x300) };

        unsafe {
            entry_data.add(0x16).write(0x02);
            entry_data.add(0x17).write(0x00);
            table.write(SegmentedEntryTable {
                opaque_00_to_01: [0; 2],
                override_count: 2,
                opaque_03_to_0d: [0; 11],
                offset_table_start: 0x10,
                opaque_10_to_17: [0; 8],
                overrides: [
                    SegmentedEntryOverride {
                        direct_entry: direct_cell as usize as u32,
                        boundary: 3,
                        opaque_06_to_07: [0; 2],
                    },
                    SegmentedEntryOverride {
                        direct_entry: 0,
                        boundary: 5,
                        opaque_06_to_07: [0; 2],
                    },
                    SegmentedEntryOverride {
                        direct_entry: 0,
                        boundary: 0,
                        opaque_06_to_07: [0; 2],
                    },
                    SegmentedEntryOverride {
                        direct_entry: 0,
                        boundary: 0,
                        opaque_06_to_07: [0; 2],
                    },
                    SegmentedEntryOverride {
                        direct_entry: 0,
                        boundary: 0,
                        opaque_06_to_07: [0; 2],
                    },
                ],
                opaque_40_to_43: [0; 4],
                entry_data: entry_data as usize as u32,
            });
            PTRMAP_PUT_OVERFLOW_CELL_HOST_OPS = PtrmapPutOverflowCellHostOps {
                ptrmap_put_overflow_ptr: record_ptrmap_put_overflow_ptr,
            };
        }

        assert_eq!(unsafe { ptrmap_put_overflow_cell(table, 3) }, 0x5a);
        assert_eq!(LAST_PAGE.load(Ordering::Relaxed), table as usize);
        assert_eq!(LAST_CELL.load(Ordering::Relaxed), direct_cell as usize);

        assert_eq!(unsafe { ptrmap_put_overflow_cell(table, 4) }, 0x5a);
        assert_eq!(LAST_PAGE.load(Ordering::Relaxed), table as usize);
        assert_eq!(LAST_CELL.load(Ordering::Relaxed), fallback_cell as usize);

        unsafe {
            PTRMAP_PUT_OVERFLOW_CELL_HOST_OPS = DEFAULT_PTRMAP_PUT_OVERFLOW_CELL_HOST_OPS;
        }
    }
}
