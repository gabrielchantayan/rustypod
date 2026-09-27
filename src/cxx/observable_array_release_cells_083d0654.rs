//! `observable_array_release_cells_083d0654` — retailOS `FUN_083d0654` @ `0x083d0654`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes nineteen A32 words from `0x083d0654` through
//! `0x083d069c`; the next real function starts at `0x083d06a0` with
//! `push {r4,r5,r6,lr}`, so the true size is **76 bytes**. The body has one
//! unconditional plain direct `bl` to `operator_delete` @ `0x082aad24`, no
//! predicated direct `bl`, and one unconditional indirect `blx` through vtable
//! slot `+0x40`. Whole-image decoding finds two inbound unconditional plain
//! `bl` sites, `0x083d06ec` and `0x083d0724`, and no predicated inbound calls.
//!
//! ## Algorithm
//!
//! If the enable byte at `+0x10` is set, walk signed indices `[0, count)`. For
//! each index, call the `+0x40` virtual accessor, load the returned cell's
//! first word, and tag-2-delete that allocation body. The retail loop does not
//! skip null cells; `operator_delete` is its null-safe callee.
//!
//! Deliberate deviations: host fixtures widen the vtable pointer and replace
//! `operator_delete` with a recording seam, since native callbacks and fixture
//! addresses do not fit in target `u32` words.

use crate::heap::veneers::operator_delete;

/// Target vtable slot `+0x40`.
pub type ObservableArrayCellAt083d0654 = unsafe extern "C" fn(*mut ObservableArrayReleaseCells083d0654, i32) -> *mut u32;

/// Host representation of the observed target vtable slot.
#[repr(C)]
pub struct ObservableArrayReleaseCells083d0654Vtable {
    pub unresolved_00_3c: [usize; 16],
    pub cell_at: ObservableArrayCellAt083d0654,
}

/// Target-layout prefix consumed by the retail cleanup loop.
#[repr(C)]
pub struct ObservableArrayReleaseCells083d0654 {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
pub type ObservableArrayCellDelete083d0654 = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_delete(cell_body: *mut u8) {
    unsafe { operator_delete(cell_body) };
}

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_CELL_DELETE_083D0654: ObservableArrayCellDelete083d0654 = host_delete;

#[inline(always)]
unsafe fn delete_cell(cell: *mut u32) {
    let cell_body = unsafe { cell.read_volatile() } as usize as *mut u8;
    #[cfg(target_os = "none")]
    unsafe { operator_delete(cell_body) };
    #[cfg(not(target_os = "none"))]
    unsafe { OBSERVABLE_ARRAY_CELL_DELETE_083D0654(cell_body) };
}

/// Releases each cell supplied by the indexed virtual accessor while enabled.
///
/// # Safety
///
/// `array` must point to a readable target-layout collection. When enabled,
/// its vtable slot `+0x40` must accept `(array, index)` and return a readable
/// cell; every cell's first word is passed directly to `operator_delete`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_release_cells_083d0654(array: *mut ObservableArrayReleaseCells083d0654) {
    #[cfg(target_os = "none")]
    {
        let base = array.cast::<u8>();
        if unsafe { base.add(0x10).read_volatile() } == 0 {
            return;
        }
        let count = unsafe { base.add(0x04).cast::<i32>().read_volatile() };
        let vtable = unsafe { base.cast::<u32>().read_volatile() } as usize as *const u32;
        let cell_at: ObservableArrayCellAt083d0654 = unsafe { core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize) };
        let mut index = 0;
        while index < count {
            unsafe { delete_cell(cell_at(array, index)) };
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = array.cast::<HostObservableArrayReleaseCells083d0654>();
        if unsafe { (*host).enabled } == 0 {
            return;
        }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            unsafe { delete_cell(((*(*host).vtable).cell_at)(array, index)) };
            index += 1;
        }
    }
}

/// Host-only replacement of the target vtable word with a native pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayReleaseCells083d0654 {
    pub vtable: *const ObservableArrayReleaseCells083d0654Vtable,
    pub count: i32,
    pub unresolved_0c_13: [u8; 8],
    pub enabled: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DELETE_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];

    unsafe extern "C" fn cell_at(_: *mut ObservableArrayReleaseCells083d0654, index: i32) -> *mut u32 {
        unsafe { INDEXES[INDEX_COUNT] = index; INDEX_COUNT += 1; CELLS.as_mut_ptr().add(index as usize) }
    }

    unsafe extern "C" fn record_delete(cell_body: *mut u8) {
        unsafe { DELETED[DELETE_COUNT] = cell_body as usize; DELETE_COUNT += 1; }
    }

    fn fixture(enabled: u8, count: i32, vtable: *const ObservableArrayReleaseCells083d0654Vtable) -> HostObservableArrayReleaseCells083d0654 {
        HostObservableArrayReleaseCells083d0654 { vtable, count, unresolved_0c_13: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_counts() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayReleaseCells083d0654Vtable { unresolved_00_3c: [0; 16], cell_at };
            INDEX_COUNT = 0; DELETE_COUNT = 0; OBSERVABLE_ARRAY_CELL_DELETE_083D0654 = record_delete;
            observable_array_release_cells_083d0654((&mut fixture(0, 2, &vtable) as *mut HostObservableArrayReleaseCells083d0654).cast());
            observable_array_release_cells_083d0654((&mut fixture(1, 0, &vtable) as *mut HostObservableArrayReleaseCells083d0654).cast());
            observable_array_release_cells_083d0654((&mut fixture(1, -1, &vtable) as *mut HostObservableArrayReleaseCells083d0654).cast());
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn deletes_every_returned_cell_word_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayReleaseCells083d0654Vtable { unresolved_00_3c: [0; 16], cell_at };
            CELLS = [0x1000, 0, 0x3000, 0]; INDEX_COUNT = 0; DELETE_COUNT = 0;
            OBSERVABLE_ARRAY_CELL_DELETE_083D0654 = record_delete;
            observable_array_release_cells_083d0654((&mut fixture(1, 3, &vtable) as *mut HostObservableArrayReleaseCells083d0654).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0, 0x3000]);
        }
    }
}
