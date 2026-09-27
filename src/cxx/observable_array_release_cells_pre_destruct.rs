//! `observable_array_release_cells_pre_destruct` — retailOS `FUN_083d1870` @
//! `0x083d1870`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes eighteen A32 words from `0x083d1870` through
//! `0x083d18b4`; the following `push {r4,r5,r6,lr}` at `0x083d18bc` begins the
//! next real function, so the true size is **72 bytes**. The body has one plain
//! direct `bl` to `operator_delete` @ `0x082aad24`, no predicated direct `bl`,
//! and one unconditional virtual `blx` through vtable slot `+0x40`. Whole-image
//! decoding finds two inbound plain `bl` sites (`0x083d1908`, `0x083d1940`) and
//! no predicated inbound `bl` sites.
//!
//! ## Algorithm
//!
//! When the byte at `+0x10` is nonzero, visit indices `[0, count)`. Each vtable
//! `+0x40` lookup returns a cell whose first word is passed to tag-2
//! `operator_delete`. Null returned bodies are deliberately forwarded because
//! `operator_delete` is null-safe.
//!
//! Deliberate deviations: host fixtures replace target-width vtable words and
//! allocator state with native callbacks. Rust uses ordinary branches rather
//! than the retail early `popeq` and indirect `blx`.

use crate::heap::veneers::operator_delete;

/// Target vtable slot `+0x40`.
pub type ObservableArrayPreDestructCellAt = unsafe extern "C" fn(*mut u32, i32) -> *mut u32;

#[repr(C)]
pub struct ObservableArrayPreDestructCellsVtable {
    pub unresolved_00_3c: [usize; 16],
    pub cell_at: ObservableArrayPreDestructCellAt,
}

#[cfg(not(target_os = "none"))]
pub type ObservableArrayPreDestructCellDelete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_delete(cell_body: *mut u8) {
    unsafe { operator_delete(cell_body) };
}

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_PRE_DESTRUCT_CELL_DELETE: ObservableArrayPreDestructCellDelete = host_delete;

#[inline(always)]
unsafe fn delete_cell(cell: *mut u32) {
    let body = unsafe { cell.read_volatile() } as usize as *mut u8;
    #[cfg(target_os = "none")]
    unsafe { operator_delete(body) };
    #[cfg(not(target_os = "none"))]
    unsafe { OBSERVABLE_ARRAY_PRE_DESTRUCT_CELL_DELETE(body) };
}

/// Releases cells through the pre-destruction array vtable.
///
/// # Safety
/// `this` must address an array with readable target fields at `+0`, `+4`, and
/// `+0x10`; when enabled, its vtable `+0x40` callback and returned cells must be
/// valid for the accesses described above.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_release_cells_pre_destruct(this: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if unsafe { base.add(0x10).read_volatile() } == 0 {
            return;
        }
        let count = unsafe { base.add(4).cast::<i32>().read_volatile() };
        let vtable = unsafe { this.read_volatile() } as usize as *const u32;
        let cell_at: ObservableArrayPreDestructCellAt = unsafe { core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize) };
        let mut index = 0;
        while index < count {
            unsafe { delete_cell(cell_at(this, index)) };
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostObservableArrayPreDestructCells>();
        if unsafe { (*host).enabled } == 0 {
            return;
        }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            unsafe { delete_cell(((*(*host).vtable).cell_at)(this, index)) };
            index += 1;
        }
    }
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayPreDestructCells {
    pub vtable: *const ObservableArrayPreDestructCellsVtable,
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

    unsafe extern "C" fn cell_at(_: *mut u32, index: i32) -> *mut u32 {
        unsafe { INDEXES[INDEX_COUNT] = index; INDEX_COUNT += 1; CELLS.as_mut_ptr().add(index as usize) }
    }

    unsafe extern "C" fn record_delete(body: *mut u8) {
        unsafe { DELETED[DELETE_COUNT] = body as usize; DELETE_COUNT += 1; }
    }

    fn fixture(enabled: u8, count: i32, vtable: *const ObservableArrayPreDestructCellsVtable) -> HostObservableArrayPreDestructCells {
        HostObservableArrayPreDestructCells { vtable, count, unresolved_0c_13: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_counts() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayPreDestructCellsVtable { unresolved_00_3c: [0; 16], cell_at };
            INDEX_COUNT = 0; DELETE_COUNT = 0; OBSERVABLE_ARRAY_PRE_DESTRUCT_CELL_DELETE = record_delete;
            observable_array_release_cells_pre_destruct((&mut fixture(0, 2, &vtable) as *mut HostObservableArrayPreDestructCells).cast());
            observable_array_release_cells_pre_destruct((&mut fixture(1, 0, &vtable) as *mut HostObservableArrayPreDestructCells).cast());
            observable_array_release_cells_pre_destruct((&mut fixture(1, -1, &vtable) as *mut HostObservableArrayPreDestructCells).cast());
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn releases_every_cell_body_in_index_order_including_null() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayPreDestructCellsVtable { unresolved_00_3c: [0; 16], cell_at };
            CELLS = [0x1000, 0, 0x3000, 0]; INDEX_COUNT = 0; DELETE_COUNT = 0;
            OBSERVABLE_ARRAY_PRE_DESTRUCT_CELL_DELETE = record_delete;
            observable_array_release_cells_pre_destruct((&mut fixture(1, 3, &vtable) as *mut HostObservableArrayPreDestructCells).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0, 0x3000]);
        }
    }
}
