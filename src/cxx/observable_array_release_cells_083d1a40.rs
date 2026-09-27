//! `observable_array_release_cells_083d1a40` — retailOS `FUN_083d1a40` @
//! **0x083d1a40**.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes sixteen A32 words from `0x083d1a40` through
//! `0x083d1a7c`; the next real function begins at `0x083d1a80`, so the true
//! size is **64 bytes**, not Ghidra's 60-byte extent. The body has two plain
//! direct `bl` instructions, to `container_element_at_alias_6bc0` @
//! `0x083d6bc0` and `operator_delete` @ `0x082aad24`; it has no predicated
//! direct `bl`. Whole-image decoding finds two inbound plain `bl` sites
//! (0x083d1ac0 and 0x083d1af8), and no predicated inbound direct `bl` sites.
//!
//! ## Algorithm
//!
//! If the enable byte at `+0x10` is nonzero, walk signed indices `[0, count)`.
//! For each index, load the element through `container_element_at_alias_6bc0`
//! and tag-2-delete it. The retail loop deliberately passes NULL elements to
//! `operator_delete`, whose NULL guard makes that safe.
//!
//! Deliberate deviations: host fixtures use native-width vtable pointers and a
//! recording delete seam because fixture addresses are not retail heap blocks.

use crate::cxx::templates::container_element_at_alias_6bc0;
use crate::heap::veneers::operator_delete;

/// Target-layout prefix consumed by the retail cleanup loop.
#[repr(C)]
pub struct ObservableArrayReleaseCells083d1a40 {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
pub type ObservableArrayReleaseCells083d1a40Delete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_delete(cell: *mut u8) {
    unsafe { operator_delete(cell) };
}

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_RELEASE_CELLS_083D1A40_DELETE: ObservableArrayReleaseCells083d1a40Delete = host_delete;

#[inline(always)]
unsafe fn delete_cell(cell: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { operator_delete(cell) };
    #[cfg(not(target_os = "none"))]
    unsafe { OBSERVABLE_ARRAY_RELEASE_CELLS_083D1A40_DELETE(cell) };
}

/// Releases each element supplied by the indexed virtual accessor while enabled.
///
/// # Safety
///
/// `this` must point to a readable target-layout collection. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return an element pointer;
/// each element is passed directly to `operator_delete`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_release_cells_083d1a40(this: *mut ObservableArrayReleaseCells083d1a40) {
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if unsafe { base.add(0x10).read_volatile() } == 0 {
            return;
        }
        let count = unsafe { base.add(0x04).cast::<i32>().read_volatile() };
        let mut index = 0;
        while index < count {
            unsafe { delete_cell(container_element_at_alias_6bc0(base, index as usize)) };
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostObservableArrayReleaseCells083d1a40>();
        if unsafe { (*host).enabled } == 0 {
            return;
        }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            unsafe { delete_cell(((*(*host).vtable).cell_at)(this.cast(), index)) };
            index += 1;
        }
    }
}

/// Host-only replacement of the target vtable word with a native pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayReleaseCells083d1a40 {
    pub vtable: *const ObservableArrayReleaseCells083d1a40Vtable,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct ObservableArrayReleaseCells083d1a40Vtable {
    pub unresolved_00_3c: [usize; 16],
    pub cell_at: unsafe extern "C" fn(*mut ObservableArrayReleaseCells083d1a40, i32) -> *mut u8,
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
    static mut ELEMENTS: [usize; 4] = [0; 4];

    unsafe extern "C" fn cell_at(_: *mut ObservableArrayReleaseCells083d1a40, index: i32) -> *mut u8 {
        unsafe { INDEXES[INDEX_COUNT] = index; INDEX_COUNT += 1; ELEMENTS[index as usize] as *mut u8 }
    }

    unsafe extern "C" fn record_delete(cell: *mut u8) {
        unsafe { DELETED[DELETE_COUNT] = cell as usize; DELETE_COUNT += 1; }
    }

    fn fixture(enabled: u8, count: i32, vtable: *const ObservableArrayReleaseCells083d1a40Vtable) -> HostObservableArrayReleaseCells083d1a40 {
        HostObservableArrayReleaseCells083d1a40 { vtable, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_counts() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayReleaseCells083d1a40Vtable { unresolved_00_3c: [0; 16], cell_at };
            INDEX_COUNT = 0; DELETE_COUNT = 0; OBSERVABLE_ARRAY_RELEASE_CELLS_083D1A40_DELETE = record_delete;
            observable_array_release_cells_083d1a40((&mut fixture(0, 2, &vtable) as *mut HostObservableArrayReleaseCells083d1a40).cast());
            observable_array_release_cells_083d1a40((&mut fixture(1, 0, &vtable) as *mut HostObservableArrayReleaseCells083d1a40).cast());
            observable_array_release_cells_083d1a40((&mut fixture(1, -1, &vtable) as *mut HostObservableArrayReleaseCells083d1a40).cast());
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn deletes_every_element_in_index_order_including_null() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayReleaseCells083d1a40Vtable { unresolved_00_3c: [0; 16], cell_at };
            ELEMENTS = [0x1000, 0, 0x3000, 0]; INDEX_COUNT = 0; DELETE_COUNT = 0;
            OBSERVABLE_ARRAY_RELEASE_CELLS_083D1A40_DELETE = record_delete;
            observable_array_release_cells_083d1a40((&mut fixture(1, 3, &vtable) as *mut HostObservableArrayReleaseCells083d1a40).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0, 0x3000]);
        }
    }
}
