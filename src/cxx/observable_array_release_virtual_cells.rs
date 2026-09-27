//! `observable_array_release_virtual_cells` — retailOS `FUN_083cf9fc` @ `0x083cf9fc`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes twenty-two A32 words from `0x083cf9fc` through
//! `0x083cfa50`; the next real function starts at `0x083cfa54` with
//! `push {r4,r5,r6,lr}`, so the true size is **88 bytes**. The body has no
//! plain direct `bl` instructions, no predicated direct `bl` instructions,
//! one unconditional indirect `blx` through vtable slot `+0x40`, and one
//! predicated indirect `blxne` through a returned object's vtable slot `+0x4`.
//! The two inbound plain `bl` sites are `0x083cfaac` and `0x083cfae4`; neither
//! is predicated.
//!
//! ## Algorithm
//!
//! If the enable byte at `+0x10` is set, walk indices `[0, count)`. For each
//! index, call the `+0x40` virtual accessor, load the returned cell's first
//! word, and when nonzero invoke that object's virtual `+0x4` method with the
//! object in `r0`.
//!
//! Deliberate deviations: the two virtual methods have no recovered identities,
//! so typed host vtables model their observed ABI while target builds dispatch
//! their target-width addresses directly.

/// Target vtable slot `+0x40`.
pub type ObservableArrayVirtualCellAt = unsafe extern "C" fn(*mut ObservableArrayReleaseVirtualCells, i32) -> *mut u32;

/// Host representation of the observed target accessor vtable.
#[repr(C)]
pub struct ObservableArrayReleaseVirtualCellsVtable {
    pub unresolved_00_3c: [usize; 16],
    pub cell_at: ObservableArrayVirtualCellAt,
}

/// Target-layout prefix consumed by the retail cleanup loop.
#[repr(C)]
pub struct ObservableArrayReleaseVirtualCells {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
/// Host representation of an object's observed vtable slot `+0x4`.
#[repr(C)]
pub struct HostObservableArrayCellVtable {
    pub unresolved_00: usize,
    pub release: unsafe extern "C" fn(*mut u8),
}

#[inline(always)]
unsafe fn release_cell(cell: *mut u32) {
    let object = unsafe { cell.read_volatile() } as usize as *mut u8;
    if object.is_null() {
        return;
    }

    #[cfg(target_os = "none")]
    {
        let vtable = unsafe { object.cast::<u32>().read_volatile() } as usize as *const u32;
        let release: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(vtable.add(1).read_volatile() as usize) };
        unsafe { release(object) };
    }

    #[cfg(not(target_os = "none"))]
    {
        let vtable = unsafe { object.cast::<*const HostObservableArrayCellVtable>().read() };
        unsafe { ((*vtable).release)(object) };
    }
}

/// Releases every non-null virtual cell supplied by the indexed accessor.
///
/// # Safety
///
/// `this` must point to a readable target-layout collection. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell.
/// Each non-null cell word must name an object whose vtable `+0x4` entry accepts
/// that object in `r0`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_release_virtual_cells(this: *mut ObservableArrayReleaseVirtualCells) {
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if unsafe { base.add(0x10).read_volatile() } == 0 {
            return;
        }
        let count = unsafe { base.add(0x04).cast::<i32>().read_volatile() };
        let vtable = unsafe { base.cast::<u32>().read_volatile() } as usize as *const u32;
        let cell_at: ObservableArrayVirtualCellAt = unsafe { core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize) };
        let mut index = 0;
        while index < count {
            unsafe { release_cell(cell_at(this, index)) };
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostObservableArrayReleaseVirtualCells>();
        if unsafe { (*host).enabled } == 0 {
            return;
        }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            unsafe { release_cell(((*(*host).vtable).cell_at)(this, index)) };
            index += 1;
        }
    }
}

/// Host-only replacement of the target vtable word with a native pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayReleaseVirtualCells {
    pub vtable: *const ObservableArrayReleaseVirtualCellsVtable,
    pub count: i32,
    pub unresolved_0c_13: [u8; 8],
    pub enabled: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];
    static mut RELEASED: [usize; 4] = [0; 4];
    static mut RELEASE_COUNT: usize = 0;

    #[repr(C)]
    struct CellObject {
        vtable: *const HostObservableArrayCellVtable,
    }

    unsafe extern "C" fn cell_at(_: *mut ObservableArrayReleaseVirtualCells, index: i32) -> *mut u32 {
        unsafe { INDEXES[INDEX_COUNT] = index; INDEX_COUNT += 1; CELLS.as_mut_ptr().add(index as usize) }
    }

    unsafe extern "C" fn record_release(object: *mut u8) {
        unsafe { RELEASED[RELEASE_COUNT] = object as usize; RELEASE_COUNT += 1; }
    }

    fn fixture(enabled: u8, count: i32, vtable: *const ObservableArrayReleaseVirtualCellsVtable) -> HostObservableArrayReleaseVirtualCells {
        HostObservableArrayReleaseVirtualCells { vtable, count, unresolved_0c_13: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_counts() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayReleaseVirtualCellsVtable { unresolved_00_3c: [0; 16], cell_at };
            INDEX_COUNT = 0;
            RELEASE_COUNT = 0;
            observable_array_release_virtual_cells((&mut fixture(0, 2, &vtable) as *mut HostObservableArrayReleaseVirtualCells).cast());
            observable_array_release_virtual_cells((&mut fixture(1, 0, &vtable) as *mut HostObservableArrayReleaseVirtualCells).cast());
            observable_array_release_virtual_cells((&mut fixture(1, -1, &vtable) as *mut HostObservableArrayReleaseVirtualCells).cast());
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(RELEASE_COUNT, 0);
        }
    }

    #[test]
    fn releases_nonnull_cells_in_index_order() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CXX_OBSERVABLE_ARRAY_RELEASE_VIRTUAL_CELLS, 0x100) else {
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x100);
            let accessor_vtable = ObservableArrayReleaseVirtualCellsVtable { unresolved_00_3c: [0; 16], cell_at };
            let cell_vtable = HostObservableArrayCellVtable { unresolved_00: 0, release: record_release };
            let first = slab.cast::<CellObject>();
            let second = slab.add(0x20).cast::<CellObject>();
            first.write(CellObject { vtable: &cell_vtable });
            second.write(CellObject { vtable: &cell_vtable });
            CELLS = [first as usize as u32, 0, second as usize as u32, 0];
            INDEX_COUNT = 0;
            RELEASE_COUNT = 0;
            observable_array_release_virtual_cells((&mut fixture(1, 3, &accessor_vtable) as *mut HostObservableArrayReleaseVirtualCells).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&RELEASED[..RELEASE_COUNT], &[first as usize, second as usize]);
        }
    }
}
