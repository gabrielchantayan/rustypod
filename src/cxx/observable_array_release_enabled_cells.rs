//! Enabled observable-array cell release.
//!
//! `observable_array_release_enabled_cells` — retailOS `FUN_083d019c` @
//! **0x083d019c**. Raw `osos.dec` establishes the true 88-byte extent:
//! twenty-two A32 words through `pop {r4,r5,r6,pc}` at `0x083d01f0`; the next
//! independently entered function begins with `push {r4,r5,r6,lr}` at
//! `0x083d01f4`. The body has no plain direct `bl` instructions, one
//! unconditional virtual `blx` through the collection vtable slot `+0x40`, and
//! one predicated virtual `blxne` through each non-null cell object's vtable
//! slot `+0x04`. Whole-image decoding finds two inbound unconditional plain
//! `bl` sites (`0x083d0240`, `0x083d0278`) and no predicated direct calls.
//!
//! When the byte at `+0x10` is nonzero, it walks indices `[0, count)`, obtains
//! each cell through vtable slot `+0x40`, and invokes slot `+0x04` on the
//! cell's non-null first-word object. Deliberate deviation: host fixtures use
//! native-width vtable pointers and callbacks; target builds retain firmware
//! word offsets. The predicated virtual call is ordinary null-guarded flow.

/// Collection vtable's indexed cell accessor at offset `+0x40`.
pub type EnabledCellAt = unsafe extern "C" fn(*mut ObservableArrayReleaseEnabledCells, i32) -> *mut u32;
type CellDestroy = unsafe extern "C" fn(*mut u8);
const CELL_AT_SLOT: usize = 0x40 / 4;
const CELL_DESTROY_SLOT: usize = 0x04 / 4;

/// Target-layout prefix used by the retail release loop.
#[repr(C)]
pub struct ObservableArrayReleaseEnabledCells {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cell_at(this: *mut ObservableArrayReleaseEnabledCells, index: i32) -> *mut u32 {
    let vtable = this.cast::<u32>().read_volatile() as usize as *const u32;
    let method: EnabledCellAt = core::mem::transmute(vtable.add(CELL_AT_SLOT).read_volatile() as usize);
    method(this, index)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_cell_object(object: *mut u8) {
    let vtable = object.cast::<u32>().read_volatile() as usize as *const u32;
    let method: CellDestroy = core::mem::transmute(vtable.add(CELL_DESTROY_SLOT).read_volatile() as usize);
    method(object);
}

/// Host vtable representation for the observed indexed accessor.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostEnabledCellVtable {
    pub unresolved_00_3c: [usize; CELL_AT_SLOT],
    pub cell_at: unsafe extern "C" fn(*mut ObservableArrayReleaseEnabledCells, i32) -> *mut *mut u8,
}

/// Host representation of a cell object whose vtable has a slot-`+0x04` destructor.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostEnabledCellObjectVtable {
    pub unresolved_00: usize,
    pub destroy: CellDestroy,
}

/// Host-only replacement for the target's 32-bit collection vtable word.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayReleaseEnabledCells {
    pub vtable: *const HostEnabledCellVtable,
    pub count: i32,
    pub unresolved_0c_13: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cell_at(this: *mut ObservableArrayReleaseEnabledCells, index: i32) -> *mut *mut u8 {
    let host = &*this.cast::<HostObservableArrayReleaseEnabledCells>();
    ((*host.vtable).cell_at)(this, index)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy_cell_object(object: *mut u8) {
    let vtable = object.cast::<*const HostEnabledCellObjectVtable>().read();
    ((*vtable).destroy)(object);
}

/// Releases every non-null cell object supplied by the indexed accessor.
///
/// # Safety
///
/// `this` must reference the target-layout collection. When enabled, its slot
/// `+0x40` accessor and every non-null returned object's slot `+0x04` must be
/// valid for the calls performed by retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_release_enabled_cells(this: *mut ObservableArrayReleaseEnabledCells) {
    #[cfg(target_os = "none")]
    if this.cast::<u8>().add(0x10).read_volatile() == 0 {
        return;
    }
    #[cfg(not(target_os = "none"))]
    if (*this.cast::<HostObservableArrayReleaseEnabledCells>()).enabled == 0 {
        return;
    }
    #[cfg(target_os = "none")]
    let count = this.cast::<u8>().add(0x04).cast::<i32>().read_volatile();
    #[cfg(not(target_os = "none"))]
    let count = (*this.cast::<HostObservableArrayReleaseEnabledCells>()).count;
    let mut index = 0;
    while index < count {
        #[cfg(target_os = "none")]
        let object = cell_at(this, index).read_volatile() as usize as *mut u8;
        #[cfg(not(target_os = "none"))]
        let object = cell_at(this, index).read();
        if !object.is_null() {
            destroy_cell_object(object);
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut DESTROYED: [usize; 4] = [0; 4];
    static mut DESTROY_COUNT: usize = 0;
    static mut CELLS: [*mut u8; 4] = [ptr::null_mut(); 4];

    unsafe extern "C" fn cell_at(_: *mut ObservableArrayReleaseEnabledCells, index: i32) -> *mut *mut u8 {
        INDEXES[INDEX_COUNT] = index;
        INDEX_COUNT += 1;
        CELLS.as_mut_ptr().add(index as usize)
    }

    unsafe extern "C" fn destroy(object: *mut u8) {
        DESTROYED[DESTROY_COUNT] = object as usize;
        DESTROY_COUNT += 1;
    }

    fn fixture(enabled: u8, count: i32, vtable: *const HostEnabledCellVtable) -> HostObservableArrayReleaseEnabledCells {
        HostObservableArrayReleaseEnabledCells { vtable, count, unresolved_0c_13: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_collections() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = HostEnabledCellVtable { unresolved_00_3c: [0; CELL_AT_SLOT], cell_at };
            INDEX_COUNT = 0;
            DESTROY_COUNT = 0;
            observable_array_release_enabled_cells((&mut fixture(0, 3, &vtable) as *mut HostObservableArrayReleaseEnabledCells).cast());
            observable_array_release_enabled_cells((&mut fixture(1, 0, &vtable) as *mut HostObservableArrayReleaseEnabledCells).cast());
            observable_array_release_enabled_cells((&mut fixture(1, -1, &vtable) as *mut HostObservableArrayReleaseEnabledCells).cast());
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(DESTROY_COUNT, 0);
        }
    }

    #[test]
    fn destroys_nonnull_cell_objects_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let collection_vtable = HostEnabledCellVtable { unresolved_00_3c: [0; CELL_AT_SLOT], cell_at };
            let object_vtable = HostEnabledCellObjectVtable { unresolved_00: 0, destroy };
            let mut first: *const HostEnabledCellObjectVtable = &object_vtable;
            let mut second: *const HostEnabledCellObjectVtable = &object_vtable;
            CELLS = [ptr::addr_of_mut!(first).cast(), ptr::null_mut(), ptr::addr_of_mut!(second).cast(), ptr::null_mut()];
            INDEX_COUNT = 0;
            DESTROY_COUNT = 0;
            observable_array_release_enabled_cells((&mut fixture(1, 3, &collection_vtable) as *mut HostObservableArrayReleaseEnabledCells).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DESTROYED[..DESTROY_COUNT], &[ptr::addr_of!(first) as usize, ptr::addr_of!(second) as usize]);
        }
    }
}
