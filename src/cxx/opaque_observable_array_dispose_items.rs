//! `opaque_observable_array_dispose_items` — retailOS `FUN_083d1d3c` @
//! `0x083d1d3c`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` establishes an 80-byte body, `0x083d1d3c..0x083d1d8b`:
//! twenty ARM words from `push {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}`.
//! The next independently entered function begins at `0x083d1d90`. The body
//! contains three plain direct `bl` calls — the unresolved cell accessor at
//! `0x083d6c2c`, unresolved element-disposal stage at `0x083d1f04`, and
//! `operator_delete` at `0x082aad24` — and no predicated direct `bl` calls.
//!
//! ## Algorithm
//!
//! When enabled byte `+0x10` is nonzero, walk signed indices `[0, count)`.
//! Each cell accessor result supplies an optional object word. For each object,
//! call the element-disposal stage with `object + 8`, then delete its return
//! value minus 8.
//!
//! Deliberate deviation: both unidentified direct callees remain explicit
//! address-backed seams. Host fixtures replace them and the delete operation;
//! target builds call the verified fixed addresses and target heap veneer.

use crate::heap::veneers::operator_delete;

/// Firmware load address of the direct cell accessor with no established class
/// identity.
pub const OPAQUE_OBSERVABLE_ARRAY_CELL_AT_ADDRESS: usize = 0x083d_6c2c;

/// Firmware load address of the direct element-disposal stage with no
/// established class identity.
pub const OPAQUE_OBSERVABLE_ARRAY_ELEMENT_DISPOSE_ADDRESS: usize = 0x083d_1f04;

/// Direct cell accessor at `0x083d6c2c`.
pub type OpaqueObservableArrayCellAt = unsafe extern "C" fn(*mut OpaqueObservableArrayDisposeItems, i32) -> *mut u32;

/// Direct element-disposal stage at `0x083d1f04`.
pub type OpaqueObservableArrayElementDispose = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// Target-layout prefix used by the disposal walk.
#[repr(C)]
pub struct OpaqueObservableArrayDisposeItems {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_opaque_observable_array_cell_at(
    this: *mut OpaqueObservableArrayDisposeItems,
    index: i32,
) -> *mut u32 {
    let cell_at: OpaqueObservableArrayCellAt = unsafe { core::mem::transmute(OPAQUE_OBSERVABLE_ARRAY_CELL_AT_ADDRESS) };
    unsafe { cell_at(this, index) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_observable_array_cell_at(
    _this: *mut OpaqueObservableArrayDisposeItems,
    _index: i32,
) -> *mut u32 {
    panic!("opaque_observable_array_dispose_items requires unresolved FUN_083d6c2c")
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_OBSERVABLE_ARRAY_CELL_AT: OpaqueObservableArrayCellAt = missing_opaque_observable_array_cell_at;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_opaque_observable_array_element_dispose(object: *mut u8) -> *mut u8 {
    let dispose: OpaqueObservableArrayElementDispose = unsafe {
        core::mem::transmute(OPAQUE_OBSERVABLE_ARRAY_ELEMENT_DISPOSE_ADDRESS)
    };
    unsafe { dispose(object) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_observable_array_element_dispose(_object: *mut u8) -> *mut u8 {
    panic!("opaque_observable_array_dispose_items requires unresolved FUN_083d1f04")
}

#[cfg(target_os = "none")]
pub const DEFAULT_OPAQUE_OBSERVABLE_ARRAY_ELEMENT_DISPOSE: OpaqueObservableArrayElementDispose =
    firmware_opaque_observable_array_element_dispose;
#[cfg(not(target_os = "none"))]
pub const DEFAULT_OPAQUE_OBSERVABLE_ARRAY_ELEMENT_DISPOSE: OpaqueObservableArrayElementDispose =
    missing_opaque_observable_array_element_dispose;

/// Active direct-call boundary for the unidentified element-disposal stage.
pub static mut OPAQUE_OBSERVABLE_ARRAY_ELEMENT_DISPOSE: OpaqueObservableArrayElementDispose =
    DEFAULT_OPAQUE_OBSERVABLE_ARRAY_ELEMENT_DISPOSE;

#[cfg(not(target_os = "none"))]
pub type OpaqueObservableArrayDelete = unsafe extern "C" fn(*mut u8);
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_OBSERVABLE_ARRAY_DELETE: OpaqueObservableArrayDelete = operator_delete;

#[inline(always)]
unsafe fn dispose_cell(cell: *mut u32) {
    let object = unsafe { cell.read_volatile() } as usize as *mut u8;
    if object.is_null() {
        return;
    }

    #[cfg(target_os = "none")]
    let allocation = unsafe { firmware_opaque_observable_array_element_dispose(object.add(8)) };
    #[cfg(not(target_os = "none"))]
    let allocation = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_ELEMENT_DISPOSE))(object.add(8))
    };

    #[cfg(target_os = "none")]
    unsafe { operator_delete(allocation.sub(8)) };
    #[cfg(not(target_os = "none"))]
    unsafe { OPAQUE_OBSERVABLE_ARRAY_DELETE(allocation.sub(8)) };
}

/// Disposes and releases every populated item while enabled.
///
/// # Safety
///
/// `this` must address a readable target-layout collection. When enabled, its
/// cell accessor must accept `(this, index)` and return a readable cell. Each
/// non-NULL cell word must be accepted by the element-disposal stage at `+8`;
/// its result minus 8 must be accepted by `operator_delete`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_dispose_items(this: *mut OpaqueObservableArrayDisposeItems) {
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if unsafe { base.add(0x10).read_volatile() } == 0 {
            return;
        }
        let count = unsafe { base.add(4).cast::<i32>().read_volatile() };
        let mut index = 0;
        while index < count {
            unsafe { dispose_cell(firmware_opaque_observable_array_cell_at(this, index)) };
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostOpaqueObservableArrayDisposeItems>();
        if unsafe { (*host).enabled } == 0 {
            return;
        }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            let cell_at = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_CELL_AT)) };
            unsafe { dispose_cell(cell_at(this, index)) };
            index += 1;
        }
    }
}

/// Host-only representation preserving target field offsets.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOpaqueObservableArrayDisposeItems {
    pub target_vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut STAGED: [usize; 4] = [0; 4];
    static mut STAGE_COUNT: usize = 0;
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DELETE_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];

    unsafe extern "C" fn cell_at(_: *mut OpaqueObservableArrayDisposeItems, index: i32) -> *mut u32 {
        unsafe { INDEXES[INDEX_COUNT] = index; INDEX_COUNT += 1; CELLS.as_mut_ptr().add(index as usize) }
    }
    unsafe extern "C" fn record_dispose(object: *mut u8) -> *mut u8 {
        unsafe { STAGED[STAGE_COUNT] = object as usize; STAGE_COUNT += 1; object.sub(8) }
    }

    unsafe extern "C" fn record_delete(allocation: *mut u8) {
        unsafe { DELETED[DELETE_COUNT] = allocation as usize; DELETE_COUNT += 1 }
    }

    fn fixture(enabled: u8, count: i32) -> HostOpaqueObservableArrayDisposeItems {
        HostOpaqueObservableArrayDisposeItems { target_vtable: 0, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_empty_cells() {
        let _lock = LOCK.lock();
        unsafe {
            OPAQUE_OBSERVABLE_ARRAY_CELL_AT = cell_at;
            OPAQUE_OBSERVABLE_ARRAY_ELEMENT_DISPOSE = record_dispose;
            OPAQUE_OBSERVABLE_ARRAY_DELETE = record_delete;
            INDEX_COUNT = 0; STAGE_COUNT = 0; DELETE_COUNT = 0;
            opaque_observable_array_dispose_items((&mut fixture(0, 2) as *mut HostOpaqueObservableArrayDisposeItems).cast());
            opaque_observable_array_dispose_items((&mut fixture(1, 0) as *mut HostOpaqueObservableArrayDisposeItems).cast());
            opaque_observable_array_dispose_items((&mut fixture(1, -1) as *mut HostOpaqueObservableArrayDisposeItems).cast());
            CELLS = [0; 4];
            opaque_observable_array_dispose_items((&mut fixture(1, 1) as *mut HostOpaqueObservableArrayDisposeItems).cast());
            assert_eq!(INDEX_COUNT, 1);
            assert_eq!(STAGE_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn disposes_then_deletes_populated_cells_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            OPAQUE_OBSERVABLE_ARRAY_CELL_AT = cell_at;
            OPAQUE_OBSERVABLE_ARRAY_ELEMENT_DISPOSE = record_dispose;
            OPAQUE_OBSERVABLE_ARRAY_DELETE = record_delete;
            CELLS = [0x1008, 0, 0x3008, 0];
            INDEX_COUNT = 0; STAGE_COUNT = 0; DELETE_COUNT = 0;
            opaque_observable_array_dispose_items((&mut fixture(1, 3) as *mut HostOpaqueObservableArrayDisposeItems).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&STAGED[..STAGE_COUNT], &[0x1010, 0x3010]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0x3000]);
        }
    }
}
