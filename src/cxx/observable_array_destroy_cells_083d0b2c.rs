//! `observable_array_destroy_cells_083d0b2c` — retailOS `FUN_083d0b2c` @ `0x083d0b2c`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes twenty-two A32 words from `0x083d0b2c` through
//! `0x083d0b80`; `push {r4,r5,r6,lr}` at `0x083d0b84` begins the next real
//! function, so the true size is **88 bytes**. The body has two unconditional
//! plain direct `bl` calls, to `FUN_0820760c` @ `0x0820760c` and
//! [`operator_delete`] @ `0x082aad24`, no predicated direct `bl`, and one
//! unconditional virtual `blx` through vtable slot `+0x40`. Raw callers at
//! `0x083d0bdc` and `0x083d0c7c` are plain direct `bl`; there are no predicated
//! direct caller calls.
//!
//! ## Algorithm
//!
//! If the enable byte at `+0x10` is nonzero, walk signed indices `[0, count)`.
//! Each vtable-slot-`+0x40` accessor result names a cell whose first word is an
//! allocation body. A nonzero body is first destroyed by `FUN_0820760c`, then
//! passed to tag-2 [`operator_delete`].
//!
//! Deliberate deviations: `FUN_0820760c` remains unported, so target builds
//! call its verified retail address while host tests use a recording seam.
//! Host fixtures also widen the vtable pointer and replace `operator_delete`
//! with a recording seam because native pointers do not fit target u32 words.

use crate::heap::veneers::operator_delete;

/// Target vtable slot `+0x40`.
pub type ObservableArrayCellAt083d0b2c = unsafe extern "C" fn(*mut ObservableArrayDestroyCells083d0b2c, i32) -> *mut u32;

/// ABI of the unported cell-object destructor `FUN_0820760c`.
pub type ObservableArrayCellDestroy083d0b2c = unsafe extern "C" fn(*mut u8);

/// Host representation of the observed target vtable slot.
#[repr(C)]
pub struct ObservableArrayDestroyCells083d0b2cVtable {
    pub unresolved_00_3c: [usize; 16],
    pub cell_at: ObservableArrayCellAt083d0b2c,
}

/// Target-layout prefix consumed by the retail destruction loop.
#[repr(C)]
pub struct ObservableArrayDestroyCells083d0b2c {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cell_destroy(_: *mut u8) {
    panic!("FUN_0820760c is unported")
}

/// Host seam for the unported cell-object destructor.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_CELL_DESTROY_083D0B2C: ObservableArrayCellDestroy083d0b2c = missing_cell_destroy;

#[cfg(not(target_os = "none"))]
pub type ObservableArrayCellDelete083d0b2c = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_delete(cell_body: *mut u8) {
    unsafe { operator_delete(cell_body) };
}

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_CELL_DELETE_083D0B2C: ObservableArrayCellDelete083d0b2c = host_delete;

#[inline(always)]
unsafe fn destroy_cell(cell_body: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let destroy: ObservableArrayCellDestroy083d0b2c = unsafe { core::mem::transmute(0x0820_760cusize) };
        unsafe { destroy(cell_body) };
        unsafe { operator_delete(cell_body) };
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { OBSERVABLE_ARRAY_CELL_DESTROY_083D0B2C(cell_body) };
        unsafe { OBSERVABLE_ARRAY_CELL_DELETE_083D0B2C(cell_body) };
    }
}

/// Destroys and frees non-null cell bodies supplied by the indexed virtual accessor.
///
/// # Safety
///
/// `this` must point to a readable target-layout collection. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_destroy_cells_083d0b2c(this: *mut ObservableArrayDestroyCells083d0b2c) {
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if unsafe { base.add(0x10).read_volatile() } == 0 {
            return;
        }
        let count = unsafe { base.add(0x04).cast::<i32>().read_volatile() };
        let vtable = unsafe { base.cast::<u32>().read_volatile() } as usize as *const u32;
        let cell_at: ObservableArrayCellAt083d0b2c = unsafe { core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize) };
        let mut index = 0;
        while index < count {
            let cell_body = unsafe { cell_at(this, index).read_volatile() } as usize as *mut u8;
            if !cell_body.is_null() {
                unsafe { destroy_cell(cell_body) };
            }
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostObservableArrayDestroyCells083d0b2c>();
        if unsafe { (*host).enabled } == 0 {
            return;
        }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            let cell_body = unsafe { ((*(*host).vtable).cell_at)(this, index).read_volatile() } as usize as *mut u8;
            if !cell_body.is_null() {
                unsafe { destroy_cell(cell_body) };
            }
            index += 1;
        }
    }
}

/// Host-only replacement of the target vtable word with a native pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayDestroyCells083d0b2c {
    pub vtable: *const ObservableArrayDestroyCells083d0b2cVtable,
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
    static mut DESTROYED: [usize; 4] = [0; 4];
    static mut DESTROY_COUNT: usize = 0;
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DELETE_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];

    unsafe extern "C" fn cell_at(_: *mut ObservableArrayDestroyCells083d0b2c, index: i32) -> *mut u32 {
        unsafe { INDEXES[INDEX_COUNT] = index; INDEX_COUNT += 1; CELLS.as_mut_ptr().add(index as usize) }
    }

    unsafe extern "C" fn record_destroy(cell_body: *mut u8) {
        unsafe { DESTROYED[DESTROY_COUNT] = cell_body as usize; DESTROY_COUNT += 1; }
    }

    unsafe extern "C" fn record_delete(cell_body: *mut u8) {
        unsafe { DELETED[DELETE_COUNT] = cell_body as usize; DELETE_COUNT += 1; }
    }

    fn fixture(enabled: u8, count: i32, vtable: *const ObservableArrayDestroyCells083d0b2cVtable) -> HostObservableArrayDestroyCells083d0b2c {
        HostObservableArrayDestroyCells083d0b2c { vtable, count, unresolved_0c_13: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_counts() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayDestroyCells083d0b2cVtable { unresolved_00_3c: [0; 16], cell_at };
            INDEX_COUNT = 0; DESTROY_COUNT = 0; DELETE_COUNT = 0;
            OBSERVABLE_ARRAY_CELL_DESTROY_083D0B2C = record_destroy;
            OBSERVABLE_ARRAY_CELL_DELETE_083D0B2C = record_delete;
            observable_array_destroy_cells_083d0b2c((&mut fixture(0, 2, &vtable) as *mut HostObservableArrayDestroyCells083d0b2c).cast());
            observable_array_destroy_cells_083d0b2c((&mut fixture(1, 0, &vtable) as *mut HostObservableArrayDestroyCells083d0b2c).cast());
            observable_array_destroy_cells_083d0b2c((&mut fixture(1, -1, &vtable) as *mut HostObservableArrayDestroyCells083d0b2c).cast());
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(DESTROY_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn destroys_and_deletes_nonnull_bodies_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayDestroyCells083d0b2cVtable { unresolved_00_3c: [0; 16], cell_at };
            CELLS = [0x1000, 0, 0x3000, 0]; INDEX_COUNT = 0; DESTROY_COUNT = 0; DELETE_COUNT = 0;
            OBSERVABLE_ARRAY_CELL_DESTROY_083D0B2C = record_destroy;
            OBSERVABLE_ARRAY_CELL_DELETE_083D0B2C = record_delete;
            observable_array_destroy_cells_083d0b2c((&mut fixture(1, 3, &vtable) as *mut HostObservableArrayDestroyCells083d0b2c).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DESTROYED[..DESTROY_COUNT], &[0x1000, 0x3000]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0x3000]);
        }
    }
}
