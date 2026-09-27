//! `observable_array_assert_items_null` — retailOS `FUN_083d1954` at `0x083d1954`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes twenty A32 words from `0x083d1954` through
//! `0x083d19a0`; `0x083d19a4` begins the next real function, so the true size
//! is **80 bytes**. The body has no plain direct `bl`, one predicated direct
//! `blne` to `operator_delete` @ `0x082aad24`, and one unconditional indirect
//! `blx` through the array vtable slot `+0x40`. Its two inbound plain `bl`
//! sites are `0x083d19f4` and `0x083d1a2c`; neither is predicated.
//!
//! ## Algorithm
//!
//! If byte `+0x10` is nonzero, walk signed indices `[0, count)`, obtain each
//! element cell through vtable slot `+0x40`, and tag-2-delete its non-NULL
//! first word.
//!
//! Deliberate deviations: the accessor has no recovered identity, so host
//! builds provide a seam for it; target builds dispatch the recovered vtable
//! slot directly. Rust retains the firmware's conditional NULL guard rather
//! than calling the null-guarded delete veneer for NULL cells.

use crate::heap::veneers::operator_delete;

/// Target-layout prefix consumed by the cleanup loop.
#[repr(C)]
pub struct ObservableArrayAssertItemsNull {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

pub type ObservableArrayAssertItemsNullAt = unsafe extern "C" fn(*mut ObservableArrayAssertItemsNull, i32) -> *mut u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cell_at(_: *mut ObservableArrayAssertItemsNull, _: i32) -> *mut u32 {
    panic!("install observable-array assert-items-null host accessor before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_delete(cell: *mut u8) {
    unsafe { operator_delete(cell) };
}

/// Host replacements for the unresolved `+0x40` accessor and tag-2 delete.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS: (ObservableArrayAssertItemsNullAt, unsafe extern "C" fn(*mut u8)) =
    (missing_cell_at, host_delete);

#[inline(always)]
unsafe fn cell_at(this: *mut ObservableArrayAssertItemsNull, index: i32) -> *mut u32 {
    #[cfg(target_os = "none")]
    unsafe {
        let vtable = this.cast::<u32>().read_volatile() as usize as *const u32;
        let accessor: ObservableArrayAssertItemsNullAt = core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize);
        accessor(this, index)
    }
    #[cfg(not(target_os = "none"))]
    unsafe { (core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS)).0)(this, index) }
}

#[inline(always)]
unsafe fn delete_cell(cell: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { operator_delete(cell) };
    #[cfg(not(target_os = "none"))]
    unsafe { (core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS)).1)(cell) };
}

/// Deletes every non-null element obtained from an enabled observable array.
///
/// # Safety
///
/// `this` must point to a readable target-layout array. When enabled, vtable
/// slot `+0x40` must accept `(this, index)` and return a readable element cell.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_assert_items_null(this: *mut ObservableArrayAssertItemsNull) {
    let base = this.cast::<u8>();
    if unsafe { base.add(0x10).read_volatile() } == 0 {
        return;
    }
    let count = unsafe { base.add(4).cast::<i32>().read_volatile() };
    let mut index = 0;
    while index < count {
        let cell = unsafe { cell_at(this, index) };
        let element = unsafe { cell.read_volatile() as usize as *mut u8 };
        if !element.is_null() {
            unsafe { delete_cell(element) };
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut CELLS: [*mut u32; 4] = [core::ptr::null_mut(); 4];
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DELETE_COUNT: usize = 0;

    unsafe extern "C" fn cell_at(_: *mut ObservableArrayAssertItemsNull, index: i32) -> *mut u32 {
        unsafe { INDEXES[INDEX_COUNT] = index; INDEX_COUNT += 1; CELLS[index as usize] }
    }

    unsafe extern "C" fn record_delete(element: *mut u8) {
        unsafe { DELETED[DELETE_COUNT] = element as usize; DELETE_COUNT += 1; }
    }

    fn fixture(enabled: u8, count: i32) -> ObservableArrayAssertItemsNull {
        ObservableArrayAssertItemsNull { vtable: 0, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_counts() {
        let _lock = LOCK.lock();
        unsafe {
            let old = OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS;
            OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS = (cell_at, record_delete);
            INDEX_COUNT = 0; DELETE_COUNT = 0;
            observable_array_assert_items_null(&mut fixture(0, 2));
            observable_array_assert_items_null(&mut fixture(1, 0));
            observable_array_assert_items_null(&mut fixture(1, -1));
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
            OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS = old;
        }
    }

    #[test]
    fn deletes_only_nonnull_cells_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let old = OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS;
            let mut first = 0u32;
            let mut empty = 0u32;
            let mut third = 0u32;
            first = 0x1000; third = 0x3000;
            CELLS = [&mut first, &mut empty, &mut third, core::ptr::null_mut()];
            INDEX_COUNT = 0; DELETE_COUNT = 0;
            OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS = (cell_at, record_delete);
            observable_array_assert_items_null(&mut fixture(1, 3));
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0x3000]);
            OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS = old;
        }
    }
}
