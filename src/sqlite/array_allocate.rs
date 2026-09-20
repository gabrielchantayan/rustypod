//! SQLite dynamic-array growth helper.
//!
//! `array_allocate` — original: `FUN_0836f4ac` @ **0x0836f4ac** (124 bytes,
//! `0x0836f4ac..0x0836f528`; 3 inbound `bl` call sites, all unconditional,
//! decoded from every aligned ARM `B`/`BL` word in `osos.dec).
//!
//! SQLite 3.5.x's private `sqlite3ArrayAllocate`: append one zeroed element to
//! a counted array, growing its allocation to `2 * capacity + initial_capacity`
//! when full. The two body calls are `db_realloc` and the IRAM `memzero` veneer.
//! On allocation failure it preserves the old array pointer and counts, writes
//! `-1` to `index`, and returns the old pointer. Deliberate deviations: none.

use super::mem::db_realloc;
use crate::libc::iram_veneers::iram_memzero_veneer;

type Reallocate = unsafe extern "C" fn(*mut u8, *mut u8, i32) -> *mut u8;

/// Appends a zeroed `element_size`-byte element to `array` and returns its
/// possibly reallocated base. All pointer arguments must be valid as required
/// by the retail helper; no NULL or overflow checks are added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn array_allocate(
    db: *mut u8,
    mut array: *mut u8,
    element_size: i32,
    initial_capacity: i32,
    entry_count: *mut i32,
    allocation_count: *mut i32,
    index: *mut i32,
) -> *mut u8 {
    unsafe { array_allocate_with(db, array, element_size, initial_capacity, entry_count, allocation_count, index, db_realloc) }
}

unsafe fn array_allocate_with(
    db: *mut u8,
    mut array: *mut u8,
    element_size: i32,
    initial_capacity: i32,
    entry_count: *mut i32,
    allocation_count: *mut i32,
    index: *mut i32,
    reallocate: Reallocate,
) -> *mut u8 {
    unsafe {
        let entry = *entry_count;
        if entry >= *allocation_count {
            let capacity = allocation_count.read().wrapping_mul(2).wrapping_add(initial_capacity);
            let grown = reallocate(db, array, element_size.wrapping_mul(capacity));
            if grown.is_null() {
                index.write(-1);
                return array;
            }
            array = grown;
            allocation_count.write(capacity);
        }
        iram_memzero_veneer(array.add(element_size.wrapping_mul(entry) as usize), element_size as usize);
        index.write(entry);
        entry_count.write(entry.wrapping_add(1));
        array
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut REALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut REALLOC_BYTES: i32 = 0;

    unsafe extern "C" fn record_realloc(_db: *mut u8, _array: *mut u8, bytes: i32) -> *mut u8 {
        unsafe {
            REALLOC_BYTES = bytes;
            REALLOC_RESULT
        }
    }

    #[test]
    fn appends_without_growing_and_zeroes_only_new_element() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut bytes = [0xa5u8; 12];
        let mut entries = 1;
        let mut capacity = 3;
        let mut index = -2;
        let array = unsafe {
            array_allocate_with(core::ptr::null_mut(), bytes.as_mut_ptr(), 4, 2, &mut entries, &mut capacity, &mut index, record_realloc)
        };
        assert_eq!(array, bytes.as_mut_ptr());
        assert_eq!(bytes, [0xa5, 0xa5, 0xa5, 0xa5, 0, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5]);
        assert_eq!((entries, capacity, index), (2, 3, 1));
    }

    #[test]
    fn grows_by_doubling_plus_initial_capacity() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut old = [0xa5u8; 4];
        let mut grown = [0xa5u8; 16];
        let mut entries = 2;
        let mut capacity = 2;
        let mut index = -2;
        unsafe { REALLOC_RESULT = grown.as_mut_ptr(); }
        let array = unsafe {
            array_allocate_with(core::ptr::null_mut(), old.as_mut_ptr(), 4, 2, &mut entries, &mut capacity, &mut index, record_realloc)
        };
        assert_eq!(array, grown.as_mut_ptr());
        assert_eq!(unsafe { REALLOC_BYTES }, 24);
        assert_eq!(&grown[8..12], &[0, 0, 0, 0]);
        assert_eq!((entries, capacity, index), (3, 6, 2));
    }

    #[test]
    fn failed_growth_preserves_array_and_counts() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut bytes = [0xa5u8; 8];
        let mut entries = 2;
        let mut capacity = 2;
        let mut index = 7;
        unsafe { REALLOC_RESULT = core::ptr::null_mut(); }
        let array = unsafe {
            array_allocate_with(core::ptr::null_mut(), bytes.as_mut_ptr(), 4, 3, &mut entries, &mut capacity, &mut index, record_realloc)
        };
        assert_eq!(array, bytes.as_mut_ptr());
        assert_eq!(bytes, [0xa5; 8]);
        assert_eq!((entries, capacity, index), (2, 2, -1));
    }
}
