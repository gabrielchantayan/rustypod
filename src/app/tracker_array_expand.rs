//! `tracker_array_expand` — original: `FUN_083d55b8` @ **0x083d55b8**
//! (120 bytes exactly; true extent `0x083d55b8..0x083d5630`).
//!
//! Raw `osos.dec` establishes three unconditional `bl` calls: `realloc` @
//! 0x0802edec, the `memzero_aligned` IRAM veneer @ 0x08037db8, and
//! `tracker_event_log_noop` @ 0x083d551c; there are no predicated calls.
//! It multiplies the array's growth factor (+0x10) by its allocated length
//! (+0x04), reallocates storage (+0x00) to that many words, clears the new
//! tail, and commits the allocation length only after a successful reallocation.
//! The diagnostic call is retained even though the verified callee is a no-op.
//! No deliberate behavioral deviations.

use core::ffi::c_void;

const STORAGE: usize = 0;
const ALLOCATED: usize = 1;
const GROWTH_FACTOR: usize = 4;

#[inline(never)]
unsafe fn expand_with_realloc(
    array: *mut u32,
    reallocate: unsafe extern "C" fn(*mut u8, usize) -> *mut u8,
) {
    let allocated = *array.add(ALLOCATED);
    let expanded = (*array.add(GROWTH_FACTOR)).wrapping_mul(allocated);
    let storage = reallocate((*array.add(STORAGE)) as *mut u8, expanded.wrapping_mul(4) as usize) as *mut u32;
    *array.add(STORAGE) = storage as u32;

    if !storage.is_null() {
        let mut index = allocated;
        while index < expanded {
            core::ptr::write_volatile(storage.add(index as usize), 0);
            index = index.wrapping_add(1);
        }
        *array.add(ALLOCATED) = expanded;
    }
}

/// Grows a tracker array by its configured multiplicative growth factor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tracker_array_expand(array: *mut u32) {
    expand_with_realloc(array, crate::runtime::malloc_rt::realloc);
    let _ = crate::app::tracker_event_log_noop::tracker_event_log_noop(array.cast::<c_void>());
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, try_map_u32_slab};
    use core::slice;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static BACKING: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TRACKER_ARRAY_EXPAND, 0x1000).map(|pointer| pointer as usize)
    });
    static mut REALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut REALLOC_ARGUMENTS: (*mut u8, usize) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn mock_realloc(ptr: *mut u8, size: usize) -> *mut u8 {
        REALLOC_ARGUMENTS = (ptr, size);
        REALLOC_RESULT
    }

    #[test]
    fn expands_and_clears_only_the_new_words() {
        let _lock = TEST_LOCK.lock();
        let Some(storage) = *BACKING else { return };
        let storage = storage as *mut u32;
        let storage = unsafe { slice::from_raw_parts_mut(storage, 6) };
        storage.copy_from_slice(&[0x1122_3344u32, 0x5566_7788, 0xdead_beef, 0xdead_beef, 0xdead_beef, 0xdead_beef]);
        let mut array = [storage.as_mut_ptr() as u32, 2, 0, 0, 3, 0];
        unsafe {
            REALLOC_RESULT = storage.as_mut_ptr().cast();
            expand_with_realloc(array.as_mut_ptr(), mock_realloc);
        }

        assert_eq!(unsafe { REALLOC_ARGUMENTS }, (storage.as_mut_ptr().cast(), 24));
        assert_eq!(array[STORAGE], storage.as_mut_ptr() as u32);
        assert_eq!(array[ALLOCATED], 6);
        assert_eq!(storage, [0x1122_3344, 0x5566_7788, 0, 0, 0, 0]);
    }

    #[test]
    fn failed_reallocation_nulls_storage_without_committing_capacity() {
        let _lock = TEST_LOCK.lock();
        let Some(storage) = *BACKING else { return };
        let storage = storage as *mut u32;
        let storage = unsafe { slice::from_raw_parts_mut(storage, 2) };
        storage.copy_from_slice(&[0x1122_3344, 0x5566_7788]);
        let mut array = [storage.as_mut_ptr() as u32, 2, 0, 0, 3, 0];
        unsafe {
            REALLOC_RESULT = core::ptr::null_mut();
            expand_with_realloc(array.as_mut_ptr(), mock_realloc);
        }

        assert_eq!(unsafe { REALLOC_ARGUMENTS }, (storage.as_mut_ptr().cast(), 24));
        assert_eq!(array[STORAGE], 0);
        assert_eq!(array[ALLOCATED], 2);
        assert_eq!(storage, [0x1122_3344, 0x5566_7788]);
    }
}
