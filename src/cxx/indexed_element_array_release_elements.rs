//! Indexed element array release.
//!
//! `indexed_element_array_release_elements` — original: `FUN_083cfef0` @
//! **0x083cfef0** (60 bytes; true extent `0x083cfef0..0x083cff2b`, with the
//! next real function beginning at `0x083cff30`). Raw ARM decoding finds two
//! incoming plain `bl` calls (at `0x083cff70` and `0x083cffa8`) and no
//! predicated incoming `bl` calls. The body makes two plain `bl` calls:
//! [`container_element_at_alias_6870`] and [`operator_delete`]; it has no
//! predicated direct calls.
//!
//! # Algorithm
//!
//! If `enabled` is nonzero, visit indices `[0, count)` and tag-2 delete every
//! element returned through vtable slot `+0x40`. `operator_delete` supplies the
//! NULL guard, so every index dispatch is retained even when its element is
//! NULL. Deliberate deviation: the host layout widens only the vtable pointer;
//! target reads retain the observed 32-bit offsets.

use crate::cxx::templates::container_element_at_alias_6870;
use crate::heap::veneers::operator_delete;

/// Host representation of the fields observed by this routine.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostIndexedElementArrayReleaseElements {
    pub vtable: *const usize,
    pub count: i32,
    pub unresolved_0c: u32,
    pub enabled: u8,
}

#[inline(always)]
unsafe fn element_count(array: *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    {
        array.add(4).cast::<i32>().read_volatile()
    }
    #[cfg(not(target_os = "none"))]
    {
        (*array.cast::<HostIndexedElementArrayReleaseElements>()).count
    }
}

#[inline(always)]
unsafe fn is_enabled(array: *mut u8) -> bool {
    #[cfg(target_os = "none")]
    {
        array.add(0x10).read_volatile() != 0
    }
    #[cfg(not(target_os = "none"))]
    {
        (*array.cast::<HostIndexedElementArrayReleaseElements>()).enabled != 0
    }
}

/// Releases all indexed elements when the array is enabled.
///
/// # Safety
///
/// `array` must identify the observed target layout, with a valid vtable slot
/// `+0x40` for every index below its signed `count`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_element_array_release_elements(array: *mut u8) {
    if !is_enabled(array) {
        return;
    }

    let count = element_count(array);
    let mut index = 0i32;
    while index < count {
        operator_delete(container_element_at_alias_6870(array, index as usize));
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SLOTS: [*mut u8; 3] = [ptr::null_mut(); 3];
    static mut INDICES: [usize; 3] = [usize::MAX; 3];
    static mut CALLS: usize = 0;

    unsafe extern "C" fn element_slot(_: *mut u8, index: usize) -> *mut *mut u8 {
        INDICES[CALLS] = index;
        CALLS += 1;
        SLOTS.as_mut_ptr().add(index)
    }

    fn fixture(count: i32, enabled: u8) -> (HostIndexedElementArrayReleaseElements, [usize; 17]) {
        (
            HostIndexedElementArrayReleaseElements {
                vtable: ptr::null(),
                count,
                unresolved_0c: 0,
                enabled,
            },
            [0; 17],
        )
    }

    #[test]
    fn disabled_or_nonpositive_count_does_not_dispatch() {
        let _guard = TEST_LOCK.lock();
        for (count, enabled) in [(3, 0), (0, 1), (-1, 1)] {
            let (mut array, mut vtable) = fixture(count, enabled);
            vtable[0x40 / 4] = element_slot as usize;
            array.vtable = vtable.as_ptr();
            unsafe {
                CALLS = 0;
                indexed_element_array_release_elements(ptr::addr_of_mut!(array).cast());
                assert_eq!(CALLS, 0);
            }
        }
    }

    #[test]
    fn enabled_array_dispatches_each_index_and_deletes_nonnull_elements() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _guard = TEST_LOCK.lock();
        let (mut array, mut vtable) = fixture(3, 1);
        vtable[0x40 / 4] = element_slot as usize;
        array.vtable = vtable.as_ptr();
        unsafe {
            CALLS = 0;
            INDICES = [usize::MAX; 3];
            SLOTS = [0x1111usize as *mut u8, ptr::null_mut(), 0x3333usize as *mut u8];
            indexed_element_array_release_elements(ptr::addr_of_mut!(array).cast());
            assert_eq!(CALLS, 3);
            assert_eq!(INDICES, [0, 1, 2]);
            assert_eq!(crate::heap::veneers::tests::free_log(), (2, 0x3333usize as *mut u8, 2));
        }
    }
}
