//! Indexed element array destruction.
//!
//! `indexed_element_array_destroy` — original: `FUN_083cffbc` @
//! **0x083cffbc** (76 bytes; true extent `0x083cffbc..0x083d0007`, with the
//! next real function beginning at `0x083d0008`). Raw ARM decoding finds two
//! incoming direct plain `bl` calls (at `0x083d0054` and `0x083d007c`) and no
//! predicated direct `bl` calls. The body makes three plain direct `bl` calls:
//! `container_element_at_083d6818`-equivalent `FUN_083d689c`,
//! [`string_object_destroy`], and [`operator_delete`]; it has no predicated
//! direct calls.
//!
//! # Algorithm
//!
//! When `enabled` is nonzero, visits indices `[0, count)`. It obtains each
//! element through vtable slot `+0x40`; every non-NULL element is destroyed as
//! a string object and then tag-2 deleted. The accessor at 0x083d689c is the
//! same observed slot-`+0x40` load implemented by
//! [`container_element_at_083d6818`]. Deliberate deviation: the host fixture
//! widens its vtable pointer while preserving the target's `count` and
//! `enabled` field meanings.

use crate::cxx::container_element_at_083d6818::container_element_at_083d6818;
use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::heap::veneers::operator_delete;

/// Host representation of the fields observed by this routine.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostIndexedElementArray {
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
        (*array.cast::<HostIndexedElementArray>()).count
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
        (*array.cast::<HostIndexedElementArray>()).enabled != 0
    }
}

/// Destroys and deletes every occupied element when the array is enabled.
///
/// # Safety
///
/// `array` must identify the observed target layout, and each non-NULL element
/// returned by vtable slot `+0x40` must be a deletable [`StringObject`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_element_array_destroy(array: *mut u8) {
    if !is_enabled(array) {
        return;
    }

    let count = element_count(array);
    let mut index = 0i32;
    while index < count {
        let element = container_element_at_083d6818(array, index as u32);
        if !element.is_null() {
            operator_delete(string_object_destroy(element.cast::<StringObject>()).cast::<u8>());
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::container_element_at_083d6818::HostElementVtable;
    use crate::cxx::string_object::{StringObjectVtable, STRING_OBJECT_VTABLE};
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SLOTS: [*mut u8; 2] = [ptr::null_mut(); 2];
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn element_slot(_: *mut u8, index: u32) -> *mut *mut u8 {
        CALLS += 1;
        SLOTS.as_mut_ptr().add(index as usize)
    }

    fn fixture(count: i32, enabled: u8) -> (HostIndexedElementArray, HostElementVtable) {
        (
            HostIndexedElementArray {
                vtable: ptr::null(),
                count,
                unresolved_0c: 0,
                enabled,
            },
            HostElementVtable {
                unresolved_00_to_3c: [0; 0x40 / 4],
                element_slot,
            },
        )
    }

    #[test]
    fn disabled_array_does_not_dispatch() {
        let _guard = TEST_LOCK.lock();
        let (mut array, vtable) = fixture(2, 0);
        array.vtable = (&vtable as *const HostElementVtable).cast::<usize>();
        unsafe {
            CALLS = 0;
            indexed_element_array_destroy(ptr::addr_of_mut!(array).cast::<u8>());
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn enabled_empty_array_does_not_dispatch() {
        let _guard = TEST_LOCK.lock();
        let (mut array, vtable) = fixture(0, 1);
        array.vtable = (&vtable as *const HostElementVtable).cast::<usize>();
        unsafe {
            CALLS = 0;
            indexed_element_array_destroy(ptr::addr_of_mut!(array).cast::<u8>());
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn enabled_array_with_negative_count_does_not_dispatch() {
        let _guard = TEST_LOCK.lock();
        let (mut array, vtable) = fixture(-1, 1);
        array.vtable = (&vtable as *const HostElementVtable).cast::<usize>();
        unsafe {
            CALLS = 0;
            indexed_element_array_destroy(ptr::addr_of_mut!(array).cast::<u8>());
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn enabled_array_destroys_each_occupied_element() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _guard = TEST_LOCK.lock();
        let (mut array, vtable) = fixture(2, 1);
        array.vtable = (&vtable as *const HostElementVtable).cast::<usize>();
        let mut first = StringObject { vtable: 0x1111usize as *const StringObjectVtable, payload: ptr::null_mut() };
        let mut second = StringObject { vtable: 0x2222usize as *const StringObjectVtable, payload: ptr::null_mut() };
        unsafe {
            CALLS = 0;
            SLOTS = [ptr::addr_of_mut!(first).cast::<u8>(), ptr::addr_of_mut!(second).cast::<u8>()];
            indexed_element_array_destroy(ptr::addr_of_mut!(array).cast::<u8>());
            assert_eq!(CALLS, 2);
            assert!(ptr::eq(first.vtable, &STRING_OBJECT_VTABLE));
            assert!(ptr::eq(second.vtable, &STRING_OBJECT_VTABLE));
        }
    }
}
