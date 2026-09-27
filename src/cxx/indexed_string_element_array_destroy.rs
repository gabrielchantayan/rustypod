//! Indexed string-element array destruction.
//!
//! `indexed_string_element_array_destroy` — original: `FUN_083cfe00` @
//! **0x083cfe00** (88 bytes; true extent `0x083cfe00..0x083cfe57`, with the
//! next independently entered function beginning at `0x083cfe58`). Raw ARM
//! decoding finds two incoming direct plain `bl` calls (at `0x083cfea4` and
//! `0x083cfedc`) and no predicated direct `bl` calls. The body makes two plain
//! direct `bl` calls: [`string_object_destroy`] and [`operator_delete`]; it has
//! no predicated direct calls. Its vtable-slot `+0x40` invocation is an indirect
//! `blx`, whose runtime target has no recovered static identity.
//!
//! # Algorithm
//!
//! When `enabled` is nonzero, visits indices `[0, count)`. It obtains each
//! element through vtable slot `+0x40`; every non-NULL element is destroyed as
//! a string object and then tag-2 deleted. Deliberate deviation: the host
//! fixture widens its vtable pointer while preserving the target's `count` and
//! `enabled` field meanings; target builds retain the observed 32-bit offsets.

#[cfg(not(target_os = "none"))]
use crate::cxx::container_element_at_083d6818::HostElementContainer;
use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::heap::veneers::operator_delete;

type ElementSlotMethod = unsafe extern "C" fn(*mut u8, u32) -> *mut *mut u8;

const VTABLE_ELEMENT_SLOT: usize = 0x40 / 4;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn element_at(array: *mut u8, index: u32) -> *mut u8 {
    let vtable = array.cast::<u32>().read_volatile() as usize as *const u32;
    let method: ElementSlotMethod = core::mem::transmute(
        vtable.add(VTABLE_ELEMENT_SLOT).read_volatile() as usize,
    );
    method(array, index).read_volatile()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn element_at(array: *mut u8, index: u32) -> *mut u8 {
    let host_array = &*array.cast::<HostElementContainer>();
    ((*host_array.vtable).element_slot)(array, index).read_volatile()
}

/// Host representation of the fields observed by this routine.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostIndexedStringElementArray {
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
        (*array.cast::<HostIndexedStringElementArray>()).count
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
        (*array.cast::<HostIndexedStringElementArray>()).enabled != 0
    }
}

/// Destroys and deletes every occupied string element when the array is enabled.
///
/// # Safety
///
/// `array` must identify the observed target layout, and each non-NULL element
/// returned by vtable slot `+0x40` must be a deletable [`StringObject`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_string_element_array_destroy(array: *mut u8) {
    if !is_enabled(array) {
        return;
    }

    let count = element_count(array);
    let mut index = 0i32;
    while index < count {
        let element = element_at(array, index as u32);
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

    fn fixture(count: i32, enabled: u8) -> (HostIndexedStringElementArray, HostElementVtable) {
        (
            HostIndexedStringElementArray {
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
            indexed_string_element_array_destroy(ptr::addr_of_mut!(array).cast::<u8>());
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn nonpositive_count_does_not_dispatch() {
        let _guard = TEST_LOCK.lock();
        for count in [0, -1] {
            let (mut array, vtable) = fixture(count, 1);
            array.vtable = (&vtable as *const HostElementVtable).cast::<usize>();
            unsafe {
                CALLS = 0;
                indexed_string_element_array_destroy(ptr::addr_of_mut!(array).cast::<u8>());
                assert_eq!(CALLS, 0);
            }
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
            indexed_string_element_array_destroy(ptr::addr_of_mut!(array).cast::<u8>());
            assert_eq!(CALLS, 2);
            assert!(ptr::eq(first.vtable, &STRING_OBJECT_VTABLE));
            assert!(ptr::eq(second.vtable, &STRING_OBJECT_VTABLE));
        }
    }
}
