//! Indexed string-element array destruction at a second retailOS entry point.
//!
//! `indexed_string_element_array_destroy_083d14a0` — retailOS `FUN_083d14a0`
//! at **0x083d14a0**. Raw `osos.dec` establishes the true 88-byte extent:
//! twenty-two A32 words from `0x083d14a0` through `0x083d14f4`; the push at
//! `0x083d14f8` starts the next independently entered function. Raw decoding
//! finds two plain direct `bl` calls, [`string_object_destroy`] at `0x08277484`
//! and [`operator_delete`] at `0x082aad24`, and no predicated direct calls.
//!
//! # Algorithm
//!
//! If `enabled` at `+0x10` is nonzero, visits signed indices `[0, count)`,
//! obtains each element through vtable slot `+0x40`, and destroys then tag-2
//! deletes every non-NULL string object. Deliberate deviations: host fixtures
//! widen the vtable pointer; target accesses retain the observed 32-bit offsets.
//! Target builds use an empty inline-assembly barrier to retain this distinct
//! retailOS BL target rather than allowing LLVM to fold it into its identical
//! sibling at `0x083cfe00`.

#[cfg(not(target_os = "none"))]
use crate::cxx::container_element_at_083d6818::{HostElementContainer, HostElementVtable};
use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::heap::veneers::operator_delete;

type ElementSlotMethod = unsafe extern "C" fn(*mut u8, u32) -> *mut *mut u8;

const VTABLE_ELEMENT_SLOT: usize = 0x40 / 4;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn element_at(array: *mut u8, index: u32) -> *mut u8 {
    let vtable = array.cast::<u32>().read_volatile() as usize as *const u32;
    let method: ElementSlotMethod = unsafe { core::mem::transmute(vtable.add(VTABLE_ELEMENT_SLOT).read_volatile() as usize) };
    unsafe { method(array, index).read_volatile() }
}

/// Host representation of the fields observed by this routine.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostIndexedStringElementArray083d14a0 {
    pub vtable: *const usize,
    pub count: i32,
    pub unresolved_0c: u32,
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn element_at(array: *mut u8, index: u32) -> *mut u8 {
    let host_array = unsafe { &*array.cast::<HostElementContainer>() };
    unsafe { ((*host_array.vtable).element_slot)(array, index).read_volatile() }
}

#[inline(always)]
unsafe fn element_count(array: *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    {
        unsafe { array.add(4).cast::<i32>().read_volatile() }
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { (*array.cast::<HostIndexedStringElementArray083d14a0>()).count }
    }
}

#[inline(always)]
unsafe fn is_enabled(array: *mut u8) -> bool {
    #[cfg(target_os = "none")]
    {
        unsafe { array.add(0x10).read_volatile() != 0 }
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { (*array.cast::<HostIndexedStringElementArray083d14a0>()).enabled != 0 }
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
pub unsafe extern "C" fn indexed_string_element_array_destroy_083d14a0(array: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe {
        core::arch::asm!("", options(nomem, nostack, preserves_flags));
    }
    if unsafe { !is_enabled(array) } {
        return;
    }

    let count = unsafe { element_count(array) };
    let mut index = 0i32;
    while index < count {
        let element = unsafe { element_at(array, index as u32) };
        if !element.is_null() {
            unsafe { operator_delete(string_object_destroy(element.cast::<StringObject>()).cast::<u8>()) };
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{StringObjectVtable, STRING_OBJECT_VTABLE};
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SLOTS: [*mut u8; 2] = [ptr::null_mut(); 2];
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn element_slot(_: *mut u8, index: u32) -> *mut *mut u8 {
        unsafe {
            CALLS += 1;
            SLOTS.as_mut_ptr().add(index as usize)
        }
    }

    fn fixture(count: i32, enabled: u8) -> (HostIndexedStringElementArray083d14a0, HostElementVtable) {
        (
            HostIndexedStringElementArray083d14a0 {
                vtable: ptr::null(), count, unresolved_0c: 0, enabled,
            },
            HostElementVtable { unresolved_00_to_3c: [0; 0x40 / 4], element_slot },
        )
    }

    #[test]
    fn disabled_or_nonpositive_array_does_not_dispatch() {
        let _guard = TEST_LOCK.lock();
        for (count, enabled) in [(2, 0), (0, 1), (-1, 1)] {
            let (mut array, vtable) = fixture(count, enabled);
            array.vtable = (&vtable as *const HostElementVtable).cast::<usize>();
            unsafe {
                CALLS = 0;
                indexed_string_element_array_destroy_083d14a0(ptr::addr_of_mut!(array).cast());
                assert_eq!(CALLS, 0);
            }
        }
    }

    #[test]
    fn enabled_array_destroys_and_deletes_only_occupied_elements() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _guard = TEST_LOCK.lock();
        let (mut array, vtable) = fixture(2, 1);
        array.vtable = (&vtable as *const HostElementVtable).cast::<usize>();
        let mut string = StringObject { vtable: 0x1111usize as *const StringObjectVtable, payload: ptr::null_mut() };
        unsafe {
            CALLS = 0;
            SLOTS = [ptr::addr_of_mut!(string).cast(), ptr::null_mut()];
            indexed_string_element_array_destroy_083d14a0(ptr::addr_of_mut!(array).cast());
            assert_eq!(CALLS, 2);
            assert!(ptr::eq(string.vtable, &STRING_OBJECT_VTABLE));
        }
    }
}
