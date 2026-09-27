//! Observable-array element destruction.
//!
//! `observable_array_destroy_elements_083d13bc` — original: `FUN_083d13bc` @
//! **0x083d13bc** (76 bytes; true extent `0x083d13bc..0x083d1407`, with the
//! next real function beginning at `0x083d1408`). Raw ARM decoding finds two
//! incoming direct plain `bl` calls (at `0x083d144c` and `0x083d1464`) and no
//! predicated direct `bl` calls. The body makes three plain direct `bl` calls:
//! `FUN_083d6ad4`, [`string_object_destroy`], and [`operator_delete`]; it has
//! no predicated direct calls.
//!
//! # Algorithm
//!
//! When `enabled` is nonzero, visits signed indices `[0, count)`. It invokes
//! vtable slot `+0x40`, dereferences the returned element slot, then destroys
//! and tag-2 deletes each non-NULL string object. Deliberate deviations: the
//! target's direct accessor call at `0x083d6ad4` is expressed as its verified
//! vtable-slot operation; host fixtures widen their vtable pointer while
//! retaining the target's `count` and `enabled` field meanings. A target-only
//! `mov r12, r12` no-op retains this separately hooked BL target instead of
//! allowing LLVM to fold it into an identical port.

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
pub struct HostObservableArrayDestroyElements {
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
        (*array.cast::<HostObservableArrayDestroyElements>()).count
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
        (*array.cast::<HostObservableArrayDestroyElements>()).enabled != 0
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
pub unsafe extern "C" fn observable_array_destroy_elements_083d13bc(array: *mut u8) {
    #[cfg(target_os = "none")]
    core::arch::asm!("mov r12, r12", options(nomem, nostack, preserves_flags));
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

    fn fixture(count: i32, enabled: u8) -> (HostObservableArrayDestroyElements, HostElementVtable) {
        (
            HostObservableArrayDestroyElements {
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
            observable_array_destroy_elements_083d13bc(ptr::addr_of_mut!(array).cast::<u8>());
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
                observable_array_destroy_elements_083d13bc(ptr::addr_of_mut!(array).cast::<u8>());
                assert_eq!(CALLS, 0);
            }
        }
    }

    #[test]
    fn enabled_array_skips_null_and_destroys_occupied_elements() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _guard = TEST_LOCK.lock();
        let (mut array, vtable) = fixture(2, 1);
        array.vtable = (&vtable as *const HostElementVtable).cast::<usize>();
        let mut first = StringObject { vtable: 0x1111usize as *const StringObjectVtable, payload: ptr::null_mut() };
        unsafe {
            CALLS = 0;
            SLOTS = [ptr::addr_of_mut!(first).cast::<u8>(), ptr::null_mut()];
            observable_array_destroy_elements_083d13bc(ptr::addr_of_mut!(array).cast::<u8>());
            assert_eq!(CALLS, 2);
            assert!(ptr::eq(first.vtable, &STRING_OBJECT_VTABLE));
        }
    }
}
