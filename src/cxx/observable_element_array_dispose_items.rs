//! `observable_element_array_dispose_items` — retailOS `FUN_0839c1c8` @
//! `0x0839c1c8`.
//!
//! Raw ARM is exactly 76 bytes, `0x0839c1c8..0x0839c213`; the next
//! independently entered function begins at `0x0839c214`. Full-image A32
//! branch decoding finds two incoming plain `bl` calls (`0x0839c260` and
//! `0x0839c284`) and no predicated direct `bl` calls. The body has one plain
//! direct `bl`, to [`container_element_at_alias_5f44`], and one predicated
//! indirect `blxne` through each returned element's vtable slot `+0x04`.
//!
//! # Algorithm
//!
//! When the byte at target offset `+0x28` is nonzero, visit signed indices
//! `[0, count)` from target offset `+0x04`. Fetch each element through the
//! array vtable's `+0x40` element-slot method and invoke slot `+0x04` of every
//! non-NULL element. Deliberate deviation: host fixtures widen the array and
//! element vtable pointers while retaining the target field meanings.

use crate::cxx::templates::container_element_at_alias_5f44;

#[cfg(not(target_os = "none"))]
use crate::cxx::templates::ElementSlotFn;

/// Host representation of the fields observed by this routine.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableElementArray {
    pub vtable: *const ElementSlotFn,
    pub count: i32,
    pub unresolved_08_to_27: [u8; 0x20],
    pub enabled: u8,
}

type ElementDispose = unsafe extern "C" fn();

#[inline(always)]
unsafe fn element_count(array: *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    {
        array.add(4).cast::<i32>().read_volatile()
    }
    #[cfg(not(target_os = "none"))]
    {
        (*array.cast::<HostObservableElementArray>()).count
    }
}

#[inline(always)]
unsafe fn is_enabled(array: *mut u8) -> bool {
    #[cfg(target_os = "none")]
    {
        array.add(0x28).read_volatile() != 0
    }
    #[cfg(not(target_os = "none"))]
    {
        (*array.cast::<HostObservableElementArray>()).enabled != 0
    }
}

/// Disposes every occupied indexed element when the array is enabled.
///
/// # Safety
///
/// `array` must identify the observed target layout. Each non-NULL element
/// returned by its `+0x40` vtable method must have a callable vtable slot
/// `+0x04`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_element_array_dispose_items(array: *mut u8) {
    if !is_enabled(array) {
        return;
    }

    let count = element_count(array);
    let mut index = 0i32;
    while index < count {
        let element = container_element_at_alias_5f44(array, index as usize);
        if !element.is_null() {
            let vtable = (element as *const *const ElementDispose).read_volatile();
            vtable.add(1).read_volatile()();
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::templates::ElementSlotFn;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SLOTS: [*mut u8; 3] = [ptr::null_mut(); 3];
    static mut DISPOSED: [u32; 3] = [0; 3];
    static mut CALLS: u32 = 0;

    #[repr(C)]
    struct ElementVtable {
        unresolved_00: ElementDispose,
        dispose: ElementDispose,
    }

    #[repr(C)]
    struct Element {
        vtable: *const ElementVtable,
        id: usize,
    }

    #[repr(C)]
    struct ArrayVtable {
        unresolved_00_to_3c: [ElementSlotFn; 0x40 / 4],
        element_slot: ElementSlotFn,
    }

    unsafe extern "C" fn element_slot(_: *mut u8, index: usize) -> *mut *mut u8 {
        CALLS += 1;
        SLOTS.as_mut_ptr().add(index)
    }

    unsafe extern "C" fn ignore() {}

    unsafe extern "C" fn dispose_first() {
        DISPOSED[0] += 1;
    }

    unsafe extern "C" fn dispose_third() {
        DISPOSED[2] += 1;
    }

    fn fixture(count: i32, enabled: u8) -> (HostObservableElementArray, ArrayVtable) {
        (
            HostObservableElementArray {
                vtable: ptr::null(),
                count,
                unresolved_08_to_27: [0; 0x20],
                enabled,
            },
            ArrayVtable {
                unresolved_00_to_3c: [element_slot; 0x40 / 4],
                element_slot,
            },
        )
    }

    #[test]
    fn disabled_and_nonpositive_arrays_do_not_dispatch() {
        let _guard = TEST_LOCK.lock();
        for (count, enabled) in [(3, 0), (0, 1), (-1, 1)] {
            let (mut array, vtable) = fixture(count, enabled);
            array.vtable = (&vtable as *const ArrayVtable).cast::<ElementSlotFn>();
            unsafe {
                CALLS = 0;
                observable_element_array_dispose_items(ptr::addr_of_mut!(array).cast());
                assert_eq!(CALLS, 0);
            }
        }
    }

    #[test]
    fn enabled_array_disposes_each_non_null_element() {
        let _guard = TEST_LOCK.lock();
        let (mut array, vtable) = fixture(3, 1);
        let first_vtable = ElementVtable { unresolved_00: ignore, dispose: dispose_first };
        let third_vtable = ElementVtable { unresolved_00: ignore, dispose: dispose_third };
        let mut first = Element { vtable: &first_vtable, id: 0 };
        let mut third = Element { vtable: &third_vtable, id: 2 };
        array.vtable = (&vtable as *const ArrayVtable).cast::<ElementSlotFn>();
        unsafe {
            CALLS = 0;
            DISPOSED = [0; 3];
            SLOTS = [ptr::addr_of_mut!(first).cast(), ptr::null_mut(), ptr::addr_of_mut!(third).cast()];
            observable_element_array_dispose_items(ptr::addr_of_mut!(array).cast());
            assert_eq!(CALLS, 3);
            assert_eq!(DISPOSED, [1, 0, 1]);
        }
    }
}
