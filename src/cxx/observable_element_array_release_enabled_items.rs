//! `observable_element_array_release_enabled_items` — retailOS `FUN_0839c0ec`
//! @ `0x0839c0ec`.
//!
//! Raw `osos.dec` is exactly 88 bytes, `0x0839c0ec..0x0839c143`; the push at
//! `0x0839c144` begins the next real function. Full-image A32 branch decoding
//! finds two incoming plain `bl` calls (`0x0839c164` and `0x0839c1b0`) and no
//! predicated direct `bl` calls. The body has one unconditional indirect `blx`
//! through the array vtable slot `+0x40`, and one predicated indirect `blxne`
//! through every non-NULL element's vtable slot `+0x04`.
//!
//! # Algorithm
//!
//! When the byte at target offset `+0x28` is nonzero, visit signed indices
//! `[0, count)` from target offset `+0x04`. Fetch each element through the
//! array vtable's `+0x40` element-slot method and invoke slot `+0x04` of every
//! non-NULL element. Deliberate deviation: host fixtures widen the array and
//! element vtable pointers while retaining the target field meanings.

use crate::cxx::templates::ElementSlotFn;

/// Host representation of the fields observed by this routine.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableElementArrayReleaseEnabledItems {
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
        unsafe { array.add(4).cast::<i32>().read_volatile() }
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { (*array.cast::<HostObservableElementArrayReleaseEnabledItems>()).count }
    }
}

#[inline(always)]
unsafe fn is_enabled(array: *mut u8) -> bool {
    #[cfg(target_os = "none")]
    {
        unsafe { array.add(0x28).read_volatile() != 0 }
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { (*array.cast::<HostObservableElementArrayReleaseEnabledItems>()).enabled != 0 }
    }
}

/// Releases every occupied indexed element when the array is enabled.
///
/// # Safety
///
/// `array` must identify the observed target layout. Each non-NULL element
/// returned by its `+0x40` vtable method must have a callable vtable slot
/// `+0x04`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_element_array_release_enabled_items(array: *mut u8) {
    if unsafe { !is_enabled(array) } {
        return;
    }

    let count = unsafe { element_count(array) };
    let mut index = 0i32;
    while index < count {
        let vtable = unsafe { array.cast::<*const ElementSlotFn>().read_volatile() };
        let element_slot = unsafe { vtable.add(0x40 / 4).read_volatile() };
        let element = unsafe { element_slot(array, index as usize).read_volatile() };
        if !element.is_null() {
            let element_vtable = unsafe { element.cast::<*const ElementDispose>().read_volatile() };
            unsafe { element_vtable.add(1).read_volatile()() };
        }
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
    static mut DISPOSED: [u32; 3] = [0; 3];

    #[repr(C)]
    struct ElementVtable {
        unresolved_00: ElementDispose,
        dispose: ElementDispose,
    }

    #[repr(C)]
    struct Element {
        vtable: *const ElementVtable,
    }

    #[repr(C)]
    struct ArrayVtable {
        unresolved_00_to_3c: [ElementSlotFn; 0x40 / 4],
        element_slot: ElementSlotFn,
    }

    unsafe extern "C" fn element_slot(_: *mut u8, index: usize) -> *mut *mut u8 {
        unsafe {
            INDICES[CALLS] = index;
            CALLS += 1;
            SLOTS.as_mut_ptr().add(index)
        }
    }

    unsafe extern "C" fn ignore() {}

    unsafe extern "C" fn dispose_first() {
        unsafe { DISPOSED[0] += 1 };
    }

    unsafe extern "C" fn dispose_third() {
        unsafe { DISPOSED[2] += 1 };
    }

    fn fixture(count: i32, enabled: u8) -> (HostObservableElementArrayReleaseEnabledItems, ArrayVtable) {
        (
            HostObservableElementArrayReleaseEnabledItems {
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
                observable_element_array_release_enabled_items(ptr::addr_of_mut!(array).cast());
                assert_eq!(CALLS, 0);
            }
        }
    }

    #[test]
    fn enabled_array_disposes_each_non_null_element_in_index_order() {
        let _guard = TEST_LOCK.lock();
        let (mut array, vtable) = fixture(3, 1);
        let first_vtable = ElementVtable { unresolved_00: ignore, dispose: dispose_first };
        let third_vtable = ElementVtable { unresolved_00: ignore, dispose: dispose_third };
        let mut first = Element { vtable: &first_vtable };
        let mut third = Element { vtable: &third_vtable };
        array.vtable = (&vtable as *const ArrayVtable).cast::<ElementSlotFn>();
        unsafe {
            CALLS = 0;
            INDICES = [usize::MAX; 3];
            DISPOSED = [0; 3];
            SLOTS = [ptr::addr_of_mut!(first).cast(), ptr::null_mut(), ptr::addr_of_mut!(third).cast()];
            observable_element_array_release_enabled_items(ptr::addr_of_mut!(array).cast());
            assert_eq!(CALLS, 3);
            assert_eq!(INDICES, [0, 1, 2]);
            assert_eq!(DISPOSED, [1, 0, 1]);
        }
    }
}
