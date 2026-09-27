//! `observable_array_release_elements` — retailOS `FUN_083d12d8` @
//! `0x083d12d8`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes from the initial `push {r4,r5,r6,lr}` at
//! `0x083d12d8` through `pop {r4,r5,r6,pc}` at `0x083d1320`: **72 bytes**.
//! `0x083d1324` is the next independently entered function. The body makes
//! one plain direct `bl` to `vtable_slot_0x40_result_word` (`FUN_083d6aa8`)
//! and one predicated indirect `blxne` through each non-NULL element's vtable
//! slot `+0x04`. Its two inbound plain `bl` calls are at `0x083d1370` and
//! `0x083d13a8`; there are no predicated direct callers.
//!
//! ## Algorithm
//!
//! A nonzero byte at `array + 0x10` enables a signed `[0, count)` walk. For
//! each index, the array vtable's `+0x40` accessor yields an element pointer;
//! non-NULL elements receive their vtable `+0x04` release call.
//!
//! Deliberate deviation: host fixtures use native-width vtable pointers.
//! The existing `vtable_slot_0x40_result_word` port models `FUN_083d6aa8`
//! without its live `r1` index argument, so target code reproduces this
//! caller's verified `+0x40` dispatch inline rather than reuse an ABI-inexact
//! seam; field and vtable accesses remain 32-bit.

/// ABI of the array vtable's indexed accessor at slot `+0x40`.
pub type ObservableArrayElementAt = unsafe extern "C" fn(*mut u8, i32) -> *mut *mut u8;

/// ABI of the element vtable release method at slot `+0x04`.
pub type ObservableArrayElementRelease = unsafe extern "C" fn(*mut u8);

const ELEMENT_AT_VTABLE_INDEX: usize = 0x40 / 4;
const ELEMENT_RELEASE_VTABLE_INDEX: usize = 0x04 / 4;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayVtable {
    pub unresolved_00_to_3c: [usize; ELEMENT_AT_VTABLE_INDEX],
    pub element_at: ObservableArrayElementAt,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArray {
    pub vtable: *const HostObservableArrayVtable,
    pub count: i32,
    pub unresolved_08_to_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayElementVtable {
    pub unresolved_00: usize,
    pub release: ObservableArrayElementRelease,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayElement {
    pub vtable: *const HostObservableArrayElementVtable,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn element_at(array: *mut u8, index: i32) -> *mut u8 {
    let vtable = unsafe { array.cast::<u32>().read_volatile() as usize as *const u32 };
    let accessor: ObservableArrayElementAt = unsafe {
        core::mem::transmute(vtable.add(ELEMENT_AT_VTABLE_INDEX).read_volatile() as usize)
    };
    unsafe { accessor(array, index).read_volatile() }
}

unsafe fn release_element(element: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let vtable = unsafe { element.cast::<u32>().read_volatile() as usize as *const u32 };
        let release: ObservableArrayElementRelease = unsafe {
            core::mem::transmute(vtable.add(ELEMENT_RELEASE_VTABLE_INDEX).read_volatile() as usize)
        };
        unsafe { release(element) };
    }

    #[cfg(not(target_os = "none"))]
    {
        let element = unsafe { &*element.cast::<HostObservableArrayElement>() };
        unsafe { ((*element.vtable).release)(element as *const _ as *mut u8) };
    }
}

/// Releases every non-NULL element returned by an enabled observable array.
///
/// # Safety
///
/// `array` must point to a readable retailOS array. When enabled, its vtable
/// slot `+0x40` and every returned non-NULL element's vtable slot `+0x04` must
/// be callable, matching the unchecked ARM loads and indirect calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn observable_array_release_elements(array: *mut u8) {
    #[cfg(target_os = "none")]
    {
        if unsafe { array.add(0x10).read_volatile() } == 0 {
            return;
        }
        let count = unsafe { array.add(0x04).cast::<i32>().read_volatile() };
        let mut index = 0;
        while index < count {
            let element = unsafe { element_at(array, index) };
            if !element.is_null() {
                unsafe { release_element(element) };
            }
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = unsafe { &*array.cast::<HostObservableArray>() };
        if host.enabled == 0 {
            return;
        }
        let mut index = 0;
        while index < host.count {
            let element = unsafe { ((*host.vtable).element_at)(array, index).read() };
            if !element.is_null() {
                unsafe { release_element(element) };
            }
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDICES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut RELEASED: [usize; 4] = [0; 4];
    static mut RELEASE_COUNT: usize = 0;
    static mut ELEMENTS: [*mut u8; 4] = [ptr::null_mut(); 4];

    unsafe extern "C" fn element_at(_array: *mut u8, index: i32) -> *mut *mut u8 {
        unsafe {
            INDICES[INDEX_COUNT] = index;
            INDEX_COUNT += 1;
            ELEMENTS.as_mut_ptr().add(index as usize)
        }
    }

    unsafe extern "C" fn record_release(element: *mut u8) {
        unsafe {
            RELEASED[RELEASE_COUNT] = element as usize;
            RELEASE_COUNT += 1;
        }
    }

    fn array(vtable: *const HostObservableArrayVtable, enabled: u8, count: i32) -> HostObservableArray {
        HostObservableArray { vtable, count, unresolved_08_to_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_null_elements() {
        let _lock = LOCK.lock();
        let vtable = HostObservableArrayVtable { unresolved_00_to_3c: [0; ELEMENT_AT_VTABLE_INDEX], element_at };
        let mut disabled = array(&vtable, 0, 2);
        let mut empty = array(&vtable, 1, 0);
        let mut negative = array(&vtable, 1, -1);
        let mut null_element = array(&vtable, 1, 1);
        unsafe {
            INDEX_COUNT = 0;
            RELEASE_COUNT = 0;
            ELEMENTS = [ptr::null_mut(); 4];
            observable_array_release_elements(ptr::addr_of_mut!(disabled).cast());
            observable_array_release_elements(ptr::addr_of_mut!(empty).cast());
            observable_array_release_elements(ptr::addr_of_mut!(negative).cast());
            observable_array_release_elements(ptr::addr_of_mut!(null_element).cast());
            assert_eq!(INDEX_COUNT, 1);
            assert_eq!(RELEASE_COUNT, 0);
        }
    }

    #[test]
    fn releases_nonnull_elements_in_index_order() {
        let _lock = LOCK.lock();
        let array_vtable = HostObservableArrayVtable { unresolved_00_to_3c: [0; ELEMENT_AT_VTABLE_INDEX], element_at };
        let element_vtable = HostObservableArrayElementVtable { unresolved_00: 0, release: record_release };
        let mut first = HostObservableArrayElement { vtable: &element_vtable };
        let mut second = HostObservableArrayElement { vtable: &element_vtable };
        let mut array = array(&array_vtable, 1, 3);
        unsafe {
            INDEX_COUNT = 0;
            RELEASE_COUNT = 0;
            ELEMENTS = [ptr::addr_of_mut!(first).cast(), ptr::null_mut(), ptr::addr_of_mut!(second).cast(), ptr::null_mut()];
            observable_array_release_elements(ptr::addr_of_mut!(array).cast());
            assert_eq!(&INDICES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&RELEASED[..RELEASE_COUNT], &[ptr::addr_of!(first) as usize, ptr::addr_of!(second) as usize]);
        }
    }
}
