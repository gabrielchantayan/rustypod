//! Dispose the first live string held by an opaque observable array.
//!
//! `opaque_observable_array_dispose_first_string` — retailOS `FUN_083d028c` @
//! **0x083d028c**. Raw `osos.dec` establishes the true 76-byte extent:
//! nineteen A32 words from `push {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}`;
//! the next independently entered function starts at `0x083d02d8`. The body
//! has three plain direct `bl` calls — `container_element_at_alias_6908` @
//! `0x083d6908`, `string_object_destroy` @ `0x08277484`, and `operator_delete`
//! @ `0x082aad24` — and no predicated direct `bl` calls. Full-image A32 branch
//! decoding finds two inbound plain `bl` sites (`0x083d0324` and `0x083d035c`)
//! and no predicated inbound `bl` sites.
//!
//! # Algorithm
//!
//! If byte `+0x10` is set, walk signed indices `[0, count)`. For the first
//! non-null element retrieved through the array's `+0x40` vtable accessor,
//! destroy that element as a StringObject and tag-2-delete the same pointer.
//! Deliberate deviation: the owning class remains unidentified, so Rust models
//! only its accessed prefix; host builds inject the two direct lifecycle calls.

#[cfg(target_os = "none")]
use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::cxx::templates::container_element_at_alias_6908;
#[cfg(target_os = "none")]
use crate::heap::veneers::operator_delete;

#[cfg(target_os = "none")]
const COUNT_OFFSET: usize = 0x04;
#[cfg(target_os = "none")]
const ENABLED_OFFSET: usize = 0x10;
#[cfg(not(target_os = "none"))]
const COUNT_OFFSET: usize = core::mem::size_of::<*const u8>();
#[cfg(not(target_os = "none"))]
const ENABLED_OFFSET: usize = COUNT_OFFSET + core::mem::size_of::<i32>() + 8;

type StringDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;
type Delete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_destroy(_: *mut u8) -> *mut u8 {
    panic!("install opaque observable-array disposal host seam before destruction")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_operator_delete(_: *mut u8) {
    panic!("install opaque observable-array disposal host seam before deletion")
}

/// Host replacements for the direct destruction and delete calls.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_OBSERVABLE_ARRAY_DISPOSE_FIRST_STRING_OPS: (StringDestroy, Delete) =
    (missing_string_destroy, missing_operator_delete);

#[inline(always)]
unsafe fn destroy_and_delete(element: *mut u8) {
    #[cfg(target_os = "none")]
    {
        string_object_destroy(element.cast::<StringObject>());
        operator_delete(element);
    }
    #[cfg(not(target_os = "none"))]
    {
        let (destroy, delete) = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_DISPOSE_FIRST_STRING_OPS));
        destroy(element);
        delete(element);
    }
}

/// Disposes the first non-null indexed StringObject when `this` is enabled.
///
/// # Safety
///
/// On target, `this` must cover byte `+0x10` and its count word at `+0x04`.
/// Host fixtures widen the leading vtable pointer, placing the equivalent
/// count and enabled fields after that native-width field. When enabled, it
/// must have a target-compatible `+0x40` element accessor; every returned
/// non-null element must be a StringObject valid for destruction and deletion.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_dispose_first_string(this: *mut u8) {
    if this.add(ENABLED_OFFSET).read() == 0 {
        return;
    }
    let count = this.add(COUNT_OFFSET).cast::<i32>().read();
    let mut index = 0i32;
    while index < count {
        let element = container_element_at_alias_6908(this, index as usize);
        if !element.is_null() {
            destroy_and_delete(element);
            return;
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::templates::{ElementSlotFn, ELEMENT_SLOT_VTABLE_INDEX};
    use parking_lot::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ELEMENTS: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut ACCESSED: [usize; 3] = [usize::MAX; 3];
    static mut ACCESS_COUNT: usize = 0;
    static mut EVENTS: [u8; 2] = [0; 2];
    static mut EVENT_COUNT: usize = 0;
    static mut DESTROYED: *mut u8 = core::ptr::null_mut();
    static mut DELETED: *mut u8 = core::ptr::null_mut();

    #[repr(C)]
    struct ArrayFixture {
        vtable: *const ElementSlotFn,
        count: i32,
        padding: [u8; 8],
        enabled: u8,
    }

    unsafe extern "C" fn element_slot(_: *mut u8, index: usize) -> *mut *mut u8 {
        ACCESSED[ACCESS_COUNT] = index;
        ACCESS_COUNT += 1;
        core::ptr::addr_of_mut!(ELEMENTS[index])
    }

    unsafe extern "C" fn destroy(element: *mut u8) -> *mut u8 {
        EVENTS[EVENT_COUNT] = 1;
        EVENT_COUNT += 1;
        DESTROYED = element;
        element
    }

    unsafe extern "C" fn delete(element: *mut u8) {
        EVENTS[EVENT_COUNT] = 2;
        EVENT_COUNT += 1;
        DELETED = element;
    }

    unsafe fn reset() {
        ELEMENTS = [core::ptr::null_mut(); 3];
        ACCESSED = [usize::MAX; 3];
        ACCESS_COUNT = 0;
        EVENTS = [0; 2];
        EVENT_COUNT = 0;
        DESTROYED = core::ptr::null_mut();
        DELETED = core::ptr::null_mut();
        OPAQUE_OBSERVABLE_ARRAY_DISPOSE_FIRST_STRING_OPS = (destroy, delete);
    }

    #[test]
    fn disabled_array_does_not_access_or_dispose_elements() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            reset();
            let vtable = [element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut array = ArrayFixture { vtable: vtable.as_ptr(), count: 3, padding: [0; 8], enabled: 0 };
            opaque_observable_array_dispose_first_string((&mut array as *mut ArrayFixture).cast());
            assert_eq!(ACCESS_COUNT, 0);
            assert_eq!(EVENT_COUNT, 0);
        }
    }

    #[test]
    fn scans_to_first_live_element_then_destroys_before_deleting() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            reset();
            let mut live = 0u8;
            ELEMENTS[2] = core::ptr::addr_of_mut!(live);
            let vtable = [element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut array = ArrayFixture { vtable: vtable.as_ptr(), count: 3, padding: [0; 8], enabled: 1 };
            opaque_observable_array_dispose_first_string((&mut array as *mut ArrayFixture).cast());
            assert_eq!(&ACCESSED[..ACCESS_COUNT], &[0, 1, 2]);
            assert_eq!(DESTROYED, core::ptr::addr_of_mut!(live));
            assert_eq!(DELETED, core::ptr::addr_of_mut!(live));
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2]);
        }
    }

    #[test]
    fn nonpositive_count_never_dispatches() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            reset();
            let vtable = [element_slot as ElementSlotFn; ELEMENT_SLOT_VTABLE_INDEX + 1];
            let mut array = ArrayFixture { vtable: vtable.as_ptr(), count: -1, padding: [0; 8], enabled: 1 };
            opaque_observable_array_dispose_first_string((&mut array as *mut ArrayFixture).cast());
            assert_eq!(ACCESS_COUNT, 0);
            assert_eq!(EVENT_COUNT, 0);
        }
    }
}
