//! `opaque_observable_array_auxiliary_destroy` — retailOS `FUN_083d0a20` at
//! load address `0x083d0a20`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes nineteen A32 words from `push {r4,r5,r6,lr}` at
//! `0x083d0a20` through `pop {r4,r5,r6,pc}` at `0x083d0a68`; `0x083d0a6c`
//! begins the next independently entered function, so the true size is **76
//! bytes**. The body has **three plain direct `bl` calls** —
//! [`indexed_virtual_value`] @ `0x083d69d8`,
//! [`owned_object_observable_array_destroy`] @ `0x081d2914`, and
//! [`operator_delete`] @ `0x082aad24` — and no predicated direct `bl` calls.
//!
//! ## Algorithm
//!
//! If byte `+0x10` is set, walk signed indices `[0, count)` and retrieve each
//! indexed virtual value. On the first nonzero value, destroy the containing
//! object through its known owned-object/observable-array destructor and
//! tag-2-delete it; otherwise leave it intact. Deliberate deviations: the
//! containing class has no recovered identity, so this port exposes only the
//! target-layout prefix and host seams for the two final operations.

use crate::app::indexed_virtual_value::indexed_virtual_value;
use crate::heap::veneers::operator_delete;

/// Prefix read by the auxiliary destructor.
#[repr(C)]
pub struct OpaqueObservableArrayAuxiliary {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

pub type OpaqueObservableArrayAuxiliaryDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;
pub type OpaqueObservableArrayAuxiliaryDelete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owned_object_observable_array_destroy(object: *mut u8) -> *mut u8 {
    panic!("install opaque observable-array auxiliary destroy host seam before destruction: {object:p}")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_operator_delete(object: *mut u8) {
    panic!("install opaque observable-array auxiliary delete host seam before deletion: {object:p}")
}

/// Host replacements for the known destructor and tag-2 delete reached after a
/// nonzero indexed value.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_OBSERVABLE_ARRAY_AUXILIARY_OPS: (
    OpaqueObservableArrayAuxiliaryDestroy,
    OpaqueObservableArrayAuxiliaryDelete,
) = (missing_owned_object_observable_array_destroy, missing_operator_delete);

#[inline(always)]
unsafe fn destroy_and_delete(object: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe {
        crate::cxx::owned_object_observable_array_destroy::owned_object_observable_array_destroy(object.cast());
        operator_delete(object);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_AUXILIARY_OPS));
        ops.0(object);
        ops.1(object);
    }
}

/// Destroys and tag-2-deletes `this` when an enabled indexed value is nonzero.
///
/// # Safety
///
/// `this` must name a readable target-layout prefix. When enabled, its vtable
/// `+0x40` method must accept `(this, index)`; a nonzero result requires `this`
/// to satisfy the owned-object/observable-array destructor and allocator.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_auxiliary_destroy(
    this: *mut OpaqueObservableArrayAuxiliary,
) {
    let base = this.cast::<u8>();
    if unsafe { base.add(0x10).read_volatile() } == 0 {
        return;
    }
    let count = unsafe { base.add(4).cast::<i32>().read_volatile() };
    let mut index = 0;
    while index < count {
        if unsafe { indexed_virtual_value(base, index) } != 0 {
            unsafe { destroy_and_delete(base) };
            return;
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::indexed_virtual_value::{INDEXED_VIRTUAL_VALUE_OPS, IndexedVirtualValueOps};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut VALUES: [u32; 4] = [0; 4];
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut CALLS: [usize; 2] = [0; 2];

    unsafe extern "C" fn value_at(_: *mut u8, index: i32) -> *const u32 {
        unsafe {
            INDEXES[INDEX_COUNT] = index;
            INDEX_COUNT += 1;
            VALUES.as_ptr().add(index as usize)
        }
    }

    unsafe extern "C" fn record_destroy(object: *mut u8) -> *mut u8 {
        unsafe { CALLS[0] = object as usize };
        object
    }

    unsafe extern "C" fn record_delete(object: *mut u8) {
        unsafe { CALLS[1] = object as usize };
    }

    fn fixture(enabled: u8, count: i32) -> OpaqueObservableArrayAuxiliary {
        OpaqueObservableArrayAuxiliary { vtable: 0, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_counts() {
        let _lock = LOCK.lock();
        unsafe {
            let old_values = core::ptr::read_volatile(core::ptr::addr_of!(INDEXED_VIRTUAL_VALUE_OPS));
            let old_ops = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_AUXILIARY_OPS));
            INDEXED_VIRTUAL_VALUE_OPS = IndexedVirtualValueOps { value_at };
            OPAQUE_OBSERVABLE_ARRAY_AUXILIARY_OPS = (record_destroy, record_delete);
            INDEX_COUNT = 0;
            CALLS = [0; 2];
            opaque_observable_array_auxiliary_destroy(&mut fixture(0, 3));
            opaque_observable_array_auxiliary_destroy(&mut fixture(1, 0));
            opaque_observable_array_auxiliary_destroy(&mut fixture(1, -1));
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(CALLS, [0; 2]);
            INDEXED_VIRTUAL_VALUE_OPS = old_values;
            OPAQUE_OBSERVABLE_ARRAY_AUXILIARY_OPS = old_ops;
        }
    }

    #[test]
    fn destroys_and_deletes_at_first_nonzero_value() {
        let _lock = LOCK.lock();
        unsafe {
            let old_values = core::ptr::read_volatile(core::ptr::addr_of!(INDEXED_VIRTUAL_VALUE_OPS));
            let old_ops = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_AUXILIARY_OPS));
            INDEXED_VIRTUAL_VALUE_OPS = IndexedVirtualValueOps { value_at };
            OPAQUE_OBSERVABLE_ARRAY_AUXILIARY_OPS = (record_destroy, record_delete);
            VALUES = [0, 0xfeed_beef, 1, 0];
            INDEX_COUNT = 0;
            CALLS = [0; 2];
            let mut object = fixture(1, 3);
            let pointer = core::ptr::addr_of_mut!(object).cast::<u8>() as usize;
            opaque_observable_array_auxiliary_destroy(&mut object);
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1]);
            assert_eq!(CALLS, [pointer, pointer]);
            INDEXED_VIRTUAL_VALUE_OPS = old_values;
            OPAQUE_OBSERVABLE_ARRAY_AUXILIARY_OPS = old_ops;
        }
    }
}
