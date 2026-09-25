//! Replaces an owned `StringObject` pointer.
//!
//! `owned_string_object_replace` — original: `FUN_083e757c` at load address
//! `0x083e757c` (48 bytes). Raw `osos.dec` establishes twelve ARM words from
//! `push {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}` at `0x083e75a8`; the next
//! independently entered function starts with `push {r4,lr}` at `0x083e75ac`.
//! Full-image ARM branch decoding finds two inbound direct `bl` call sites,
//! both plain unconditional (`0x08186f68` and `0x081baa70`) and no predicated
//! `bl` calls. The body has two plain unconditional direct `bl` calls:
//! [`string_object_opaque_base_destroy`] @ `0x08291fb4` and
//! [`operator_delete`] @ `0x082aad24`.
//!
//! # Algorithm
//!
//! If `slot` already holds `replacement`, return. Otherwise destroy and delete
//! a non-NULL old StringObject, then store `replacement`.
//!
//! # Deliberate deviation
//!
//! The target slot is a 32-bit pointer word; the `repr(C)` Rust pointer slot is
//! native-width so host tests can use valid pointers. Both target callees are
//! already ported and are called directly; their host implementations retain
//! their documented opaque-base and heap-operation seams.

use crate::cxx::string_object::StringObject;
use crate::cxx::string_object_opaque_base_destroy::string_object_opaque_base_destroy;
use crate::heap::veneers::operator_delete;

/// Replaces the slot's owned StringObject, disposing of a distinct old value first.
///
/// # Safety
///
/// `slot` must name a readable and writable pointer word. A non-NULL old value
/// must meet [`string_object_opaque_base_destroy`]'s safety contract and be
/// valid for [`operator_delete`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.owned_string_object_replace")]
#[inline(never)]
pub unsafe extern "C" fn owned_string_object_replace(
    slot: *mut *mut StringObject,
    replacement: *mut StringObject,
) {
    let old = unsafe { slot.read() };
    if old == replacement {
        return;
    }
    if !old.is_null() {
        unsafe {
            string_object_opaque_base_destroy(old);
            operator_delete(old.cast());
        }
    }
    unsafe { slot.write(replacement) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object_opaque_base_destroy::{OpaqueBaseDestroyOps, OPAQUE_BASE_DESTROY_OPS};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{DEFAULT_HEAP_OPS, HEAP_OPS};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DESTROYED_BASE: usize = 0;
    static mut FREED_OBJECT: usize = 0;
    static mut FREED_TAG: usize = 0;

    unsafe extern "C" fn record_base_destroy(base: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
        unsafe { DESTROYED_BASE = base as usize };
        base
    }


    unsafe extern "C" fn passthrough_base_destroy(base: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
        base
    }
    unsafe extern "C" fn record_free(
        _heap: *mut HeapDescriptorDescriptor,
        object: *mut u8,
        tag: usize,
    ) {
        unsafe {
            FREED_OBJECT = object as usize;
            FREED_TAG = tag;
        }
    }

    fn install_recording_seams() {
        unsafe {
            core::ptr::addr_of_mut!(OPAQUE_BASE_DESTROY_OPS).write(OpaqueBaseDestroyOps {
                destroy: record_base_destroy,
            });
            let mut ops = DEFAULT_HEAP_OPS;
            ops.free = record_free;
            core::ptr::addr_of_mut!(HEAP_OPS).write(ops);
            core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP).write(1usize as *mut _);
            DESTROYED_BASE = 0;
            FREED_OBJECT = 0;
            FREED_TAG = 0;
        }
    }

    fn restore_seams() {
        unsafe {
            core::ptr::addr_of_mut!(OPAQUE_BASE_DESTROY_OPS).write(OpaqueBaseDestroyOps {
                destroy: passthrough_base_destroy,
            });
            core::ptr::addr_of_mut!(HEAP_OPS).write(DEFAULT_HEAP_OPS);
            core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP).write(core::ptr::null_mut());
        }
    }

    #[test]
    fn equal_pointer_preserves_slot_without_disposal() {
        let _lock = TEST_LOCK.lock();
        install_recording_seams();
        let mut object = [0usize; 3];
        let object = object.as_mut_ptr().cast::<StringObject>();
        let mut slot = object;

        unsafe { owned_string_object_replace(&mut slot, object) };

        assert_eq!(slot, object);
        assert_eq!(unsafe { DESTROYED_BASE }, 0);
        assert_eq!(unsafe { FREED_OBJECT }, 0);
        restore_seams();
    }

    #[test]
    fn null_old_pointer_stores_replacement_without_disposal() {
        let _lock = TEST_LOCK.lock();
        install_recording_seams();
        let replacement = 0x1234usize as *mut StringObject;
        let mut slot = core::ptr::null_mut();

        unsafe { owned_string_object_replace(&mut slot, replacement) };

        assert_eq!(slot, replacement);
        assert_eq!(unsafe { DESTROYED_BASE }, 0);
        assert_eq!(unsafe { FREED_OBJECT }, 0);
        restore_seams();
    }

    #[test]
    fn distinct_old_pointer_destroys_then_deletes_before_replacement() {
        let _lock = TEST_LOCK.lock();
        install_recording_seams();
        let mut old_storage = [0usize; 3];
        let old = old_storage.as_mut_ptr().cast::<StringObject>();
        let replacement = 0x5678usize as *mut StringObject;
        let mut slot = old;

        unsafe { owned_string_object_replace(&mut slot, replacement) };

        assert_eq!(slot, replacement);
        assert_eq!(unsafe { DESTROYED_BASE }, unsafe { old.cast::<u32>().add(2) } as usize);
        assert_eq!(unsafe { FREED_OBJECT }, old as usize);
        assert_eq!(unsafe { FREED_TAG }, 2);
        restore_seams();
    }
}
