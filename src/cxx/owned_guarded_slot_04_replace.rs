//! Replaces an owned guarded-slot-`+0x04` object pointer.
//!
//! `owned_guarded_slot_04_replace` — original: `FUN_083e73a0` @
//! **0x083e73a0** (48 bytes). Raw `osos.dec` establishes the extent: twelve
//! ARM words from `push {r4, r5, r6, lr}` through `pop {r4, r5, r6, pc}` at
//! `0x083e73cc`; the next real function begins at `0x083e73d0`.
//! Full-image ARM decoding finds three inbound direct `bl` calls at
//! `0x08124620`, `0x08140308`, and `0x0815fc18`, plus one predicated `beq` at
//! `0x08140324`; there are no predicated `bl` calls. The body makes two
//! plain unconditional `bl` calls: guarded vtable slot `+0x04` dispatch @
//! `0x08157448` and `operator_delete` @ `0x082aad24`.
//!
//! # Algorithm
//!
//! If the slot already contains `replacement`, leave it unchanged. Otherwise,
//! dispatch the old non-NULL object through its guarded virtual slot `+0x04`,
//! delete that object, then store `replacement` into the slot.
//!
//! # Deliberate deviation
//!
//! The target's object pointer is a 32-bit word; Rust uses a native pointer in
//! a `repr(C)` one-word slot so host tests can invoke the already ported typed
//! vtable seam. The target calls the two ported entries directly; their host
//! implementations use their documented vtable and heap-operation seams.

use crate::cxx::guarded_vtable_slot_04_dispatch_08157448::{
    guarded_vtable_slot_04_dispatch_08157448, GuardedSlot04Handle08157448,
};
use crate::heap::veneers::operator_delete;

/// Replaces the slot's owned object, disposing of a distinct old object first.
///
/// # Safety
///
/// `slot` must name a readable and writable object-pointer word. A non-NULL old
/// object must satisfy [`guarded_vtable_slot_04_dispatch_08157448`]'s safety
/// contract and be valid for [`operator_delete`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.owned_guarded_slot_04_replace")]
#[inline(never)]
pub unsafe extern "C" fn owned_guarded_slot_04_replace(slot: *mut *mut u8, replacement: *mut u8) {
    let old = unsafe { slot.read() };
    if old == replacement {
        return;
    }
    if !old.is_null() {
        unsafe {
            guarded_vtable_slot_04_dispatch_08157448(
                slot.cast::<GuardedSlot04Handle08157448>(),
            );
            operator_delete(old);
        }
    }
    unsafe { slot.write(replacement) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{DEFAULT_HEAP_OPS, HEAP_OPS};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLBACK_OBJECT: usize = 0;
    static mut FREED_OBJECT: usize = 0;
    static mut FREED_TAG: usize = 0;

    unsafe extern "C" fn record_callback(object: *mut u8) {
        unsafe { CALLBACK_OBJECT = object as usize };
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

    fn install_recording_heap() {
        unsafe {
            let mut ops = DEFAULT_HEAP_OPS;
            ops.free = record_free;
            core::ptr::addr_of_mut!(HEAP_OPS).write(ops);
            core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP).write(1usize as *mut _);
            CALLBACK_OBJECT = 0;
            FREED_OBJECT = 0;
            FREED_TAG = 0;
        }
    }

    fn restore_heap() {
        unsafe {
            core::ptr::addr_of_mut!(HEAP_OPS).write(DEFAULT_HEAP_OPS);
            core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP).write(core::ptr::null_mut());
        }
    }

    #[test]
    fn equal_pointer_preserves_slot_without_dispatch_or_delete() {
        let _lock = TEST_LOCK.lock();
        install_recording_heap();
        let mut object = [0usize; 2];
        let object = object.as_mut_ptr().cast::<u8>();
        let mut slot = object;

        unsafe { owned_guarded_slot_04_replace(&mut slot, object) };

        assert_eq!(slot, object);
        assert_eq!(unsafe { CALLBACK_OBJECT }, 0);
        assert_eq!(unsafe { FREED_OBJECT }, 0);
        restore_heap();
    }

    #[test]
    fn null_old_pointer_stores_replacement_without_disposal() {
        let _lock = TEST_LOCK.lock();
        install_recording_heap();
        let replacement = 0x1234usize as *mut u8;
        let mut slot = core::ptr::null_mut();

        unsafe { owned_guarded_slot_04_replace(&mut slot, replacement) };

        assert_eq!(slot, replacement);
        assert_eq!(unsafe { CALLBACK_OBJECT }, 0);
        assert_eq!(unsafe { FREED_OBJECT }, 0);
        restore_heap();
    }

    #[test]
    fn distinct_old_pointer_dispatches_then_deletes_before_replacement() {
        let _lock = TEST_LOCK.lock();
        install_recording_heap();
        let mut vtable = [0usize, record_callback as usize];
        let mut object = [vtable.as_mut_ptr() as usize];
        let old = object.as_mut_ptr().cast::<u8>();
        let replacement = 0x5678usize as *mut u8;
        let mut slot = old;

        unsafe { owned_guarded_slot_04_replace(&mut slot, replacement) };

        assert_eq!(slot, replacement);
        assert_eq!(unsafe { CALLBACK_OBJECT }, old as usize);
        assert_eq!(unsafe { FREED_OBJECT }, old as usize);
        assert_eq!(unsafe { FREED_TAG }, 2);
        restore_heap();
    }
}
