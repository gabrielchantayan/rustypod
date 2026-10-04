//! Guarded context lifecycle vtable dispatch.
//!
//! `context_lifecycle_slot_0x34_dispatch` — `FUN_081f0684` at 0x081f0684.
//! Raw extent: 52 bytes, [0x081f0684, 0x081f06b8); the next push starts
//! an independent function. Whole-image A32 decoding verifies two inbound
//! plain BLs (0x0814ac7c, 0x0814afb8), zero predicated inbound BLs, one
//! outbound plain BL to mutex_lock, zero predicated outbound BLs, and one
//! BLXNE through the object's vtable. The final B targets mutex_unlock.
//!
//! Lock context+0x50, load the lifecycle object at +0x48, invoke its vtable
//! slot +0x34 with that object when non-NULL, then unlock the same guard.
//! Ignore the slot result. Deliberate deviations: Rust expresses the tail
//! branch as a return-position call; host builds widen object/vtable pointer
//! words to native width while retaining the slot's word index. No target
//! behavioral deviations.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const LIFECYCLE_OBJECT_OFFSET: usize = 0x48;
const LIFECYCLE_GUARD_OFFSET: usize = 0x50;
const LIFECYCLE_SLOT: usize = 0x34 / 4;

/// `context` must contain a valid Mutex at +0x50 and a lifecycle-object
/// pointer at +0x48. Non-NULL objects must have a valid vtable slot +0x34.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_lifecycle_slot_0x34_dispatch(context: *mut u8) {
    let guard = context.add(LIFECYCLE_GUARD_OFFSET).cast::<Mutex>();
    mutex_lock(guard);
    let object = context.add(LIFECYCLE_OBJECT_OFFSET).cast::<*mut u8>().read();
    if !object.is_null() {
        let vtable = object.cast::<*const usize>().read();
        let slot: unsafe extern "C" fn(*mut u8) = core::mem::transmute(vtable.add(LIFECYCLE_SLOT).read());
        slot(object);
    }
    mutex_unlock(guard);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Context {
        prefix: [u8; LIFECYCLE_OBJECT_OFFSET],
        object: *mut u8,
        #[cfg(target_pointer_width = "32")]
        padding: u32,
        guard: Mutex,
    }

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        state: u32,
        guard: *mut Mutex,
    }

    unsafe extern "C" fn transition(object: *mut u8) {
        let object = &mut *object.cast::<Object>();
        assert_eq!(*(*object.guard).sem_cell, 0);
        object.state = object.state.wrapping_add(1);
        // Unlock must tolerate a guard whose cell changed during dispatch.
        (*object.guard).sem_cell = core::ptr::null_mut();
    }

    #[test]
    fn absent_object_accepts_null_and_zero_handle_guards() {
        let mut cell = 0u32;
        for sem_cell in [core::ptr::null_mut(), &mut cell as *mut u32] {
            let mut context = Context {
                prefix: [0xa5; LIFECYCLE_OBJECT_OFFSET],
                object: core::ptr::null_mut(),
                #[cfg(target_pointer_width = "32")]
                padding: 0,
                guard: Mutex { sem_cell, unused: 0x12345678 },
            };
            unsafe { context_lifecycle_slot_0x34_dispatch((&mut context as *mut Context).cast()); }
            assert_eq!(context.guard.sem_cell, sem_cell);
            assert_eq!(context.guard.unused, 0x12345678);
            assert_eq!(context.prefix, [0xa5; LIFECYCLE_OBJECT_OFFSET]);
        }
    }

    #[test]
    fn present_object_transitions_once_and_can_clear_guard() {
        let mut cell = 0;
        let mut context = Context {
            prefix: [0; LIFECYCLE_OBJECT_OFFSET],
            object: core::ptr::null_mut(),
            #[cfg(target_pointer_width = "32")]
            padding: 0,
            guard: Mutex { sem_cell: &mut cell, unused: 0xabcdef01 },
        };
        let mut vtable = [0usize; LIFECYCLE_SLOT + 1];
        vtable[LIFECYCLE_SLOT] = transition as *const () as usize;
        let mut object = Object { vtable: vtable.as_ptr(), state: u32::MAX, guard: &mut context.guard };
        context.object = (&mut object as *mut Object).cast();
        assert_eq!(core::ptr::addr_of!(context.guard) as usize - &context as *const Context as usize, LIFECYCLE_GUARD_OFFSET);
        unsafe { context_lifecycle_slot_0x34_dispatch((&mut context as *mut Context).cast()); }
        assert_eq!(object.state, 0);
        assert!(context.guard.sem_cell.is_null());
        assert_eq!(context.guard.unused, 0xabcdef01);
    }
}
