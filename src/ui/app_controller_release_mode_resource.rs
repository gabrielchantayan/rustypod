//! Releases an app-controller resource selected by its mode byte.
//!
//! `app_controller_release_mode_resource` — original: `FUN_0817f408` @
//! `0x0817f408` (236 bytes, `0x0817f408..0x0817f4f3`). Raw ARM establishes
//! that Ghidra's 100-byte extent ends in the middle of this function: the
//! shared continuation at `0x0817f46c` consumes the saved registers and ends
//! at the next independent `push` at `0x0817f4f4`. It has eleven direct plain
//! `bl` instructions, one predicated `bleq`, and one internal predicated
//! `blt`; whole-image decoding finds three inbound plain `bl` callers and no
//! predicated inbound call. It maps resource byte `+0x11d` 1..4 to slots 0..3,
//! stops the resource, finds its owning object, destroys and deallocates that
//! object, clears the parent slot's byte `+0xd4`, decrements the parent count,
//! signals event 1, dispatches the matching release action, and clamps a
//! negative count before finishing the parent operation.
//!
//! Deliberate deviations: the unported direct callees have no established
//! identities beyond their observed roles, so host builds expose them as a
//! narrow operation seam. Target builds call their verified retailOS addresses.

const RESOURCE_MODE_OFFSET: usize = 0x11d;
const PARENT_COUNT_OFFSET: usize = 0xd0;
const SLOT_ACTIVE_OFFSET: usize = 0xd4;
const RESOURCE_OWNER_OFFSET: usize = 0x3c;

type StopResource = unsafe extern "C" fn(*mut u8, u32);
type FindOwner = unsafe extern "C" fn(*mut u8) -> *mut u8;
type ResourceOperation = unsafe extern "C" fn(*mut u8);
type Signal = unsafe extern "C" fn(u32);
type ReleaseAction = unsafe extern "C" fn(*mut u8, u32);
type FinishParent = unsafe extern "C" fn(*mut u8, u32);

#[derive(Clone, Copy)]
pub struct AppControllerReleaseModeResourceOps {
    pub stop_resource: StopResource,
    pub find_owner: FindOwner,
    pub prepare_owner: ResourceOperation,
    pub destroy_owner: ResourceOperation,
    pub deallocate_owner: ResourceOperation,
    pub signal: Signal,
    pub release_actions: [ReleaseAction; 4],
    pub finish_parent: FinishParent,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_stop(_resource: *mut u8, _value: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_find(_resource: *mut u8) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_operation(_owner: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_signal(_event: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_release(_parent: *mut u8, _value: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_finish(_parent: *mut u8, _value: u32) {}

#[cfg(not(target_os = "none"))]
pub static mut APP_CONTROLLER_RELEASE_MODE_RESOURCE_OPS: AppControllerReleaseModeResourceOps = AppControllerReleaseModeResourceOps {
    stop_resource: no_stop, find_owner: no_find, prepare_owner: no_operation,
    destroy_owner: no_operation, deallocate_owner: no_operation, signal: no_signal,
    release_actions: [no_release; 4], finish_parent: no_finish,
};

#[cfg(target_os = "none")]
unsafe fn firmware_ops() -> AppControllerReleaseModeResourceOps {
    unsafe {
        AppControllerReleaseModeResourceOps {
            stop_resource: core::mem::transmute(0usize), // dynamically dispatched below
            find_owner: core::mem::transmute(0x082a_2670usize),
            prepare_owner: core::mem::transmute(0x0828_d504usize),
            destroy_owner: core::mem::transmute(0x0828_e5b0usize),
            deallocate_owner: core::mem::transmute(0x082a_ad24usize),
            signal: core::mem::transmute(0x081d_8870usize),
            release_actions: [core::mem::transmute(0x0828_d64cusize), core::mem::transmute(0x0828_d66cusize), core::mem::transmute(0x0828_d690usize), core::mem::transmute(0x0828_d6acusize)],
            finish_parent: core::mem::transmute(0x0817_f324usize),
        }
    }
}

/// # Safety
/// `parent` needs writable words at `+0xd0` and `slot*+0xd4`; `resource` must
/// contain the retailOS layout through `+0x11d` and a valid vtable on target.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_controller_release_mode_resource(parent: *mut u8, resource: *mut u8) {
    let slot = match unsafe { resource.add(RESOURCE_MODE_OFFSET).read() } {
        1 => 0, 2 => 1, 3 => 2, 4 => 3, _ => return,
    };
    #[cfg(target_os = "none")]
    unsafe {
        let vtable = resource.cast::<u32>().read() as *const u8;
        let stop: StopResource = core::mem::transmute(vtable.add(0xa0).cast::<u32>().read() as usize);
        stop(resource, 0);
        release_with_ops(parent, resource, slot, firmware_ops());
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        let ops = APP_CONTROLLER_RELEASE_MODE_RESOURCE_OPS;
        (ops.stop_resource)(resource, 0);
        release_with_ops(parent, resource, slot, ops);
    }
}

unsafe fn release_with_ops(parent: *mut u8, resource: *mut u8, slot: usize, ops: AppControllerReleaseModeResourceOps) {
    let owner = unsafe { (ops.find_owner)(resource) };
    if !owner.is_null() {
        unsafe {
            resource.add(RESOURCE_OWNER_OFFSET).cast::<u32>().write(0);
            (ops.prepare_owner)(owner);
            (ops.destroy_owner)(owner);
            (ops.deallocate_owner)(owner);
        }
    }
    unsafe {
        parent.add(slot + SLOT_ACTIVE_OFFSET).write(0);
        let count = parent.add(PARENT_COUNT_OFFSET).cast::<i32>();
        count.write(count.read().wrapping_sub(1));
        (ops.signal)(1);
        (ops.release_actions[slot])(parent, 0);
        if count.read() < 0 {
            count.write(0);
            (ops.finish_parent)(parent, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    static SIGNALS: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn signal(event: u32) { SIGNALS.store(event as usize, Ordering::Relaxed); }
    unsafe extern "C" fn release(parent: *mut u8, value: u32) { unsafe { parent.add(0xc0).write(value as u8 + 1); } }

    #[test]
    fn releases_valid_slot_and_clamps_negative_parent_count() {
        let mut parent = [0u8; 0xe0];
        let mut resource = [0u8; 0x120];
        unsafe {
            resource[RESOURCE_MODE_OFFSET] = 3;
            parent.as_mut_ptr().add(PARENT_COUNT_OFFSET).cast::<i32>().write(0);
            let mut ops = APP_CONTROLLER_RELEASE_MODE_RESOURCE_OPS;
            ops.signal = signal;
            ops.release_actions[2] = release;
            APP_CONTROLLER_RELEASE_MODE_RESOURCE_OPS = ops;
            app_controller_release_mode_resource(parent.as_mut_ptr(), resource.as_mut_ptr());
            assert_eq!(parent[SLOT_ACTIVE_OFFSET + 2], 0);
            assert_eq!(parent.as_ptr().add(PARENT_COUNT_OFFSET).cast::<i32>().read(), 0);
            assert_eq!(parent[0xc0], 1);
            assert_eq!(SIGNALS.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn ignores_unknown_mode_without_side_effects() {
        let mut parent = [0xa5u8; 0xe0];
        let mut resource = [0u8; 0x120];
        resource[RESOURCE_MODE_OFFSET] = 5;
        unsafe { app_controller_release_mode_resource(parent.as_mut_ptr(), resource.as_mut_ptr()); }
        assert_eq!(parent, [0xa5; 0xe0]);
    }
}
