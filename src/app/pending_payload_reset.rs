//! `pending_payload_reset` — retailOS `FUN_082070c8` @ **0x082070c8**.
//!
//! True extent: **88 bytes**, ending before the independent push at 0x08207120.
//! Four plain outbound BLs, zero predicated BLs, one `blxne r1`, and a tail
//! branch to 0x081fb524. Whole-image decoding finds two plain inbound BLs.
//! Locks owner+0x14, clears its pending list, clears flag bit zero at +0x28,
//! releases the optional object at +0x10 through vtable slot +4, clears that
//! pointer, unlocks, then removes the owner from the shared callback queue.
//!
//! Deliberate deviations: the tail branch is a return-position Rust call.
//! The unported queue operation retains its verified address and two-pointer
//! ABI; no implementation is inferred from Ghidra's incorrectly expanded body.
//! Host layouts use native pointers and the existing pending-list fixture;
//! the host queue seam panics unless explicitly installed, rather than faking
//! successful removal. Firmware fields remain aligned 32-bit word accesses.

use crate::app::pending_payload_list_clear::pending_payload_list_clear;
use crate::kernel::sync_mutex::{Mutex, mutex_lock, mutex_unlock};

type QueueRemove = unsafe extern "C" fn(*mut u8, *mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_queue_remove(_: *mut u8, _: *mut u8) {
    panic!("callback queue removal requires a host implementation");
}

#[cfg(not(target_os = "none"))]
pub static mut HOST_QUEUE_REMOVE: QueueRemove = missing_queue_remove;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostPendingPayloadOwner {
    pub pending: crate::app::pending_payload_list_clear::HostPendingPayloadList,
    pub flags: u32,
    pub mutex: Mutex,
}

/// Resets pending payload state and unregisters the owner from its queue.
///
/// # Safety
/// Firmware owner must expose writable words through +0x28, a valid mutex at
/// +0x14, and a valid pending list. A nonnull +0x10 object must have a callable
/// vtable slot +4 taking that object. The shared queue must be initialized.
/// Hosts must supply `HostPendingPayloadOwner` and install `HOST_QUEUE_REMOVE`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pending_payload_reset(owner: *mut u8) {
    #[cfg(target_os = "none")]
    let (mutex, active, flags) = (
        owner.add(0x14).cast::<Mutex>(),
        owner.cast::<usize>().add(0x10 / 4),
        owner.cast::<u32>().add(0x28 / 4),
    );
    #[cfg(not(target_os = "none"))]
    let (mutex, active, flags) = {
        let host = owner.cast::<HostPendingPayloadOwner>();
        (core::ptr::addr_of_mut!((*host).mutex),
         core::ptr::addr_of_mut!((*host).pending.unresolved_00_to_1f[2]),
         core::ptr::addr_of_mut!((*host).flags))
    };
    mutex_lock(mutex);
    pending_payload_list_clear(owner);
    flags.write_volatile(flags.read_volatile() & !1);
    let object = active.read_volatile() as *mut u8;
    if !object.is_null() {
        let vtable = object.cast::<*const usize>().read_volatile();
        let release: unsafe extern "C" fn(*mut u8) = core::mem::transmute(vtable.add(1).read_volatile());
        release(object);
    }
    active.write_volatile(0);
    mutex_unlock(mutex);
    let queue = crate::app::callback_queue::callback_queue_instance_get();
    #[cfg(target_os = "none")]
    let remove: QueueRemove = core::mem::transmute(0x081f_b524usize);
    #[cfg(not(target_os = "none"))]
    let remove = core::ptr::addr_of!(HOST_QUEUE_REMOVE).read_volatile();
    remove(queue, owner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::pending_payload_list_clear::{HostPendingPayloadList, HostPendingPayloadNode, HostPendingPayloadVtable};
    use core::ptr;

    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut OWNER: *mut HostPendingPayloadOwner = ptr::null_mut();
    static mut STAGE: u32 = 0;

    unsafe extern "C" fn release_pending(_: *mut u8) {
        assert_eq!(STAGE, 0);
        assert_eq!((*OWNER).flags, 0xffff_ffff);
        STAGE = 1;
    }

    unsafe extern "C" fn release_active(_: *mut u8) {
        assert_eq!(STAGE, 1);
        assert!((*OWNER).pending.head.is_null());
        assert!((*OWNER).pending.tail.is_null());
        assert_eq!((*OWNER).flags, 0xffff_fffe);
        assert_ne!((*OWNER).pending.unresolved_00_to_1f[2], 0);
        STAGE = 2;
    }

    unsafe extern "C" fn remove(_: *mut u8, owner: *mut u8) {
        assert_eq!(owner, OWNER.cast());
        assert_eq!((*OWNER).pending.unresolved_00_to_1f[2], 0);
        STAGE += 10;
    }

    #[test]
    fn releases_list_before_active_object_and_preserves_other_flag_bits() {
        let _lock = LOCK.lock();
        unsafe {
            let old = HOST_QUEUE_REMOVE;
            HOST_QUEUE_REMOVE = remove;
            let pending_vtable = HostPendingPayloadVtable { unresolved_00: 0, release: release_pending };
            let mut node = HostPendingPayloadNode { payload_vtable: &pending_vtable, unresolved_08_to_3f: [0; 7], next: ptr::null_mut() };
            let active_vtable = [0usize, release_active as *const () as usize];
            let mut active_object = active_vtable.as_ptr();
            let mut owner = HostPendingPayloadOwner {
                pending: HostPendingPayloadList { unresolved_00_to_1f: [0, 0, ptr::addr_of_mut!(active_object) as usize, 0], head: &mut node, tail: &mut node },
                flags: u32::MAX,
                mutex: Mutex { sem_cell: ptr::null_mut(), unused: 0 },
            };
            OWNER = &mut owner;
            STAGE = 0;
            pending_payload_reset(OWNER.cast());
            assert_eq!(STAGE, 12);
            // Repeat reset: no object dispatch, all other flag bits survive.
            STAGE = 0;
            pending_payload_reset(OWNER.cast());
            assert_eq!(STAGE, 10);
            assert_eq!(owner.flags, 0xffff_fffe);
            HOST_QUEUE_REMOVE = old;
            OWNER = ptr::null_mut();
        }
    }
}
