//! Request state 2 and notify the owner.
//!
//! Original: FUN_08132f28 @ 0x08132f28, exactly 64 bytes through
//! 0x08132f68 (next independent PUSH). Raw A32 decoding: one plain and
//! one predicated incoming BL; three plain outgoing BLs, no predicated
//! outgoing BLs, and a tail B to 0x08132c6c.
//!
//! Acquire the counted mutex at +0x74, store state 2 at +0x64, release
//! the mutex, set the request flag at +0x66, post mailbox slot +0x70,
//! then prepare/wait through resident 0x08132c6c with timeout 200.
//! Its tail chain through 0x08132d48 returns 1 on normal completion.
//! The concrete owner class and meaning of state 2 are not established.
//!
//! Deviations: repr(C) native pointers expand host fields while retaining
//! target offsets. Existing mutex/mailbox ports are reused; the unported
//! prepare/wait helper uses a verified resident address on ARM and an
//! explicitly installed host operation. Rust expresses the tail B as a call.

use crate::kernel::kobj::{mailbox_slot_post, Mailbox};
use crate::kernel::sync_mutex::{mutex_lock_counted, mutex_unlock_counted, CountedMutex};

#[repr(C)]
pub struct StateRequestOwner {
    pub prefix: [u8; 0x64],
    pub state: u8,
    pub reserved_65: u8,
    pub request_pending: u8,
    pub reserved_67: [u8; 9],
    pub mailbox: *mut Mailbox,
    pub lock: CountedMutex,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(StateRequestOwner, state) == 0x64);
    assert!(core::mem::offset_of!(StateRequestOwner, request_pending) == 0x66);
    assert!(core::mem::offset_of!(StateRequestOwner, mailbox) == 0x70);
    assert!(core::mem::offset_of!(StateRequestOwner, lock) == 0x74);
};

pub type OwnerPrepareWait = unsafe extern "C" fn(*mut StateRequestOwner, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare_wait(_: *mut StateRequestOwner, _: u32) -> u32 {
    panic!("install resident owner prepare/wait host operation")
}

#[cfg(not(target_os = "none"))]
pub static mut OWNER_PREPARE_WAIT: OwnerPrepareWait = missing_prepare_wait;

/// # Safety
/// Owner and its mailbox must be live and satisfy the existing kernel ports.
/// On target the full resident owner (including member +0x80 and beyond) must
/// be valid for 0x08132c6c. Host callers must install an equivalent operation
/// without concurrent modification of OWNER_PREPARE_WAIT.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owner_request_state_two(owner: *mut StateRequestOwner) -> u32 {
    mutex_lock_counted(core::ptr::addr_of_mut!((*owner).lock));
    core::ptr::addr_of_mut!((*owner).state).write_volatile(2);
    mutex_unlock_counted(core::ptr::addr_of_mut!((*owner).lock));
    core::ptr::addr_of_mut!((*owner).request_pending).write_volatile(1);
    mailbox_slot_post(core::ptr::addr_of_mut!((*owner).mailbox));
    #[cfg(target_os = "none")]
    let prepare_wait: OwnerPrepareWait = core::mem::transmute(0x0813_2c6cusize);
    #[cfg(not(target_os = "none"))]
    let prepare_wait = core::ptr::addr_of!(OWNER_PREPARE_WAIT).read();
    prepare_wait(owner, 200)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::sync_mutex::Mutex;
    use parking_lot::Mutex as TestMutex;

    static LOCK: TestMutex<()> = TestMutex::new(());

    unsafe extern "C" fn observe_ready(owner: *mut StateRequestOwner, timeout: u32) -> u32 {
        assert_eq!(timeout, 200);
        assert_eq!((*owner).state, 2);
        assert_eq!((*owner).request_pending, 1);
        let prefix = core::ptr::addr_of!((*owner).prefix).read();
        assert_eq!((*owner).lock.hold_count, u32::from_le_bytes(prefix[..4].try_into().unwrap()));
        let before = u32::from_le_bytes(prefix[4..8].try_into().unwrap());
        assert_eq!((*(*owner).mailbox).state, before.wrapping_add(1));
        // A resident helper can mutate the object; the wrapper must not rewrite it.
        (*owner).state = 7;
        (*owner).request_pending = 0;
        0x8765_4321
    }

    #[test]
    fn state_notification_preserves_fields_and_resident_mutations() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = core::ptr::addr_of!(OWNER_PREPARE_WAIT).read();
            OWNER_PREPARE_WAIT = observe_ready;
            for (holds, tokens, state, pending) in [
                (0u32, 0u32, 0u8, 0u8),
                (u32::MAX, u32::MAX - 1, 255, 255),
                (17, u32::MAX - 2, 2, 1),
            ] {
                let mut mailbox = Mailbox { state: tokens, id: 0x55 };
                let mut owner = StateRequestOwner {
                    prefix: [0xa5; 0x64], state, reserved_65: 0x93,
                    request_pending: pending, reserved_67: [0x6b; 9],
                    mailbox: &mut mailbox,
                    lock: CountedMutex {
                        mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0x1234 },
                        hold_count: holds,
                    },
                };
                owner.prefix[..4].copy_from_slice(&holds.to_le_bytes());
                owner.prefix[4..8].copy_from_slice(&tokens.to_le_bytes());
                let prefix = owner.prefix;
                assert_eq!(owner_request_state_two(&mut owner), 0x8765_4321);
                assert_eq!((owner.state, owner.request_pending), (7, 0));
                assert_eq!(owner.prefix, prefix);
                assert_eq!(owner.reserved_65, 0x93);
                assert_eq!(owner.reserved_67, [0x6b; 9]);
                assert_eq!(owner.lock.mutex.unused, 0x1234);
                assert_eq!(mailbox.id, 0x55);
                assert_eq!(owner.mailbox, &mut mailbox as *mut Mailbox);
            }
            OWNER_PREPARE_WAIT = saved;
        }
    }
}
