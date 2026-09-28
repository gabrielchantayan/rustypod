//! `mutexed_list_pop_delete` — original: `FUN_0839eae4` @ **0x0839eae4**.
//!
//! Raw `osos.dec` words establish the 52-byte extent
//! `0x0839eae4..0x0839eb17`; `push {r4,r5,r6,lr}` at `0x0839eb18` begins the
//! next independently entered function. The body has three plain direct `bl`
//! instructions (to `mutex_lock`, the unported 0x080f10b8 list ABI, and
//! `operator_delete`) and no predicated `bl` instructions. Full-image A32
//! decoding finds two incoming plain `bl` sites (0x0816679c and 0x08166864)
//! and no predicated incoming `bl` sites.
//!
//! # Algorithm
//!
//! Lock the mutex at `list_owner + 8`, pop the owner’s opaque list through
//! the verified 0x080f10b8 ABI, delete the popped node's `+4` allocation, and
//! return the popped node. Stock code does not null-check the popped node
//! before reading `+4`.
//!
//! # Deliberate deviation
//!
//! 0x080f10b8 has no verified names.yaml identity, so device builds call its
//! fixed address and host tests inject its observed pop ABI. Rust expresses
//! the final delete call normally rather than preserving register r5 across
//! the call; the returned node is unchanged.

use crate::heap::veneers::operator_delete;
use crate::kernel::sync_mutex::{mutex_lock, Mutex};

const LIST_MUTEX_OFFSET: usize = 8;
const NODE_ALLOCATION_OFFSET: usize = 4;
const LIST_POP_FRONT_ADDRESS: usize = 0x080f_10b8;

type ListPopFront = unsafe extern "C" fn(*mut u8) -> *mut u8;
type MutexLock = unsafe extern "C" fn(*mut Mutex);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_list_pop_front(list_owner: *mut u8) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, ListPopFront>(LIST_POP_FRONT_ADDRESS)(list_owner) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_list_pop_front(_: *mut u8) -> *mut u8 {
    panic!("mutexed_list_pop_delete requires FUN_080f10b8")
}

/// Locks `list_owner + 8`, removes its first opaque list node, deletes that
/// node's owned `+4` allocation, and returns the removed node.
///
/// # Safety
///
/// `list_owner` must be valid for the mutex and the opaque 0x080f10b8 list
/// ABI. That ABI must return a non-null node whose target-width word at `+4`
/// is valid for `operator_delete`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutexed_list_pop_delete(list_owner: *mut u8) -> *mut u8 {
    unsafe { mutexed_list_pop_delete_with(list_owner, mutex_lock, firmware_list_pop_front) }
}

#[inline(always)]
unsafe fn mutexed_list_pop_delete_with(
    list_owner: *mut u8,
    lock: MutexLock,
    pop_front: ListPopFront,
) -> *mut u8 {
    unsafe {
        lock(list_owner.add(LIST_MUTEX_OFFSET).cast());
        let node = pop_front(list_owner);
        let allocation = node.add(NODE_ALLOCATION_OFFSET).cast::<*mut u8>().read();
        operator_delete(allocation);
        node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn mark_locked(mutex: *mut Mutex) {
        unsafe { mutex.cast::<u8>().sub(LIST_MUTEX_OFFSET).write(0xa5) }
    }

    unsafe extern "C" fn pop_after_lock(owner: *mut u8) -> *mut u8 {
        unsafe {
            assert_eq!(owner.read(), 0xa5, "lock precedes list pop");
            let node = owner.add(0x40);
            node.add(NODE_ALLOCATION_OFFSET).cast::<*mut u8>().write(core::ptr::null_mut());
            node
        }
    }

    #[test]
    fn locks_before_popping_and_returns_node_when_owned_allocation_is_null() {
        let mut owner = [0u8; 0x50];
        let node = unsafe { mutexed_list_pop_delete_with(owner.as_mut_ptr(), mark_locked, pop_after_lock) };
        assert_eq!(node, unsafe { owner.as_mut_ptr().add(0x40) });
        assert_eq!(owner[0], 0xa5);
    }
}
