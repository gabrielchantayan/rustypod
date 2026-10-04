//! Available-slot count, `FUN_0820cd78` @ 0x0820cd78.
//!
//! True extent: 112 bytes, 0x0820cd78..0x0820cde8; the next entry starts
//! with push {r3-r7,lr}. Raw A32 decoding verifies two outbound plain BLs
//! (lock at 0x0820cd8c, unlock at 0x0820cdd0), zero predicated BLs, and two
//! inbound plain BLs at 0x081e4488 and 0x081e4830, zero predicated BLs.
//! Lock the pool's mutex, count exactly state 1 across 128 twenty-byte slots,
//! store the count before unlocking, and return 0 on success or 2 on error.
//! The allocator at 0x0820cbac consumes these slots by changing state 1 to 3.
//!
//! Deliberate deviations: repr(C) mutex/service pointer fields widen on hosts;
//! slot words retain target width. Reuses the ported lock-service adapters,
//! whose status is always zero, so LLVM may remove the unreachable errors.

use core::ffi::c_void;
use crate::app::lock_service::{lock_service_lock, lock_service_unlock};
use crate::kernel::sync_mutex::Mutex;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PoolSlot {
    pub payload: [u32; 2],
    pub state: u8,
    pub reserved: [u8; 3],
    pub next: u32,
    pub owner: u32,
}

#[repr(C)]
pub struct SlotPool {
    pub slots: [PoolSlot; 128],
    pub mutex: Mutex,
    pub lock_service: *mut c_void,
}

/// # Safety
/// `pool` must be a live pool with a valid mutex; `count` must be writable.
/// Concurrent slot mutation must obey the pool mutex. Install the existing
/// kernel semaphore operations before using a created mutex.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_pool_available_count(pool: *mut SlotPool, count: *mut i32) -> i32 {
    let mutex = core::ptr::addr_of_mut!((*pool).mutex);
    if lock_service_lock((*pool).lock_service, mutex) != 0 {
        return 2;
    }
    let mut available = 0;
    for index in 0..128 {
        if core::ptr::addr_of!((*pool).slots[index].state).read() == 1 {
            available += 1;
        }
    }
    count.write(available);
    if lock_service_unlock((*pool).lock_service, mutex) != 0 { 2 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> SlotPool {
        SlotPool {
            slots: [PoolSlot { payload: [0x01010101; 2], state: 0,
                reserved: [1; 3], next: 0x01010101, owner: 0x01010101 }; 128],
            mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 1 },
            lock_service: core::ptr::null_mut(),
        }
    }

    #[test]
    fn only_exact_state_one_counts() {
        let mut pool = pool();
        for state in 0..=255u8 {
            for slot in &mut pool.slots { slot.state = state; }
            let mut count = -1;
            assert_eq!(unsafe { slot_pool_available_count(&mut pool, &mut count) }, 0);
            assert_eq!(count, if state == 1 { 128 } else { 0 });
            assert!(pool.slots.iter().all(|slot| slot.state == state));
        }
    }

    #[test]
    fn counts_first_last_and_sparse_slots_without_touching_neighbors() {
        let mut pool = pool();
        let mut count = -1;
        for index in [0, 127, 63, 64] { pool.slots[index].state = 1; }
        assert_eq!(unsafe { slot_pool_available_count(&mut pool, &mut count) }, 0);
        assert_eq!(count, 4);
        pool.slots[0].state = 3;
        pool.slots[127].state = 255;
        assert_eq!(unsafe { slot_pool_available_count(&mut pool, &mut count) }, 0);
        assert_eq!(count, 2);
        assert!(pool.slots.iter().all(|slot| slot.payload == [0x01010101; 2]
            && slot.reserved == [1; 3] && slot.next == 0x01010101 && slot.owner == 0x01010101));
        assert_eq!(pool.mutex.unused, 1);
    }
}
