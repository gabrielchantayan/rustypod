//! `slot_buffers_release` — original: `FUN_08206754` @ 0x08206754 (120
//! bytes, 0x08206754..0x082067cc).
//!
//! Verified call count: three plain unconditional `bl` sites — lock-service
//! lock @ 0x08228360, pool-free @ 0x0826f758, and lock-service unlock @
//! 0x08228388 — and no predicated `bl` sites. The literal at 0x082067cc is
//! the global pool-control pointer, not part of the function.
//!
//! Each of four 0x20-byte slots has an embedded mutex at +0x62c, an optional
//! pool allocation at +0x63c, and its recorded allocation length at +0x640.
//! The routine locks each slot through the service at `this + 0x624`, clears
//! its length, frees a non-NULL allocation when the global pool exists, clears
//! the allocation field, and unlocks it. A nonzero lock status returns 3
//! immediately; the ported lock-service adapter always returns zero.
//!
//! Deliberate deviations: the fixed RAM global at 0x08a0e13c is a private
//! host static for tests. The target's 32-bit pointer fields are read and
//! written as words, rather than Rust pointer fields, so host pointer width
//! cannot change the firmware offsets. Host builds also no-op the lock pair:
//! their widened `Mutex` cannot occupy the target's 4-byte-aligned +0x62c
//! field; target builds call the ported lock-service adapters directly.

use core::ptr;

#[cfg(target_pointer_width = "32")]
use crate::app::lock_service::{lock_service_lock, lock_service_unlock};
use crate::heap::pool::{pool_free, PoolControl};
#[cfg(target_pointer_width = "32")]
use crate::kernel::sync_mutex::Mutex;

const SERVICE_OFFSET: usize = 0x624;
const SLOT_MUTEX_OFFSET: usize = 0x62c;
const SLOT_ALLOCATION_OFFSET: usize = 0x63c;
const SLOT_LENGTH_OFFSET: usize = 0x640;
const SLOT_STRIDE: usize = 0x20;
const SLOT_COUNT: usize = 4;
const SLOT_RELEASE_ERROR: i32 = 3;

#[cfg(target_os = "none")]
const GLOBAL_POOL_CONTROL: *const *mut PoolControl = 0x08a0_e13cusize as *const *mut PoolControl;

#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_POOL_CONTROL: *mut PoolControl = ptr::null_mut();

#[inline(always)]
unsafe fn global_pool_control() -> *mut PoolControl {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(GLOBAL_POOL_CONTROL)
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(HOST_GLOBAL_POOL_CONTROL))
    }
}

#[cfg(target_pointer_width = "32")]
#[inline(always)]
unsafe fn lock_slot(service: *mut u8, slot: *mut u8) -> i32 {
    lock_service_lock(service.cast(), slot.cast::<Mutex>())
}

#[cfg(not(target_pointer_width = "32"))]
#[inline(always)]
unsafe fn lock_slot(_service: *mut u8, _slot: *mut u8) -> i32 {
    0
}

#[cfg(target_pointer_width = "32")]
#[inline(always)]
unsafe fn unlock_slot(service: *mut u8, slot: *mut u8) {
    lock_service_unlock(service.cast(), slot.cast::<Mutex>());
}

#[cfg(not(target_pointer_width = "32"))]
#[inline(always)]
unsafe fn unlock_slot(_service: *mut u8, _slot: *mut u8) {}

/// Releases all four slot-owned pool buffers.
///
/// # Safety
///
/// `slots` must point to the owning firmware object, whose fields through
/// `+0x6a0` are valid. Each nonzero allocation field must be a valid payload
/// from the global pool, as required by `pool_free`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_buffers_release(slots: *mut u8) -> i32 {
    let service = slots.add(SERVICE_OFFSET);

    for slot_index in 0..SLOT_COUNT {
        let slot = slots.add(SLOT_MUTEX_OFFSET + slot_index * SLOT_STRIDE);
        if lock_slot(service, slot) != 0 {
            return SLOT_RELEASE_ERROR;
        }

        ptr::write(slot.add(SLOT_LENGTH_OFFSET - SLOT_MUTEX_OFFSET).cast::<u32>(), 0);
        let allocation = ptr::read(slot.add(SLOT_ALLOCATION_OFFSET - SLOT_MUTEX_OFFSET).cast::<u32>());
        if allocation != 0 {
            let pool = global_pool_control();
            if !pool.is_null() {
                pool_free(pool, allocation as usize as *mut u8);
            }
            ptr::write(slot.add(SLOT_ALLOCATION_OFFSET - SLOT_MUTEX_OFFSET).cast::<u32>(), 0);
        }
        unlock_slot(service, slot);
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SLOT_BUFFERS_RELEASE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn releases_all_slots_and_clears_even_unavailable_pool_allocations() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/slot_buffers_release"));
            return;
        };
        let slots = base as *mut u8;
        unsafe {
            slots.write_bytes(0, FIXTURE_LEN);
            HOST_GLOBAL_POOL_CONTROL = ptr::null_mut();
            for index in 0..SLOT_COUNT {
                ptr::write((slots.add(SLOT_ALLOCATION_OFFSET + index * SLOT_STRIDE)).cast::<u32>(), 0x1000 + index as u32);
                ptr::write((slots.add(SLOT_LENGTH_OFFSET + index * SLOT_STRIDE)).cast::<u32>(), 0x8000 + index as u32);
            }
            assert_eq!(slot_buffers_release(slots), 0);
            for index in 0..SLOT_COUNT {
                assert_eq!(ptr::read((slots.add(SLOT_ALLOCATION_OFFSET + index * SLOT_STRIDE)).cast::<u32>()), 0);
                assert_eq!(ptr::read((slots.add(SLOT_LENGTH_OFFSET + index * SLOT_STRIDE)).cast::<u32>()), 0);
            }
        }
    }

    #[test]
    fn clears_lengths_when_slots_have_no_allocation() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/slot_buffers_release"));
            return;
        };
        let slots = base as *mut u8;
        unsafe {
            slots.write_bytes(0, FIXTURE_LEN);
            HOST_GLOBAL_POOL_CONTROL = ptr::null_mut();
            for index in 0..SLOT_COUNT {
                ptr::write((slots.add(SLOT_LENGTH_OFFSET + index * SLOT_STRIDE)).cast::<u32>(), u32::MAX);
            }

            assert_eq!(slot_buffers_release(slots), 0);
            for index in 0..SLOT_COUNT {
                assert_eq!(ptr::read((slots.add(SLOT_LENGTH_OFFSET + index * SLOT_STRIDE)).cast::<u32>()), 0);
            }
        }
    }
}
