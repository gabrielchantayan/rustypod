//! `resource_slot_acquire` — original: `FUN_081d5c14` @ `0x081d5c14`.
//!
//! Raw `osos.dec` words establish the exact 116-byte extent
//! `0x081d5c14..0x081d5c88`: the next real function opens with
//! `push {r0-r11,lr}` at `0x081d5c88`. The body has three unconditional plain
//! `bl` instructions (`mutex_lock`, `mutex_unlock`, and `condvar_wait_forever`),
//! no predicated `bl` instructions, and one indirect `blx` through a slot's
//! object vtable.
//!
//! While holding the pool mutex at `+0x40`, scan `count` status bytes at
//! `+0x34`. Claim the first zero byte, invoke the claimed entry's vtable slot
//! `+0`, unlock, and return that entry. If every entry is busy, wait forever on
//! the condition variable at `+0x48` and retry. Deliberate deviation: host
//! builds route the otherwise unidentified virtual call through a narrow seam;
//! target builds invoke the stored target-width vtable function directly.

use crate::kernel::condvar::{condvar_wait_forever, CondVar};
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const SLOT_COUNT_OFFSET: usize = 0x00;
const SLOT_POINTERS_OFFSET: usize = 0x0c;
const SLOT_BUSY_OFFSET: usize = 0x34;
const SLOT_MUTEX_OFFSET: usize = 0x40;
const SLOT_CONDVAR_OFFSET: usize = 0x48;

pub type ResourceSlotDispatch = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_slot_dispatch(_slot: *mut u8) {
    panic!("install resource-slot acquire host dispatch before calling this port")
}

/// Host replacement for the selected slot's otherwise unidentified vtable slot.
#[cfg(not(target_os = "none"))]
pub static mut RESOURCE_SLOT_DISPATCH: ResourceSlotDispatch = missing_resource_slot_dispatch;

#[inline(always)]
unsafe fn dispatch_slot(slot: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let vtable = unsafe { (slot as *const u32).read() };
        let dispatch: unsafe extern "C" fn() = unsafe { core::mem::transmute(vtable as usize) };
        unsafe { dispatch() };
    }
    #[cfg(not(target_os = "none"))]
    {
        let dispatch = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_SLOT_DISPATCH))
        };
        unsafe { dispatch(slot) };
    }
}

/// Claims and initializes the first available resource slot.
///
/// # Safety
/// `pool` must point to the target-width pool layout described above. Its first
/// `count` words at `+0x0c` must be valid slot pointers and its associated mutex
/// and condition variable must be initialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn resource_slot_acquire(pool: *mut u8) -> *mut u8 {
    unsafe { mutex_lock(pool.add(SLOT_MUTEX_OFFSET).cast::<Mutex>()) };
    loop {
        let count = unsafe { (pool.add(SLOT_COUNT_OFFSET) as *const i32).read() };
        let mut index = 0i32;
        while index < count {
            let slot_index = index as usize;
            let busy = unsafe { pool.add(SLOT_BUSY_OFFSET + slot_index).read() };
            if busy == 0 {
                unsafe { pool.add(SLOT_BUSY_OFFSET + slot_index).write(1) };
                let slot_address = unsafe {
                    (pool.add(SLOT_POINTERS_OFFSET + slot_index * core::mem::size_of::<u32>())
                        as *const u32)
                        .read()
                };
                let slot = slot_address as usize as *mut u8;
                unsafe { dispatch_slot(slot) };
                unsafe { mutex_unlock(pool.add(SLOT_MUTEX_OFFSET).cast::<Mutex>()) };
                return slot;
            }
            index += 1;
        }
        unsafe { condvar_wait_forever(pool.add(SLOT_CONDVAR_OFFSET).cast::<CondVar>()) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex as TestMutex;
    use std::sync::LazyLock;

    static TEST_LOCK: TestMutex<()> = TestMutex::new(());
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::RESOURCE_SLOT_ACQUIRE, 0x1000).map(|pointer| pointer as usize)
    });
    static mut DISPATCHED_SLOT: usize = 0;

    unsafe extern "C" fn record_dispatch(slot: *mut u8) {
        unsafe { DISPATCHED_SLOT = slot as usize };
    }

    struct DispatchGuard(ResourceSlotDispatch);

    impl DispatchGuard {
        unsafe fn install() -> Self {
            let old = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_SLOT_DISPATCH)) };
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(RESOURCE_SLOT_DISPATCH), record_dispatch) };
            Self(old)
        }
    }

    impl Drop for DispatchGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(RESOURCE_SLOT_DISPATCH), self.0) };
        }
    }

    #[test]
    fn claims_first_free_slot_and_dispatches_it() {
        let _lock = TEST_LOCK.lock();
        let Some(pool) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/resource_slot_acquire"));
            return;
        };
        let pool = pool as *mut u8;
        unsafe {
            pool.write_bytes(0, 0x1000);
            (pool as *mut u32).write(3);
            (pool.add(SLOT_POINTERS_OFFSET) as *mut u32).write((pool.add(0x200)) as usize as u32);
            (pool.add(SLOT_POINTERS_OFFSET + 4) as *mut u32).write((pool.add(0x210)) as usize as u32);
            (pool.add(SLOT_POINTERS_OFFSET + 8) as *mut u32).write((pool.add(0x220)) as usize as u32);
            pool.add(SLOT_BUSY_OFFSET).write(1);
            DISPATCHED_SLOT = 0;
            let _dispatch = DispatchGuard::install();
            let selected = resource_slot_acquire(pool);
            assert_eq!(selected, pool.add(0x210));
            assert_eq!(pool.add(SLOT_BUSY_OFFSET + 1).read(), 1);
            assert_eq!(pool.add(SLOT_BUSY_OFFSET + 2).read(), 0);
            assert_eq!(DISPATCHED_SLOT, selected as usize);
        }
    }

    #[test]
    fn claims_slot_zero_without_scanning_later_slots() {
        let _lock = TEST_LOCK.lock();
        let Some(pool) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/resource_slot_acquire"));
            return;
        };
        let pool = pool as *mut u8;
        unsafe {
            pool.write_bytes(0, 0x1000);
            (pool as *mut u32).write(2);
            (pool.add(SLOT_POINTERS_OFFSET) as *mut u32).write((pool.add(0x240)) as usize as u32);
            (pool.add(SLOT_POINTERS_OFFSET + 4) as *mut u32).write((pool.add(0x250)) as usize as u32);
            pool.add(SLOT_BUSY_OFFSET + 1).write(1);
            DISPATCHED_SLOT = 0;
            let _dispatch = DispatchGuard::install();
            assert_eq!(resource_slot_acquire(pool), pool.add(0x240));
            assert_eq!(pool.add(SLOT_BUSY_OFFSET).read(), 1);
            assert_eq!(DISPATCHED_SLOT, pool.add(0x240) as usize);
        }
    }
}
