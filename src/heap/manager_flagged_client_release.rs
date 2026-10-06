//! Release one manager flagged-client count under its notification mutex.
//!
//! `FUN_0818ac5c` @ `0x0818ac5c`: 76 bytes, true extent
//! `[0x0818ac5c, 0x0818aca8)`, followed by an independent push prologue.
//! Raw A32 verifies 2 plain BLs, 2 predicated BLs (BLEQ drain, BLNE panic),
//! one tail B to mutex unlock, and 2 incoming plain BLs, no predicated callers.
//! Lock manager+0x180 (ignore status), decrement the unsigned count at +0x1c0
//! only if nonzero, drain context+0x19c only on the 1->0 transition, then
//! compare a fresh flagged-client list count with the stored counter. A
//! mismatch is fatal without unlocking; otherwise return the unlock status.
//!
//! Deliberate deviations: use canonical Rust ports for the verified lock,
//! drain, count and panic callees and the unlock tail alias. The repr(C)
//! manager prefix widens its list pointer on hosts while preserving ARM
//! offsets. Existing callees' kernel and opaque-initializer seams apply;
//! no new production seam, validation, or error recovery is introduced.

use core::ptr::{addr_of_mut, read_volatile, write_volatile};
use crate::cxx::opaque_context_drain::drain_opaque_context;
use crate::heap::manager_client_find::ManagerClientList;
use crate::heap::manager_flagged_client_count::manager_flagged_client_count;
use crate::heap::veneers::heap_panic;
use crate::kernel::posix_mutex::{PosixMutex, posix_mutex_lock, posix_mutex_unlock};

/// Manager prefix through the flagged-client counter; padding is target words.
#[repr(C)]
pub struct ManagerFlaggedClients {
    pub clients: ManagerClientList,
    pub reserved_2c: [u32; 85],
    pub mutex: PosixMutex,
    pub reserved_198: u32,
    pub pending_context: [u32; 3],
    pub reserved_1a8: [u32; 6],
    pub flagged_count: u32,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(ManagerFlaggedClients, mutex) == 0x180);
    assert!(core::mem::offset_of!(ManagerFlaggedClients, pending_context) == 0x19c);
    assert!(core::mem::offset_of!(ManagerFlaggedClients, flagged_count) == 0x1c0);
};

#[inline(always)]
unsafe fn release_with(
    manager: *mut ManagerFlaggedClients,
    mut lock: impl FnMut(*mut PosixMutex) -> u32,
    mut drain: impl FnMut(*mut u32) -> u32,
    mut count: impl FnMut(*mut ManagerClientList) -> u32,
    mut verify: impl FnMut(u32, u32),
    mut unlock: impl FnMut(*mut PosixMutex) -> u32,
) -> u32 {
    let mutex = addr_of_mut!((*manager).mutex);
    lock(mutex);
    let counter = addr_of_mut!((*manager).flagged_count);
    let held = read_volatile(counter);
    if held != 0 {
        write_volatile(counter, held - 1);
        if held == 1 {
            drain(addr_of_mut!((*manager).pending_context).cast());
        }
    }
    let actual = count(addr_of_mut!((*manager).clients));
    verify(actual, read_volatile(counter));
    unlock(mutex)
}

/// # Safety
/// Manager storage, circular client list, mutex and pending context must satisfy
/// their respective callees' contracts. The caller must own the synchronization
/// needed to change client flags consistently with this counter decrement.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn manager_flagged_client_release(manager: *mut ManagerFlaggedClients) -> u32 {
    release_with(manager,
        |mutex| posix_mutex_lock(mutex),
        |context| drain_opaque_context(context),
        |clients| manager_flagged_client_count(clients),
        |actual, stored| { if actual != stored { heap_panic(); } },
        |mutex| posix_mutex_unlock(mutex))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::Cell;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn unsigned_decrement_saturates_at_zero_and_drains_only_last_release() {
        for held in [0, 1, 2, 0x8000_0000, u32::MAX] {
            let mut manager: ManagerFlaggedClients = unsafe { core::mem::zeroed() };
            manager.flagged_count = held;
            manager.reserved_198 = 0xaabb_ccdd;
            let expected = held.saturating_sub(1);
            let drained = Cell::new(false);
            unsafe {
                assert_eq!(release_with(&mut manager,
                    |_| 17, // Failed lock status is deliberately ignored.
                    |_| { drained.set(true); 23 }, // Drain status is ignored too.
                    |_| expected,
                    |actual, stored| assert_eq!(actual, stored),
                    |_| 31), 31);
            }
            assert_eq!(manager.flagged_count, expected);
            assert_eq!(drained.get(), held == 1);
            assert_eq!(manager.reserved_198, 0xaabb_ccdd);
        }
    }

    #[test]
    fn reloads_counter_after_list_count_and_does_not_unlock_on_mismatch() {
        let mut manager: ManagerFlaggedClients = unsafe { core::mem::zeroed() };
        manager.flagged_count = 2;
        let counter = addr_of_mut!(manager.flagged_count);
        unsafe {
            assert_eq!(release_with(&mut manager, |_| 0, |_| panic!("not last"),
                |_| { counter.write(7); 7 },
                |actual, stored| assert_eq!(actual, stored), |_| 9), 9);
        }
        let unlocked = Cell::new(false);
        let result = catch_unwind(AssertUnwindSafe(|| unsafe {
            release_with(&mut manager, |_| 0, |_| panic!("not last"),
                |_| 0, |actual, stored| assert_eq!(actual, stored),
                |_| { unlocked.set(true); 0 })
        }));
        assert!(result.is_err());
        assert_eq!(manager.flagged_count, 6);
        assert!(!unlocked.get());
    }
}
