//! `locked_handle_resolve` — original: `FUN_0828088c` @ **0x0828088c**
//! (80 bytes; five plain direct `bl` instructions and zero predicated `bl`
//! instructions).
//!
//! Raw ARM establishes the body from `0x0828088c` through `0x082808db`; the
//! next prologue begins at `0x082808dc`. Its calls are `mutex_lock_counted` @
//! `0x08094404`, the `handle_deref_or_null` alias @ `0x083d603c`, the
//! unported predicate @ `0x081375b0`, and `mutex_unlock_counted` @
//! `0x0809449c` twice. The predicate itself is recovered from raw code and
//! its C reference: it reads the resolved object's handle at `+0x54` twice,
//! and succeeds only if its second resolved target has a nonzero first word.
//!
//! # Algorithm
//!
//! Locks the owner's counted mutex at `+0x78`, resolves the handle at `+0x38`,
//! and returns that resolved object only when its nested `+0x54` handle names
//! an object whose first word is nonzero. It always releases the lock before
//! returning.
//!
//! # Deliberate deviation
//!
//! The unported predicate at `0x081375b0` is expressed as a private helper
//! rather than a dispatch seam. This preserves its two handle reads and exact
//! boolean result while keeping the port's only external calls to identified,
//! already ported callees. Host-native pointers shift struct byte offsets;
//! named `repr(C)` fields preserve the target's distinct 32-bit word fields.

use crate::cxx::handle::handle_deref_or_null;
use crate::kernel::sync_mutex::{mutex_lock_counted, mutex_unlock_counted, CountedMutex};
use core::ptr::addr_of;

#[repr(C)]
pub struct LockedHandleOwner {
    _before_handle: [u32; 0x38 / 4],
    pub handle: *const *mut u8,
    _between_handle_and_lock: [u32; (0x78 - 0x3c) / 4],
    pub lock: *mut CountedMutex,
}

#[repr(C)]
struct NestedHandleOwner {
    _before_handle: [u32; 0x54 / 4],
    handle: *const *mut u8,
}

#[inline(always)]
unsafe fn nested_handle_head_is_nonzero(object: *mut u8) -> bool {
    let nested_owner = object.cast::<NestedHandleOwner>();
    let nested_slot = unsafe { addr_of!((*nested_owner).handle) };
    let first_cell = unsafe { nested_slot.read_volatile() };
    if first_cell.is_null() || unsafe { first_cell.read_volatile() }.is_null() {
        return false;
    }

    let second_cell = unsafe { nested_slot.read_volatile() };
    let second_target = unsafe { second_cell.read_volatile() };
    unsafe { second_target.cast::<u32>().read_volatile() != 0 }
}

/// Resolves `owner.handle` while holding `owner.lock`, subject to the nested
/// handle's nonzero-head predicate.
///
/// # Safety
///
/// `owner`, its lock, and both two-level handle cells must be valid. The
/// resolved outer object must have the `NestedHandleOwner` target layout, and
/// a non-NULL resolved nested object must have a readable first word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn locked_handle_resolve(owner: *mut LockedHandleOwner) -> *mut u8 {
    let lock = unsafe { (*owner).lock };
    unsafe { mutex_lock_counted(lock) };

    let object = unsafe { handle_deref_or_null(addr_of!((*owner).handle)) };
    let result = if unsafe { nested_handle_head_is_nonzero(object) } {
        unsafe { (*owner).handle.read() }
    } else {
        core::ptr::null_mut()
    };

    unsafe { mutex_unlock_counted(lock) };
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::sync_mutex::Mutex;

    fn counted_mutex() -> CountedMutex {
        CountedMutex {
            mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
            hold_count: 0,
        }
    }

    fn owner(handle: *const *mut u8, lock: *mut CountedMutex) -> LockedHandleOwner {
        LockedHandleOwner {
            _before_handle: [0; 0x38 / 4],
            handle,
            _between_handle_and_lock: [0; (0x78 - 0x3c) / 4],
            lock,
        }
    }

    #[test]
    fn returns_outer_object_when_nested_head_is_nonzero() {
        let mut nested_target = 0xfeed_beefu32;
        let mut nested_cell = &mut nested_target as *mut u32 as *mut u8;
        let mut object = NestedHandleOwner {
            _before_handle: [0; 0x54 / 4],
            handle: &mut nested_cell,
        };
        let mut outer_cell = &mut object as *mut NestedHandleOwner as *mut u8;
        let mut lock = counted_mutex();
        let mut owner = owner(&mut outer_cell, &mut lock);

        let result = unsafe { locked_handle_resolve(&mut owner) };

        assert_eq!(result, &mut object as *mut NestedHandleOwner as *mut u8);
        assert_eq!(lock.hold_count, 0);
    }

    #[test]
    fn rejects_null_or_zero_head_nested_handle_and_unlocks() {
        let mut zero_target = 0u32;
        let mut zero_cell = &mut zero_target as *mut u32 as *mut u8;
        let mut object = NestedHandleOwner {
            _before_handle: [0; 0x54 / 4],
            handle: &mut zero_cell,
        };
        let mut outer_cell = &mut object as *mut NestedHandleOwner as *mut u8;
        let mut lock = counted_mutex();
        let mut owner = owner(&mut outer_cell, &mut lock);

        assert!(unsafe { locked_handle_resolve(&mut owner) }.is_null());
        assert_eq!(lock.hold_count, 0);

        object.handle = core::ptr::null();
        assert!(unsafe { locked_handle_resolve(&mut owner) }.is_null());
        assert_eq!(lock.hold_count, 0);
    }
}
