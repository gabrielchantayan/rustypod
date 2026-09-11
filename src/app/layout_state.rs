//! Layout-state activation/deactivation helpers for the unnamed embedded-timer
//! object selected by the media-layout controller.
//!
//! `deactivate_layout_state` — original: `FUN_081a221c` @ **0x081a221c**
//! (**56 bytes exactly**, `0x081a221c..0x081a2254`). The sibling method opens
//! with `push {r4, lr}` at `0x081a2254`; there is no literal pool.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds **10 direct `bl`
//! callers**: one unconditional `bl` at `0x0821c668` and nine caller-gated
//! `blne` sites (`0x08216818`, `0x08216878`, `0x08217650`, `0x082176d4`,
//! `0x0821cfd4`, `0x0821db50`, `0x0821deec`, `0x0821fa28`, `0x0821fce0`). A
//! further `bne` tail transfer at `0x0821f494` reaches the entry. No aligned
//! data word in the image holds this address, so it is not virtually
//! dispatched. The caller-side predicates gate the action; the body itself
//! has no flag or NULL guard.
//!
//! ## Algorithm
//!
//! Lock `this + 0x74`, call `FUN_081a2158(this, 0)` to propagate the disabled
//! state, stop the embedded timer at `this + 0x30`, clear `this + 0x70`, then
//! unlock. The stores and both calls are unconditional.
//!
//! ## Deliberate deviations
//!
//! `mutex_lock`, `timer_stop`, and `mutex_unlock` are already ported and are
//! called directly on target. `FUN_081a2158` is not in `names.yaml`, so it is
//! represented by a volatile dispatch seam: target builds call its verified
//! firmware address and host tests install a recorder. Host builds make the
//! outer mutex calls no-ops because this is a 32-bit embedded mutex at offset
//! `0x74`, which is necessarily misaligned for Rust's 64-bit-host `Mutex`;
//! this does not affect target code.

use core::ptr;

use crate::drivers::timer::timer_stop;
#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const TIMER_OFFSET: usize = 0x30;
const ACTIVE_OFFSET: usize = 0x70;
const MUTEX_OFFSET: usize = 0x74;

/// Unported direct callee `FUN_081a2158`.
pub const LAYOUT_STATE_SET_ENABLED_ADDRESS: usize = 0x081a_2158;

/// Dispatch slot for the unported layout-state propagation method.
#[derive(Clone, Copy)]
pub struct LayoutStateOps {
    /// Propagates `enabled` through this object's dependent layout objects.
    pub set_enabled: unsafe extern "C" fn(this: *mut u8, enabled: u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_set_enabled(this: *mut u8, enabled: u32) {
    let f: unsafe extern "C" fn(*mut u8, u32) =
        unsafe { core::mem::transmute(LAYOUT_STATE_SET_ENABLED_ADDRESS) };
    unsafe { f(this, enabled) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_set_enabled(_this: *mut u8, _enabled: u32) {
    panic!("deactivate_layout_state requires firmware callee 0x081a2158")
}

#[cfg(target_os = "none")]
pub static mut LAYOUT_STATE_OPS: LayoutStateOps = LayoutStateOps {
    set_enabled: firmware_set_enabled,
};

#[cfg(not(target_os = "none"))]
pub static mut LAYOUT_STATE_OPS: LayoutStateOps = LayoutStateOps {
    set_enabled: missing_set_enabled,
};

#[inline(always)]
fn layout_state_ops() -> LayoutStateOps {
    unsafe { ptr::addr_of!(LAYOUT_STATE_OPS).read_volatile() }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lock_layout_mutex(this: *mut u8) {
    unsafe { mutex_lock(this.add(MUTEX_OFFSET).cast::<Mutex>()) };
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lock_layout_mutex(_this: *mut u8) {}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlock_layout_mutex(this: *mut u8) {
    unsafe { mutex_unlock(this.add(MUTEX_OFFSET).cast::<Mutex>()) };
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn unlock_layout_mutex(_this: *mut u8) {}

/// `deactivate_layout_state` — original: `FUN_081a221c` @ **0x081a221c**
/// (56 bytes; 10 direct `bl` callers: 1 `bl` and 9 `blne`, plus one `bne`
/// tail transfer).
///
/// Disables this layout state under its embedded mutex: propagates literal
/// zero, stops the embedded timer, then clears the active byte. It has no
/// null or active-state guard, exactly as retailOS.
///
/// # Safety
///
/// `this` must point to a writable, target-layout object through its mutex at
/// `+0x74`; its embedded timer at `+0x30` must be initialized. The installed
/// `LAYOUT_STATE_OPS.set_enabled` slot must be callable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn deactivate_layout_state(this: *mut u8) {
    unsafe { lock_layout_mutex(this) };
    let set_enabled = layout_state_ops().set_enabled;
    unsafe { set_enabled(this, 0) };
    unsafe { timer_stop(this.add(TIMER_OFFSET)) };
    unsafe { this.add(ACTIVE_OFFSET).write_volatile(0) };
    unsafe { unlock_layout_mutex(this) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::TIMER_OPS_TEST_LOCK;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    const OBJECT_BYTES: usize = 0x84;
    const TIMER_STATE_OFFSET: usize = 0x20;

    #[repr(align(8))]
    struct LayoutStateObject([u8; OBJECT_BYTES]);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        TimerStop(usize),
        SetEnabled(usize, u32),
    }

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());

    unsafe extern "C" fn recording_trace(timer: *mut u8) {
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Call::TimerStop(timer as usize));
    }

    unsafe extern "C" fn recording_set_enabled(this: *mut u8, enabled: u32) {
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Call::SetEnabled(this as usize, enabled));
    }

    struct TimerOpsRestore(TimerOps);

    impl Drop for TimerOpsRestore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.0) };
        }
    }

    struct LayoutStateOpsRestore(LayoutStateOps);

    impl Drop for LayoutStateOpsRestore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(LAYOUT_STATE_OPS).write_volatile(self.0) };
        }
    }

    unsafe fn install_recorders() -> (TimerOpsRestore, LayoutStateOpsRestore) {
        let saved_timer_ops = unsafe { ptr::addr_of!(TIMER_OPS).read_volatile() };
        let mut recorded_timer_ops = saved_timer_ops;
        recorded_timer_ops.trace_assert = recording_trace;
        unsafe { ptr::addr_of_mut!(TIMER_OPS).write_volatile(recorded_timer_ops) };

        let saved_layout_ops = unsafe { ptr::addr_of!(LAYOUT_STATE_OPS).read_volatile() };
        unsafe {
            ptr::addr_of_mut!(LAYOUT_STATE_OPS).write_volatile(LayoutStateOps {
                set_enabled: recording_set_enabled,
            })
        };

        (TimerOpsRestore(saved_timer_ops), LayoutStateOpsRestore(saved_layout_ops))
    }

    fn calls() -> Vec<Call> {
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn prepare_object(active: u8, timer_state: u32) -> LayoutStateObject {
        let mut object = LayoutStateObject([0; OBJECT_BYTES]);
        unsafe {
            object.0.as_mut_ptr().add(ACTIVE_OFFSET).write_volatile(active);
            object
                .0
                .as_mut_ptr()
                .add(TIMER_OFFSET + TIMER_STATE_OFFSET)
                .cast::<u32>()
                .write_volatile(timer_state);
        }
        object
    }

    fn lock_ops() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let timer_guard = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let layout_guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        (timer_guard, layout_guard)
    }

    #[test]
    fn deactivation_propagates_zero_stops_timer_then_clears_active_flag() {
        let _guards = lock_ops();
        let mut object = prepare_object(0xff, TIMER_STATE_RUNNING);
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        unsafe {
            let _restore = install_recorders();
            let this = object.0.as_mut_ptr();

            deactivate_layout_state(this);

            assert_eq!(
                calls(),
                std::vec![Call::SetEnabled(this as usize, 0), Call::TimerStop(this.add(TIMER_OFFSET) as usize)],
                "retailOS propagates the disabled state before stopping its timer"
            );
            assert_eq!(
                this.add(TIMER_OFFSET + TIMER_STATE_OFFSET).cast::<u32>().read_volatile(),
                TIMER_STATE_STOPPED,
                "the embedded timer reaches timer_stop"
            );
            assert_eq!(this.add(ACTIVE_OFFSET).read_volatile(), 0);
        }
    }

    #[test]
    fn deactivation_is_unconditional_when_already_inactive_and_stopped() {
        let _guards = lock_ops();
        let mut object = prepare_object(0, TIMER_STATE_STOPPED);
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        unsafe {
            let _restore = install_recorders();
            let this = object.0.as_mut_ptr();

            deactivate_layout_state(this);

            assert_eq!(
                calls(),
                std::vec![Call::SetEnabled(this as usize, 0), Call::TimerStop(this.add(TIMER_OFFSET) as usize)],
                "the original has no active-state guard"
            );
            assert_eq!(this.add(ACTIVE_OFFSET).read_volatile(), 0);
            assert_eq!(
                this.add(TIMER_OFFSET + TIMER_STATE_OFFSET).cast::<u32>().read_volatile(),
                TIMER_STATE_STOPPED
            );
        }
    }
}
