//! State transition and notification — `FUN_080050fc` @ 0x080050fc (28 bytes).
//!
//! The record has a callback context word at +0x1c, its current state byte at
//! +0x20, and its previous-state byte at +0x21. The routine snapshots the
//! current state into the previous-state field unless that state is the special
//! value 2, writes the requested state, then tail-calls the notification
//! callback through the literal veneer at 0x0800371c with the context word.
//! The callback target is runtime-installed firmware code (0x080ea6ec), so the
//! target default calls it directly while host tests install a recording seam.

/// Record offset holding the word passed to the notification callback.
const CALLBACK_CONTEXT: usize = 0x1c;
/// Record offset holding the active state byte.
const CURRENT_STATE: usize = 0x20;
/// Record offset holding the prior state byte.
const PREVIOUS_STATE: usize = 0x21;
/// State whose transition must not overwrite the prior-state byte.
const PRESERVE_PREVIOUS_STATE: u8 = 2;
/// Target held by the literal veneer at 0x0800371c.
const ROM_STATE_NOTIFICATION: usize = 0x080e_a6ec;

/// ABI of the unported state-notification callback.
pub type StateNotificationFn = unsafe extern "C" fn(context: u32);

/// Runtime integration seam for the notification callback.
#[derive(Clone, Copy)]
pub struct StateTransitionOps {
    pub notify_state_change: StateNotificationFn,
}

unsafe extern "C" fn rom_notify_state_change(context: u32) {
    let callback: StateNotificationFn = core::mem::transmute(ROM_STATE_NOTIFICATION);
    callback(context);
}

/// Direct-ROM default; host tests replace this callback before calling the port.
pub static mut STATE_TRANSITION_OPS: StateTransitionOps = StateTransitionOps {
    notify_state_change: rom_notify_state_change,
};

#[inline(always)]
unsafe fn state_transition_ops() -> StateTransitionOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STATE_TRANSITION_OPS))
}

/// set_state_and_notify — original: `FUN_080050fc` @ 0x080050fc (28 bytes).
///
/// Store `new_state` in `record`'s current-state byte. Unless the old current
/// state is 2, first copy it to the previous-state byte. Then call the callback
/// supplied by the 0x0800371c literal veneer with the record's context word.
/// The original performs no null or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn set_state_and_notify(record: *mut u8, new_state: u8) {
    let old_state = record.add(CURRENT_STATE).read_volatile();
    if old_state != PRESERVE_PREVIOUS_STATE {
        record.add(PREVIOUS_STATE).write_volatile(old_state);
    }
    record.add(CURRENT_STATE).write_volatile(new_state);
    let callback_context = (record.add(CALLBACK_CONTEXT) as *const u32).read_volatile();
    (state_transition_ops().notify_state_change)(callback_context);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLBACK_ARGUMENT: u32 = 0;
    static mut CALLBACK_COUNT: usize = 0;

    struct TestOps {
        _lock: MutexGuard<'static, ()>,
        saved: StateTransitionOps,
    }

    impl Drop for TestOps {
        fn drop(&mut self) {
            unsafe { STATE_TRANSITION_OPS = self.saved };
        }
    }

    fn install_recording_callback() -> TestOps {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(STATE_TRANSITION_OPS));
            STATE_TRANSITION_OPS = StateTransitionOps {
                notify_state_change: record_notification,
            };
            core::ptr::addr_of_mut!(CALLBACK_ARGUMENT).write(0);
            core::ptr::addr_of_mut!(CALLBACK_COUNT).write(0);
            TestOps { _lock: lock, saved }
        }
    }

    unsafe extern "C" fn record_notification(context: u32) {
        core::ptr::addr_of_mut!(CALLBACK_ARGUMENT).write(context);
        let count = core::ptr::addr_of!(CALLBACK_COUNT).read();
        core::ptr::addr_of_mut!(CALLBACK_COUNT).write(count + 1);
    }
    #[repr(align(4))]

    struct StateRecord {
        bytes: [u8; PREVIOUS_STATE + 1],
    }

    impl StateRecord {
        fn new(context: u32, current: u8, previous: u8) -> Self {
            let mut record = Self {
                bytes: [0xa5; PREVIOUS_STATE + 1],
            };
            record.bytes[CALLBACK_CONTEXT..CALLBACK_CONTEXT + 4]
                .copy_from_slice(&context.to_le_bytes());
            record.bytes[CURRENT_STATE] = current;
            record.bytes[PREVIOUS_STATE] = previous;
            record
        }

        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.bytes.as_mut_ptr()
        }
    }

    #[test]
    fn records_non_special_previous_state_and_notifies_with_context() {
        let _ops = install_recording_callback();
        let mut record = StateRecord::new(0x1234_5678, 7, 0xee);

        unsafe { set_state_and_notify(record.as_mut_ptr(), 9) };

        assert_eq!(record.bytes[CURRENT_STATE], 9);
        assert_eq!(record.bytes[PREVIOUS_STATE], 7);
        unsafe {
            assert_eq!(CALLBACK_COUNT, 1);
            assert_eq!(CALLBACK_ARGUMENT, 0x1234_5678);
        }
    }

    #[test]
    fn special_current_state_preserves_previous_state_and_notifies() {
        let _ops = install_recording_callback();
        let mut record = StateRecord::new(0xdead_beef, PRESERVE_PREVIOUS_STATE, 0x4c);

        unsafe { set_state_and_notify(record.as_mut_ptr(), 3) };

        assert_eq!(record.bytes[CURRENT_STATE], 3);
        assert_eq!(record.bytes[PREVIOUS_STATE], 0x4c);
        unsafe {
            assert_eq!(CALLBACK_COUNT, 1);
            assert_eq!(CALLBACK_ARGUMENT, 0xdead_beef);
        }
    }
}
