//! First event-handler dispatch boundary.
//!
//! The retailOS veneer at 0x08003930 jumps into unported event machinery.
//! Keeping it behind this volatile operation slot preserves the original's
//! tail-dispatch boundary while making host behavior observable.

/// ABI of the unported tail target reached through the 0x08003930 veneer.
pub type FirstEventDispatchFn = unsafe extern "C" fn(handler: u32, event: u32) -> u32;

/// Indirect target for [`dispatch_first_event_handler`].
#[derive(Clone, Copy)]
pub struct FirstEventDispatchOps {
    /// Processes `event` with the handler word stored at source + 0x20.
    pub dispatch: FirstEventDispatchFn,
}

unsafe extern "C" fn missing_first_event_dispatch(_handler: u32, _event: u32) -> u32 {
    0
}

/// Default until the retailOS 0x08003930 target is ported.
pub const DEFAULT_FIRST_EVENT_DISPATCH_OPS: FirstEventDispatchOps = FirstEventDispatchOps {
    dispatch: missing_first_event_dispatch,
};

/// Tail-target boundary. Host tests temporarily install a recorder.
pub static mut FIRST_EVENT_DISPATCH_OPS: FirstEventDispatchOps = DEFAULT_FIRST_EVENT_DISPATCH_OPS;

#[inline(always)]
fn first_event_dispatch() -> FirstEventDispatchFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(FIRST_EVENT_DISPATCH_OPS.dispatch))
    }
}

/// dispatch_first_event_handler — original: `FUN_080076cc` @ 0x080076cc
/// (8 bytes).
///
/// Loads the first handler word from `source + 0x20` and tail-dispatches it
/// through the 0x08003930 veneer, preserving the caller's event word in r1
/// and returning the target's r0 result unchanged. The veneer currently
/// reaches unported code, so [`FIRST_EVENT_DISPATCH_OPS`] supplies its target
/// default and host-test seam.
///
/// # Safety
///
/// `source` must be non-null and valid for an aligned 32-bit read at +0x20.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_first_event_handler(source: *const u8, event: u32) -> u32 {
    let handler = source.add(0x20).cast::<u32>().read();
    first_event_dispatch()(handler, event)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RECORDED_HANDLER: u32 = 0;
    static mut RECORDED_EVENT: u32 = 0;

    unsafe extern "C" fn record_dispatch(handler: u32, event: u32) -> u32 {
        CALLS += 1;
        RECORDED_HANDLER = handler;
        RECORDED_EVENT = event;
        0xfeed_c0de
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(RECORDED_HANDLER).write(0);
            addr_of_mut!(RECORDED_EVENT).write(0);
            addr_of_mut!(FIRST_EVENT_DISPATCH_OPS).write(FirstEventDispatchOps {
                dispatch: record_dispatch,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(FIRST_EVENT_DISPATCH_OPS).write(DEFAULT_FIRST_EVENT_DISPATCH_OPS);
        }
        drop(guard);
    }

    #[test]
    fn loads_the_handler_word_at_offset_20_and_forwards_the_event_and_result() {
        let guard = install_recorder();
        let mut source = [0u32; 9];
        source[0] = 0xaaaa_aaaa;
        source[7] = 0xbbbb_bbbb;
        source[8] = 0x1234_5678;

        let result = unsafe { dispatch_first_event_handler(source.as_ptr().cast(), 1) };

        unsafe {
            assert_eq!(addr_of!(CALLS).read(), 1);
            assert_eq!(addr_of!(RECORDED_HANDLER).read(), 0x1234_5678);
            assert_eq!(addr_of!(RECORDED_EVENT).read(), 1);
        }
        assert_eq!(result, 0xfeed_c0de, "tail target result is returned unchanged");
        restore_default(guard);
    }

    #[test]
    fn default_target_returns_zero_after_the_same_field_load_contract() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(FIRST_EVENT_DISPATCH_OPS).write(DEFAULT_FIRST_EVENT_DISPATCH_OPS);
        }
        let mut source = [0u32; 9];
        source[8] = 0xdead_beef;

        assert_eq!(
            unsafe { dispatch_first_event_handler(source.as_ptr().cast(), 0x22) },
            0,
            "unported target default has the target's zero-result contract"
        );
        drop(guard);
    }
}
