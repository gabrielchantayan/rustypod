//! Event-loop callback dispatch boundary.
//!
//! The retailOS veneer at 0x08003900 jumps into unported event-loop
//! machinery. Keeping that target behind a volatile operation slot makes the
//! field forwarding observable on hosts while the ARM implementation keeps the
//! literal veneer and tail-dispatch ABI intact.

/// Instruction word and literal target in the fixed dispatch veneer at
/// 0x08003900.
pub const EVENT_LOOP_CALLBACK_DISPATCH_INSN: u32 = 0xe51f_f004;
pub const EVENT_LOOP_CALLBACK_DISPATCH_TARGET: u32 = 0x0818_c528;

/// ABI of the unported tail target reached through the 0x08003900 veneer.
pub type EventLoopCallbackDispatchFn = unsafe extern "C" fn(callback: u32) -> u32;

/// Host/target dispatch boundary for the unported callback target.
#[derive(Clone, Copy)]
pub struct EventLoopCallbackDispatchOps {
    /// Processes the 32-bit callback word loaded from source +0x20.
    pub dispatch: EventLoopCallbackDispatchFn,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_event_loop_callback_dispatch(_callback: u32) -> u32 {
    0
}

/// Host default until the 0x08003900 veneer target is ported.
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_EVENT_LOOP_CALLBACK_DISPATCH_OPS: EventLoopCallbackDispatchOps =
    EventLoopCallbackDispatchOps {
        dispatch: missing_event_loop_callback_dispatch,
    };

/// Host-side target seam. Tests replace this with a recording dispatcher.
#[cfg(not(target_arch = "arm"))]
pub static mut EVENT_LOOP_CALLBACK_DISPATCH_OPS: EventLoopCallbackDispatchOps =
    DEFAULT_EVENT_LOOP_CALLBACK_DISPATCH_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn event_loop_callback_dispatch() -> EventLoopCallbackDispatchFn {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(EVENT_LOOP_CALLBACK_DISPATCH_OPS.dispatch))
    }
}

/// dispatch_event_loop_callback — original: `FUN_080074e8` @ 0x080074e8
/// (12 bytes).
///
/// Loads the 32-bit callback word at `source + 0x20` and tail-dispatches it
/// through the 0x08003900 literal veneer to 0x0818c528. The target's r0
/// result is forwarded unchanged; the recovered event-loop callers use zero
/// as the "not ready" result and retry their polling loop.
///
/// The target build is the original `ldr; b` wrapper plus the literal veneer.
/// Host builds use [`EVENT_LOOP_CALLBACK_DISPATCH_OPS`] because the retailOS
/// target address is not executable there.
///
/// # Safety
///
/// `source` must be non-null and valid for an aligned 32-bit read at +0x20.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_event_loop_callback(source: *const u8) -> u32 {
    let callback = source.add(0x20).cast::<u32>().read();
    event_loop_callback_dispatch()(callback)
}

// The target wrapper and its literal veneer are one assembly fragment so the
// dispatch remains an actual tail branch rather than a Rust call/return.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl dispatch_event_loop_callback
    .type dispatch_event_loop_callback, %function
dispatch_event_loop_callback:
    ldr     r0, [r0, #0x20]
    b       retail_event_loop_callback_dispatch
    .size dispatch_event_loop_callback, . - dispatch_event_loop_callback

retail_event_loop_callback_dispatch:
    ldr     pc, [pc, #-4]
    .word   0x0818c528
    .size retail_event_loop_callback_dispatch, . - retail_event_loop_callback_dispatch
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RECORDED_CALLBACK: u32 = 0;

    unsafe extern "C" fn record_dispatch(callback: u32) -> u32 {
        CALLS += 1;
        RECORDED_CALLBACK = callback;
        0xc001_c0de
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(RECORDED_CALLBACK).write(0);
            addr_of_mut!(EVENT_LOOP_CALLBACK_DISPATCH_OPS).write(EventLoopCallbackDispatchOps {
                dispatch: record_dispatch,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(EVENT_LOOP_CALLBACK_DISPATCH_OPS)
                .write(DEFAULT_EVENT_LOOP_CALLBACK_DISPATCH_OPS);
        }
        drop(guard);
    }

    #[test]
    fn forwards_only_the_callback_word_at_offset_20_and_the_target_result() {
        let guard = install_recorder();
        let mut source = [0u32; 9];
        source[0] = 0xaaaa_aaaa;
        source[7] = 0xbbbb_bbbb;
        source[8] = 0x1234_5678;

        let result = unsafe { dispatch_event_loop_callback(source.as_ptr().cast()) };

        unsafe {
            assert_eq!(addr_of!(CALLS).read(), 1);
            assert_eq!(addr_of!(RECORDED_CALLBACK).read(), 0x1234_5678);
        }
        assert_eq!(result, 0xc001_c0de, "tail target result is forwarded unchanged");
        restore_default(guard);
    }

    #[test]
    fn default_target_returns_zero_after_the_same_field_load() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(EVENT_LOOP_CALLBACK_DISPATCH_OPS)
                .write(DEFAULT_EVENT_LOOP_CALLBACK_DISPATCH_OPS);
        }
        let mut source = [0u32; 9];
        source[8] = 0xdead_beef;

        assert_eq!(
            unsafe { dispatch_event_loop_callback(source.as_ptr().cast()) },
            0,
            "unported target default has the event-loop retry result"
        );
        drop(guard);
    }

    #[test]
    fn records_the_fixed_veneer_encoding() {
        assert_eq!(EVENT_LOOP_CALLBACK_DISPATCH_INSN, 0xe51f_f004);
        assert_eq!(EVENT_LOOP_CALLBACK_DISPATCH_TARGET, 0x0818_c528);
        assert_eq!(EVENT_LOOP_CALLBACK_DISPATCH_TARGET & 3, 0);
    }
}
