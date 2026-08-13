//! `stream_context_reset_and_notify` — original: `FUN_08004ccc` @
//! `0x08004ccc` (40 bytes).
//!
//! # Algorithm
//!
//! The media-startup coordinator at `0x080056d0` receives the active stream
//! context in `r0` from the preceding framework call. This helper first enters
//! the stream-reset continuation through the `0x080036d0` veneer (target
//! `0x080746ec`) with the context's embedded stream state at `+0x44`. It then
//! clears the context's one-byte reset-pending flag at `+0x05` and tail-enters
//! the paired stream notification continuation through `0x080036d8` (target
//! `0x080747c8`) with that same embedded state. Both target addresses land
//! inside a recovered renderer sequence and inherit its unliftable framework
//! register/stack context, so the ARM implementation retains literal veneers;
//! host builds expose the two observable calls as a seam.
//!
//! Deliberate host deviation: the target continuations are entered through
//! their retail veneers, whereas host tests call replaceable ordinary C ABI
//! hooks. The context remains an opaque byte-addressed allocation so its
//! 32-bit firmware offsets are preserved on 64-bit hosts.

/// Offset of the reset-pending byte in the owning stream context.
pub const RESET_PENDING_OFFSET: usize = 0x05;
/// Offset of the embedded stream state passed to both continuations.
pub const STREAM_STATE_OFFSET: usize = 0x44;

/// ABI of each recovered stream continuation.
pub type StreamStateContinuation = unsafe extern "C" fn(stream_state: *mut u8);

/// The two continuation edges observable from this wrapper.
#[derive(Clone, Copy)]
pub struct StreamContextResetNotifyOps {
    /// Retail veneer `0x080036d0`, literal target `0x080746ec`.
    pub reset_stream_state: StreamStateContinuation,
    /// Retail veneer `0x080036d8`, literal target `0x080747c8`.
    pub notify_stream_state: StreamStateContinuation,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_stream_state_continuation(_stream_state: *mut u8) {}

/// Host default before the recovered renderer continuations are ported.
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_STREAM_CONTEXT_RESET_NOTIFY_OPS: StreamContextResetNotifyOps =
    StreamContextResetNotifyOps {
        reset_stream_state: missing_stream_state_continuation,
        notify_stream_state: missing_stream_state_continuation,
    };

/// Host replacement for the two otherwise stack-sensitive retail continuations.
#[cfg(not(target_arch = "arm"))]
pub static mut STREAM_CONTEXT_RESET_NOTIFY_OPS: StreamContextResetNotifyOps =
    DEFAULT_STREAM_CONTEXT_RESET_NOTIFY_OPS;

/// Reads the host seam without allowing LLVM to fold its default callbacks.
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn stream_context_reset_notify_ops() -> StreamContextResetNotifyOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STREAM_CONTEXT_RESET_NOTIFY_OPS))
}

/// Resets and notifies an embedded stream state — original: `FUN_08004ccc` @
/// `0x08004ccc` (40 bytes).
///
/// Calls the reset continuation with `stream_context + 0x44`, clears the
/// reset-pending byte at `stream_context + 0x05`, then calls the notification
/// continuation with the same pointer.
///
/// # Safety
///
/// `stream_context` must point to a writable context containing byte `+0x05`
/// and an embedded stream state beginning at `+0x44`. Installed host callbacks
/// must accept that embedded-state pointer.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_context_reset_and_notify(stream_context: *mut u8) {
    let stream_state = stream_context.add(STREAM_STATE_OFFSET);
    let ops = stream_context_reset_notify_ops();
    (ops.reset_stream_state)(stream_state);
    core::ptr::write_volatile(stream_context.add(RESET_PENDING_OFFSET), 0);
    (ops.notify_stream_state)(stream_state);
}

// The callback targets are renderer-continuation entries, not independently
// callable C functions: preserving the stock veneer/tail-transfer sequence is
// required for their inherited framework state.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl stream_context_reset_and_notify
    .type stream_context_reset_and_notify, %function
stream_context_reset_and_notify:
    push    {{r4, lr}}
    mov     r4, r0
    add     r0, r0, #0x44
    bl      retail_stream_state_reset
    mov     r0, #0
    strb    r0, [r4, #5]
    add     r0, r4, #0x44
    pop     {{r4, lr}}
    b       retail_stream_state_notify
    .size stream_context_reset_and_notify, . - stream_context_reset_and_notify

retail_stream_state_reset:
    ldr     pc, [pc, #-4]
    .word   0x080746ec

retail_stream_state_notify:
    ldr     pc, [pc, #-4]
    .word   0x080747c8
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ORDER: [u8; 2] = [0; 2];
    static mut CALL_COUNT: usize = 0;
    static mut RESET_ARGUMENT: *mut u8 = core::ptr::null_mut();
    static mut NOTIFY_ARGUMENT: *mut u8 = core::ptr::null_mut();
    static mut FLAG_SEEN_BY_RESET: u8 = 0;
    static mut FLAG_SEEN_BY_NOTIFY: u8 = 0;
    static mut ACTIVE_CONTEXT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_reset(stream_state: *mut u8) {
        ORDER[CALL_COUNT] = 1;
        CALL_COUNT += 1;
        RESET_ARGUMENT = stream_state;
        FLAG_SEEN_BY_RESET = core::ptr::read_volatile(ACTIVE_CONTEXT.add(RESET_PENDING_OFFSET));
    }

    unsafe extern "C" fn record_notify(stream_state: *mut u8) {
        ORDER[CALL_COUNT] = 2;
        CALL_COUNT += 1;
        NOTIFY_ARGUMENT = stream_state;
        FLAG_SEEN_BY_NOTIFY = core::ptr::read_volatile(ACTIVE_CONTEXT.add(RESET_PENDING_OFFSET));
    }

    fn install_recorders(context: *mut u8) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(ORDER).write([0; 2]);
            addr_of_mut!(CALL_COUNT).write(0);
            addr_of_mut!(RESET_ARGUMENT).write(core::ptr::null_mut());
            addr_of_mut!(NOTIFY_ARGUMENT).write(core::ptr::null_mut());
            addr_of_mut!(FLAG_SEEN_BY_RESET).write(0);
            addr_of_mut!(FLAG_SEEN_BY_NOTIFY).write(0);
            addr_of_mut!(ACTIVE_CONTEXT).write(context);
            addr_of_mut!(STREAM_CONTEXT_RESET_NOTIFY_OPS).write(StreamContextResetNotifyOps {
                reset_stream_state: record_reset,
                notify_stream_state: record_notify,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(STREAM_CONTEXT_RESET_NOTIFY_OPS)
                .write(DEFAULT_STREAM_CONTEXT_RESET_NOTIFY_OPS);
            addr_of_mut!(ACTIVE_CONTEXT).write(core::ptr::null_mut());
        }
        drop(guard);
    }

    #[test]
    fn resets_then_clears_then_notifies_the_embedded_stream_state() {
        let mut context = [0xa5u8; STREAM_STATE_OFFSET + 16];
        context[RESET_PENDING_OFFSET] = 0x7e;
        let guard = install_recorders(context.as_mut_ptr());

        unsafe { stream_context_reset_and_notify(context.as_mut_ptr()) };

        unsafe {
            assert_eq!(addr_of!(ORDER).read(), [1, 2]);
            assert_eq!(addr_of!(CALL_COUNT).read(), 2);
            assert_eq!(
                addr_of!(RESET_ARGUMENT).read(),
                context.as_mut_ptr().add(STREAM_STATE_OFFSET)
            );
            assert_eq!(
                addr_of!(NOTIFY_ARGUMENT).read(),
                context.as_mut_ptr().add(STREAM_STATE_OFFSET)
            );
            assert_eq!(addr_of!(FLAG_SEEN_BY_RESET).read(), 0x7e);
            assert_eq!(addr_of!(FLAG_SEEN_BY_NOTIFY).read(), 0);
        }
        assert_eq!(context[RESET_PENDING_OFFSET], 0);
        assert_eq!(context[RESET_PENDING_OFFSET - 1], 0xa5);
        assert_eq!(context[RESET_PENDING_OFFSET + 1], 0xa5);
        restore_default(guard);
    }

    #[test]
    fn records_the_retail_veneer_targets() {
        assert_eq!(STREAM_STATE_OFFSET, 0x44);
        assert_eq!(RESET_PENDING_OFFSET, 0x05);
    }
}
