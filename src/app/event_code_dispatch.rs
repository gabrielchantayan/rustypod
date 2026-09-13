//! `event_code_dispatch_unflagged` — original: `FUN_080873f0` @ `0x080873f0`
//! (8 bytes: `mov r1,#0; mov r0,r0`).
//!
//! # Verified call sites
//!
//! Decoding every ARM `B`/`BL`-immediate word in `osos.dec` finds seven
//! direct `bl` callers: six unconditional (`0x080fac50`, `0x080fc7a0`,
//! `0x080fc7c4`, `0x08149100`, `0x081e2340`, and `0x083934d4`) and one
//! `bleq` (`0x0814911c`). The conditional call is gated by its caller; this
//! wrapper itself has no guard. Four additional unconditional tail `b`
//! transfers (`0x0809eab4`, `0x080c6924`, `0x0811f814`, and `0x081e2324`)
//! enter this wrapper. No aligned DATA word in the image points at this entry.
//!
//! # Algorithm
//!
//! Sets the shared worker's second argument to zero, then falls through to
//! the separately linked body at `0x080873f8`. That 88-byte worker maps the
//! supplied event code through unported `FUN_080e4d44`, waits for byte `+2`
//! of the object at `0x089ca864` to become nonzero (sleeping one RTXC tick per
//! unsuccessful poll), then calls unported `FUN_08064820` with the mapped
//! code and this zero flag. The worker's higher-level identity is not inferred
//! here; this port covers only the verified unflagged entry ABI.
//!
//! # Deliberate deviation
//!
//! A payload cannot fall through into retailOS, so ARM builds use a literal
//! tail veneer after setting `r1 = 0`. Host builds use a volatile callback
//! seam for the unported worker; it proves that zero, unknown, and otherwise
//! noncanonical input words reach the worker unchanged and with the flag
//! cleared.

/// ABI of the shared, unported worker at `0x080873f8`.
pub type EventCodeDispatchWorker = unsafe extern "C" fn(event_code: u32, flag: u32);

/// RetailOS load address of the shared worker reached by the stock fall-through.
pub const EVENT_CODE_DISPATCH_WORKER_ADDRESS: usize = 0x0808_73f8;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_event_code_dispatch_worker(_event_code: u32, _flag: u32) {}

/// Host callback replacing the retailOS worker at [`EVENT_CODE_DISPATCH_WORKER_ADDRESS`].
///
/// The volatile load preserves test installations and mirrors the target's
/// runtime tail transfer.
#[cfg(not(target_arch = "arm"))]
pub static mut EVENT_CODE_DISPATCH_WORKER: EventCodeDispatchWorker = missing_event_code_dispatch_worker;

/// Clears the worker flag while preserving the event-code word.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_code_dispatch_unflagged(event_code: u32) {
    let worker = core::ptr::read_volatile(core::ptr::addr_of!(EVENT_CODE_DISPATCH_WORKER));
    worker(event_code, 0);
}

// The retail entry falls through to the following, separately linked function.
// A payload cannot keep that adjacency, so load the worker address into pc after
// retaining the original r1 write and the ABI-neutral mov r0, r0.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl event_code_dispatch_unflagged
    .type event_code_dispatch_unflagged, %function
event_code_dispatch_unflagged:
    mov     r1, #0
    mov     r0, r0
    ldr     pc, [pc, #-4]
    .word   0x080873f8
    .size event_code_dispatch_unflagged, . - event_code_dispatch_unflagged
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static WORKER_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut EVENT_CODES: [u32; 2] = [0; 2];
    static mut FLAGS: [u32; 2] = [0; 2];

    unsafe extern "C" fn recording_event_code_dispatch_worker(event_code: u32, flag: u32) {
        let slot = CALLS as usize;
        EVENT_CODES[slot] = event_code;
        FLAGS[slot] = flag;
        CALLS += 1;
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                EVENT_CODE_DISPATCH_WORKER = missing_event_code_dispatch_worker;
                CALLS = 0;
                EVENT_CODES = [0; 2];
                FLAGS = [0; 2];
            }
        }
    }

    #[test]
    fn clears_worker_flag_without_filtering_event_codes() {
        let _lock = WORKER_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;

        unsafe {
            EVENT_CODE_DISPATCH_WORKER = recording_event_code_dispatch_worker;

            event_code_dispatch_unflagged(0);
            event_code_dispatch_unflagged(u32::MAX);

            assert_eq!(CALLS, 2, "the wrapper tail-dispatches every input");
            assert_eq!(EVENT_CODES, [0, u32::MAX]);
            assert_eq!(FLAGS, [0, 0]);
        }
    }
}
