//! Application runtime-state reset.
//!
//! Original: `FUN_0819c9e0` @ 0x0819c9e0 (124 bytes exactly: 100 bytes of
//! instructions followed by six literal-pool words at 0x0819ca44..0x0819ca58;
//! the next independently linked function starts at 0x0819ca5c). Decoding
//! every ARM B/BL-immediate word in `osos.dec` finds three outbound direct
//! calls: one plain unconditional `bl` to the IRAM `memzero_aligned` veneer
//! and two predicated `bleq` calls to `timer_trace_assert`. The final `b` is a
//! tail branch through the `memzero` veneer, not a fourth call.
//!
//! # Algorithm
//!
//! If either of the two global timer objects has state `"run "` at +0x18,
//! trace/assert it. Clear bytes +2, +3, and +4 of the global runtime mutex
//! object; clear the 127 bytes after the leading word of the first global
//! buffer; then clear 127 bytes of the second global buffer.
//!
//! # Deliberate deviation
//!
//! The two retail clears enter through IRAM veneers at 0x08037db8 and
//! 0x08037dc8. This port invokes the existing Rust implementations through
//! volatile function-pointer loads, preserving calls while preventing LLVM
//! from replacing them with AEABI memory-clear builtins. Host builds model the
//! five fixed global objects as isolated statics.

use crate::drivers::timer::timer_trace_assert;
use crate::libc::memzero::{memzero, memzero_aligned};

const TIMER_STATE_RUNNING: u32 = 0x7275_6e20;
const CLEAR_LEN: usize = 0x7f;

type Memzero = unsafe extern "C" fn(*mut u8, usize) -> *mut u8;
#[cfg(not(target_os = "none"))]
#[repr(align(4))]
struct Aligned<const N: usize>([u8; N]);


static MEMZERO_ALIGNED_CALL: Memzero = memzero_aligned;
static MEMZERO_CALL: Memzero = memzero;

#[cfg(target_os = "none")]
const FIRST_TIMER: *mut u8 = 0x08a7_79d0 as *mut u8;
#[cfg(target_os = "none")]
const SECOND_TIMER: *mut u8 = 0x08a7_79f0 as *mut u8;
#[cfg(target_os = "none")]
const RUNTIME_MUTEX: *mut u8 = 0x089c_b29c as *mut u8;
#[cfg(target_os = "none")]
const FIRST_BUFFER: *mut u8 = 0x08a7_794c as *mut u8;
#[cfg(target_os = "none")]
const SECOND_BUFFER: *mut u8 = 0x08a7_7b0e as *mut u8;

#[cfg(not(target_os = "none"))]
static mut HOST_FIRST_TIMER: Aligned<0x1c> = Aligned([0; 0x1c]);
#[cfg(not(target_os = "none"))]
static mut HOST_SECOND_TIMER: Aligned<0x1c> = Aligned([0; 0x1c]);
#[cfg(not(target_os = "none"))]
static mut HOST_RUNTIME_MUTEX: Aligned<5> = Aligned([0; 5]);
#[cfg(not(target_os = "none"))]
static mut HOST_FIRST_BUFFER: Aligned<{ CLEAR_LEN + 4 }> = Aligned([0; CLEAR_LEN + 4]);
#[cfg(not(target_os = "none"))]
static mut HOST_SECOND_BUFFER: Aligned<CLEAR_LEN> = Aligned([0; CLEAR_LEN]);

#[inline(always)]
unsafe fn globals() -> (*mut u8, *mut u8, *mut u8, *mut u8, *mut u8) {
    #[cfg(target_os = "none")]
    {
        (FIRST_TIMER, SECOND_TIMER, RUNTIME_MUTEX, FIRST_BUFFER, SECOND_BUFFER)
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe {
            (
                core::ptr::addr_of_mut!(HOST_FIRST_TIMER).cast(),
                core::ptr::addr_of_mut!(HOST_SECOND_TIMER).cast(),
                core::ptr::addr_of_mut!(HOST_RUNTIME_MUTEX).cast(),
                core::ptr::addr_of_mut!(HOST_FIRST_BUFFER).cast(),
                core::ptr::addr_of_mut!(HOST_SECOND_BUFFER).cast(),
            )
        }
    }
}

/// app_runtime_state_reset — original: `FUN_0819c9e0` @ 0x0819c9e0.
///
/// Conditionally traces each running global timer, clears the three runtime
/// mutex flag bytes, and clears the two fixed 127-byte buffers. The original
/// has no NULL, alignment, or bounds guards on any fixed object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_runtime_state_reset() {
    let (first_timer, second_timer, runtime_mutex, first_buffer, second_buffer) = unsafe { globals() };

    if unsafe { first_timer.add(0x18).cast::<u32>().read_volatile() } == TIMER_STATE_RUNNING {
        unsafe { timer_trace_assert(first_timer) };
    }
    unsafe { runtime_mutex.add(2).write_volatile(0) };
    if unsafe { second_timer.add(0x18).cast::<u32>().read_volatile() } == TIMER_STATE_RUNNING {
        unsafe { timer_trace_assert(second_timer) };
    }
    unsafe {
        runtime_mutex.add(3).write_volatile(0);
        runtime_mutex.add(4).write_volatile(0);
        first_buffer.cast::<u32>().write_volatile(0);
        core::ptr::read_volatile(core::ptr::addr_of!(MEMZERO_ALIGNED_CALL))(
            first_buffer.add(4),
            CLEAR_LEN,
        );
        core::ptr::read_volatile(core::ptr::addr_of!(MEMZERO_CALL))(second_buffer, CLEAR_LEN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static GLOBALS_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn reset_globals() -> (*mut u8, *mut u8, *mut u8, *mut u8, *mut u8) {
        let globals = unsafe { globals() };
        unsafe {
            core::ptr::write_bytes(globals.0, 0, 0x1c);
            core::ptr::write_bytes(globals.1, 0, 0x1c);
            core::ptr::write_bytes(globals.2, 0xa5, 5);
            core::ptr::write_bytes(globals.3, 0xa5, CLEAR_LEN + 4);
            core::ptr::write_bytes(globals.4, 0xa5, CLEAR_LEN);
        }
        globals
    }

    #[test]
    fn clears_runtime_flags_and_both_fixed_buffers() {
        let _guard = GLOBALS_LOCK.lock();
        let (_, _, mutex, first, second) = unsafe { reset_globals() };

        unsafe { app_runtime_state_reset() };

        unsafe {
            assert_eq!(mutex.read_volatile(), 0xa5);
            assert_eq!(mutex.add(1).read_volatile(), 0xa5);
            assert_eq!(mutex.add(2).read_volatile(), 0);
            assert_eq!(mutex.add(3).read_volatile(), 0);
            assert_eq!(mutex.add(4).read_volatile(), 0);
            assert_eq!(first.cast::<u32>().read_volatile(), 0);
            assert!(core::slice::from_raw_parts(first.add(4), CLEAR_LEN).iter().all(|&byte| byte == 0));
            assert!(core::slice::from_raw_parts(second, CLEAR_LEN).iter().all(|&byte| byte == 0));
        }
    }

    #[test]
    fn accepts_running_and_nonrunning_timer_states() {
        let _guard = GLOBALS_LOCK.lock();
        let (first_timer, second_timer, _, _, _) = unsafe { reset_globals() };

        unsafe {
            first_timer.add(0x18).cast::<u32>().write_volatile(TIMER_STATE_RUNNING);
            second_timer.add(0x18).cast::<u32>().write_volatile(0x7374_6f70);
            app_runtime_state_reset();
        }
    }
}
