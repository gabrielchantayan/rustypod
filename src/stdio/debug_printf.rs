//! retailOS's diagnostic `printf` — the trace channel the drivers log
//! through.
//!
//! Port: `debug_printf` — `FUN_082bd4a8` @ 0x082bd4a8 (28 bytes,
//! 0x082bd4a8..0x082bd4c4; **48 call sites**, binary-scanned by decoding
//! every B/BL word in osos.dec: 36 `bl`, 9 `blne`, 1 `bleq`, 1 tail `b`,
//! 1 tail `beq`. No DATA word holds the address, so it is never
//! dispatched virtually).
//!
//! # Decoded from the raw ARM at 0x082bd4a8
//!
//! ```text
//! push  {r0, r1, r2, r3}   ; home the argument registers
//! push  {r4, lr}
//! ldr   r0, [sp, #8]       ; the spilled r0 — the format string
//! add   r1, sp, #12        ; &spilled r1 — the va_list
//! bl    0x08396e1c         ; the formatter
//! pop   {r4}
//! ldr   pc, [sp], #20      ; lr -> pc, dropping lr + the 4 spill words
//! ```
//!
//! Seven instructions; 0x082bd4c4 starts the next function with its own
//! `push`, and there is no literal pool. This is the textbook AAPCS
//! variadic prologue: spill r0-r3 into a frame that is contiguous with
//! the caller's stacked arguments, then call the `v`-flavored worker
//! with a pointer just past the fixed parameter. In C:
//! `int debug_printf(const char *fmt, ...) { return debug_vprintf(fmt,
//! ap); }`.
//!
//! # What it is a front end for
//!
//! The worker `FUN_08396e1c` @ 0x08396e1c (380 bytes,
//! 0x08396e1c..0x08396f98 plus a 4-byte digit-table literal; 0x08396f9c
//! starts the next function) is a **hand-rolled mini-printf that writes
//! straight to the ARM Angel semihosting console** — no FILE, no
//! buffering, no relation to the ADS `printf` family in
//! printf/printf_api.rs. `debug_printf` is its *only* caller, which is
//! why the pair reads as one function split at the varargs boundary.
//!
//! The worker scans the format for `%` and `\`, flushing each literal
//! run through `FUN_0808e2b8` (which prints the run by parking a NUL
//! over its last byte, issuing semihost `SYS_WRITE0` (op 4), then
//! emitting the saved last byte with `SYS_WRITEC` (op 3, the
//! [`crate::stdio::semihost`] wrapper @ 0x080769a0) and restoring it).
//! Conversions: an optional `0`-prefixed decimal width, an ignored `l`,
//! then `d` (signed: emit `'-'`, negate, fall into the unsigned
//! printer @ 0x080944d8), `u`, `x`/`X` (an 8-digit zero-padded hex
//! buffer built backwards in the spill frame and flushed with
//! `SYS_WRITE0`), `c` (`SYS_WRITEC` — except at width 4, where it
//! dispatches 0x0807a344, the **FourCC tag printer**, so `%4c` spells a
//! tag out), `s` (`SYS_WRITE0` on the argument), `%` (literal), and any
//! other letter degrades to a single space. It always returns 0.
//!
//! Call sites confirm the diagnostic reading: 43 of the 48 load the
//! format with `add r0, pc, #imm` — inline PC-relative string literals
//! such as `"mDS: write data CRC response error\n"` (0x08087adc, the
//! storage driver) and `"cI: card failed HS_TIMING SWITCH\n"`
//! (0x08074e14, the card driver). The ten predicated sites (9 `blne`,
//! 1 `bleq`, 1 `beq`) are callers gating a trace on a status **bitmask**
//! — e.g. `tst r4, #0x400000; addne r0, pc, #0x50; blne` — not on a
//! NULL check; this entry point has no NULL guard on the format at all.
//!
//! # Deviations
//!
//! - The `...` becomes an explicit `args: VaList` (`*const u32`), the
//!   house convention already used by printf/printf_api.rs's `sprintf` /
//!   `snprintf` and cxx/string_object.rs. That *is* what the original
//!   builds: the spill frame exists only to manufacture the pointer this
//!   signature takes directly. A variadic C caller therefore needs the
//!   same small capture trampoline printf_api.rs documents.
//! - The formatter is not ported yet, so it rides the
//!   [`DEBUG_VPRINTF`] slot: on target the default calls 0x08396e1c in
//!   place; on host it panics until a test installs one.

use crate::printf::printf_api::VaList;

/// The formatter's signature: format string plus a pointer to the first
/// variadic argument word.
pub type DebugVprintfFn = unsafe extern "C" fn(fmt: *const u8, args: VaList) -> i32;

/// Target default: the stock semihosting formatter @ 0x08396e1c.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_debug_vprintf(fmt: *const u8, args: VaList) -> i32 {
    let formatter: DebugVprintfFn = unsafe { core::mem::transmute(0x0839_6e1cusize) };
    unsafe { formatter(fmt, args) }
}

/// Host default: nothing to forward to, and silently returning 0 would
/// make a missing install look like a successful trace.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_debug_vprintf(_fmt: *const u8, _args: VaList) -> i32 {
    panic!("debug_printf requires the semihosting formatter 0x08396e1c")
}

/// The active formatter. Host tests install recording mocks.
#[cfg(target_os = "none")]
pub static mut DEBUG_VPRINTF: DebugVprintfFn = firmware_debug_vprintf;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut DEBUG_VPRINTF: DebugVprintfFn = missing_debug_vprintf;

/// Reads the formatter slot. Volatile so a build in which nothing
/// rewrites the slot cannot constant-fold the default in and delete the
/// dispatch (house rule, see stdio/semihost.rs).
#[inline(always)]
unsafe fn debug_vprintf() -> DebugVprintfFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DEBUG_VPRINTF)) }
}

/// debug_printf — original: `FUN_082bd4a8` @ 0x082bd4a8 (28 bytes;
/// 48 call sites — 36 `bl`, 9 `blne`, 1 `bleq`, 1 `b`, 1 `beq` —
/// binary-scanned).
///
/// The varargs front end of the semihosting trace formatter: hands the
/// format string and the argument list to 0x08396e1c and returns its
/// result unchanged (the formatter always reports 0). Nothing is
/// validated — a NULL format reaches the formatter exactly as in the
/// original, whose callers do their own gating.
///
/// # Safety
///
/// `fmt` and `args` must satisfy the formatter: a NUL-terminated format
/// and enough argument words for its conversions. [`DEBUG_VPRINTF`]
/// must be installed on host.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn debug_printf(fmt: *const u8, args: VaList) -> i32 {
    unsafe { (debug_vprintf())(fmt, args) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes swaps of [`DEBUG_VPRINTF`].
    static FORMATTER_LOCK: Mutex<()> = Mutex::new(());

    /// What the recording formatter saw, in order.
    static mut SEEN: Vec<(*const u8, VaList)> = Vec::new();
    /// Results the recorder returns, one per call, then repeating the last.
    static mut RESULTS: Vec<i32> = Vec::new();

    unsafe extern "C" fn recording_vprintf(fmt: *const u8, args: VaList) -> i32 {
        unsafe {
            let seen = &mut *core::ptr::addr_of_mut!(SEEN);
            seen.push((fmt, args));
            let results = &*core::ptr::addr_of!(RESULTS);
            results[(seen.len() - 1).min(results.len() - 1)]
        }
    }

    /// Restores the shipped default even when a test panics.
    struct FormatterGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl Drop for FormatterGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(DEBUG_VPRINTF).write(missing_debug_vprintf);
                (*core::ptr::addr_of_mut!(SEEN)).clear();
            }
        }
    }

    fn install(results: &[i32]) -> FormatterGuard {
        let guard = FORMATTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(SEEN)).clear();
            let slot = &mut *core::ptr::addr_of_mut!(RESULTS);
            slot.clear();
            slot.extend_from_slice(results);
            core::ptr::addr_of_mut!(DEBUG_VPRINTF).write(recording_vprintf);
        }
        FormatterGuard(guard)
    }

    fn seen() -> Vec<(*const u8, VaList)> {
        unsafe { (*core::ptr::addr_of!(SEEN)).clone() }
    }

    #[test]
    fn hands_the_format_and_argument_list_to_the_formatter_untouched() {
        let _guard = install(&[0]);
        // The stock frame is the spilled r1..r3 followed by the caller's
        // stacked arguments, i.e. one contiguous run of words.
        let arg_words: [u32; 3] = [0x6d44_5321, 42, 0xffff_ffff];
        let fmt = b"mDS: %s %d %x\n\0";

        let rc = unsafe { debug_printf(fmt.as_ptr(), arg_words.as_ptr()) };

        assert_eq!(rc, 0, "the formatter's result is returned unchanged");
        assert_eq!(
            seen(),
            std::vec![(fmt.as_ptr() as *const u8, arg_words.as_ptr() as VaList)],
            "format and va_list arrive as passed — no copy, no validation"
        );
    }

    #[test]
    fn propagates_a_non_zero_formatter_result_rather_than_forcing_zero() {
        // The stock formatter always returns 0, but this entry point does
        // not synthesize that: it returns whatever the callee left in r0.
        let _guard = install(&[-1]);
        let fmt = b"\0";

        let rc = unsafe { debug_printf(fmt.as_ptr(), core::ptr::null()) };

        assert_eq!(rc, -1);
    }

    #[test]
    fn passes_a_null_format_straight_through() {
        // No guard exists in the original; the ten predicated call sites
        // gate on a trace bitmask, not on the format pointer.
        let _guard = install(&[0]);

        let rc = unsafe { debug_printf(core::ptr::null(), core::ptr::null()) };

        assert_eq!(rc, 0);
        assert_eq!(seen().len(), 1, "the formatter is entered even so");
        assert!(seen()[0].0.is_null());
    }

    #[test]
    fn re_reads_the_formatter_slot_on_every_call() {
        let _guard = install(&[7, 9]);
        let fmt = b"cI: %u\n\0";
        let first: [u32; 1] = [1];
        let second: [u32; 1] = [2];

        let a = unsafe { debug_printf(fmt.as_ptr(), first.as_ptr()) };
        let b = unsafe { debug_printf(fmt.as_ptr(), second.as_ptr()) };

        assert_eq!((a, b), (7, 9), "nothing is cached between calls");
        assert_eq!(
            seen(),
            std::vec![
                (fmt.as_ptr() as *const u8, first.as_ptr() as VaList),
                (fmt.as_ptr() as *const u8, second.as_ptr() as VaList),
            ],
            "each call carries its own argument frame"
        );
    }
}
