//! The retailOS trace-line printer: the `(...)`-format diagnostic channel
//! that dumps system state ("Clock rate is 520 Hz, Tick interval is ...")
//! to the semihosting console.
//!
//! Port: `trace_printf` — `FUN_082dcf7c` @ 0x082dcf7c (48 bytes,
//! 0x082dcf7c..0x082dcfac; **44 call sites**, binary-scanned by decoding
//! every B/BL word in osos.dec: 34 plain `bl`, 10 predicated `blne`, no
//! tail branches. No DATA word holds the address, so it is never
//! dispatched virtually).
//!
//! # Decoded from the raw ARM at 0x082dcf7c
//!
//! ```text
//! push  {r0, r1, r2, r3}   ; spill the four register arguments
//! push  {r4, lr}
//! ldr   r0, [sp, #8]       ; the spilled r0 — the format string
//! ldr   r1, =0x08a1081c    ; the static trace-line buffer (shared literal)
//! add   r2, sp, #12        ; &spilled r1 — the va_list frame
//! bl    0x082cecfc         ; format one line into the buffer
//! ldr   r1, =0x08a1081c    ; reload the buffer base
//! mov   r0, #4             ; Angel semihosting SYS_WRITE0
//! swi   0x123456           ; emit the line on the debug console
//! pop   {r4}
//! ldr   pc, [sp], #20      ; return, dropping lr + the four spill words
//! ```
//!
//! Extent verified from the raw words: both `ldr r?, =...` share ONE
//! literal word at 0x082dcfa8 (= 0x08a1081c), and 0x082dcfac starts the
//! next function with its own `cmp r0, #0`. Ghidra reports 44 bytes — it
//! dropped that trailing literal pool word; the true size is 48.
//!
//! Unlike its sibling `debug_printf` @ 0x082bd4a8 (stdio/debug_printf.rs,
//! which streams straight through a mini-printf), this entry point renders
//! the whole line into a FIXED static buffer and hands the buffer base to
//! SYS_WRITE0 in one shot. The formatter `FUN_082cecfc` @ 0x082cecfc is a
//! hand-rolled row-format interpreter — formats look like
//! `(H'Clock rate is',I5,H' Hz, Tick interval is',I4,H' ms, ',N)`
//! (0x082bed98): `(...)` counted groups, `H'..'` literal text, `I`/`U`/`B`
//! integer conversions with widths, `S` strings, `X` spaces, and a final
//! `N` whose job is to store the terminating NUL byte (verified in the raw
//! asm: `cmp r1,#0x4e; moveq r0,#0; strbeq r0,[r5],#1`) so the buffer is a
//! well-formed C string by the time the SWI reads it. The formatter's
//! return value (characters produced) is discarded: `mov r0, #4` overwrites
//! it before the SWI, and every one of the 44 callers treats the call as a
//! statement — the value "returned" is whatever the SWI leaves in r0.
//!
//! The ten predicated sites (`blne`) gate on VALUE comparisons in their
//! own bodies (e.g. `cmp r0, r1; ...; addeq r0, pc, #0x168; bleq`
//! @ 0x082bfd88) — there is no NULL guard on the format here either.
//!
//! # Deviations
//!
//! - The `...` becomes an explicit `args: VaList` (`*const u32`), the
//!   house convention (printf/printf_api.rs, stdio/debug_printf.rs). That
//!   IS what the original builds: the spill frame exists only to
//!   manufacture the pointer this signature takes. A variadic C caller
//!   needs the same small capture trampoline printf_api.rs documents.
//! - The formatter is not ported yet, so it rides the [`TRACE_FORMAT`]
//!   slot: on target the default calls 0x082cecfc in place; on host it
//!   panics until a test installs one.
//! - The SWI goes through the [`super::semihost::SEMIHOST_SWI`] dispatch
//!   hook (house pattern, stdio/semihost.rs) instead of an inlined
//!   `swi 0x123456`; on device the SWI is dead anyway (no debugger traps
//!   it). The result the SWI leaves in r0 is returned, as in the original.
//! - The firmware globals are Rust statics rather than fixed addresses.
//!   The line buffer's size is not encoded anywhere in the image; it is
//!   bounded above by the next referenced global at 0x08a10870, giving
//!   0x54 = 84 bytes ([`TRACE_BUF_CAPACITY`]).

use super::semihost::{semihost_swi, SYS_WRITE0};
use crate::printf::printf_api::VaList;

/// Line capacity of the static trace buffer (original @ 0x08a1081c):
/// bounded above by the next referenced global at 0x08a10870.
pub const TRACE_BUF_CAPACITY: usize = 0x54;

/// The static line buffer the formatter renders into and SYS_WRITE0
/// emits (original: data @ 0x08a1081c; only this function's literal pool
/// references it in the whole image).
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut TRACE_BUF: [u8; TRACE_BUF_CAPACITY] = [0; TRACE_BUF_CAPACITY];

/// The row formatter's signature (`FUN_082cecfc` shape): format string,
/// output buffer, pointer to the first variadic argument word; returns
/// the number of characters produced (ignored by this entry point).
pub type TraceFormatFn = unsafe extern "C" fn(fmt: *const u8, buf: *mut u8, args: VaList) -> i32;

/// Target default: the stock row-format interpreter @ 0x082cecfc.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_trace_format(fmt: *const u8, buf: *mut u8, args: VaList) -> i32 {
    let formatter: TraceFormatFn = unsafe { core::mem::transmute(0x082c_ecfcusize) };
    unsafe { formatter(fmt, buf, args) }
}

/// Host default: nothing to forward to, and silently returning 0 would
/// make a missing install look like an empty but successful trace.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_trace_format(_fmt: *const u8, _buf: *mut u8, _args: VaList) -> i32 {
    panic!("trace_printf requires the row formatter 0x082cecfc")
}

/// The active formatter. Host tests install recording mocks.
#[cfg(target_os = "none")]
pub static mut TRACE_FORMAT: TraceFormatFn = firmware_trace_format;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut TRACE_FORMAT: TraceFormatFn = missing_trace_format;

/// Reads the formatter slot. Volatile so a build in which nothing
/// rewrites the slot cannot constant-fold the default in and delete the
/// dispatch (house rule, see stdio/semihost.rs).
#[inline(always)]
unsafe fn trace_format() -> TraceFormatFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRACE_FORMAT)) }
}

/// trace_printf — original: `FUN_082dcf7c` @ 0x082dcf7c (48 bytes;
/// 44 call sites — 34 `bl`, 10 `blne` — binary-scanned).
///
/// Renders one trace line into the fixed buffer [`TRACE_BUF`] via the
/// row formatter and emits the buffer with a single Angel SYS_WRITE0.
/// Nothing is validated — a NULL format reaches the formatter exactly as
/// in the original, whose predicated call sites do their own gating.
/// Returns the SWI's r0 result; the formatter's character count is
/// discarded (`mov r0, #4` clobbers it before the SWI).
///
/// # Safety
///
/// `fmt` and `args` must satisfy the formatter: a NUL-terminated format
/// ending in `N` (which supplies the string terminator) and enough
/// argument words for its conversions. [`TRACE_FORMAT`] must be installed
/// on host.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn trace_printf(fmt: *const u8, args: VaList) -> i32 {
    let buf = core::ptr::addr_of_mut!(TRACE_BUF) as *mut u8;
    unsafe { (trace_format())(fmt, buf, args) };
    // SYS_WRITE0 takes r1 pointing DIRECTLY at the NUL-terminated string
    // (no parameter block) — the reloaded literal, i.e. the buffer base.
    unsafe { semihost_swi()(SYS_WRITE0, buf as *const usize) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::stdio::semihost::tests::SWI_LOCK;
    use std::string::String;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes swaps of [`TRACE_FORMAT`] (private to this module).
    static FORMATTER_LOCK: Mutex<()> = Mutex::new(());

    /// What the recording formatter saw, in order: (fmt, buf, args).
    static mut SEEN: Vec<(*const u8, *mut u8, VaList)> = Vec::new();
    /// Strings the recorder renders into the buffer, one per call, then
    /// repeating the last; an empty entry writes nothing at all.
    static mut RENDERED: Vec<Vec<u8>> = Vec::new();
    /// Counts the recorder returns, one per call, then repeating last.
    static mut COUNTS: Vec<i32> = Vec::new();

    /// One recorded flush: (op, r1 as issued, NUL-terminated string).
    static mut FLUSH_LOG: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    /// Scripted SWI results, consumed front to back; empty = -1.
    static mut SWI_RESULTS: Vec<i32> = Vec::new();

    unsafe extern "C" fn recording_formatter(fmt: *const u8, buf: *mut u8, args: VaList) -> i32 {
        unsafe {
            let seen = &mut *core::ptr::addr_of_mut!(SEEN);
            seen.push((fmt, buf, args));
            let call = seen.len() - 1;
            let rendered = &*core::ptr::addr_of!(RENDERED);
            if let Some(script) = rendered.get(call).or_else(|| rendered.last()) {
                for (i, &b) in script.iter().enumerate() {
                    buf.add(i).write_volatile(b);
                }
            }
            let counts = &*core::ptr::addr_of!(COUNTS);
            counts.get(call).or_else(|| counts.last()).copied().unwrap_or(0)
        }
    }

    /// Recording mock for the SWI boundary: captures the op, the raw r1,
    /// and the NUL-terminated string it points at (SYS_WRITE0 shape);
    /// answers from the scripted results.
    unsafe extern "C" fn recording_swi(op: usize, block: *const usize) -> i32 {
        unsafe {
            let mut s = Vec::new();
            let mut p = block as *const u8;
            while *p != 0 {
                s.push(*p);
                p = p.add(1);
            }
            (*core::ptr::addr_of_mut!(FLUSH_LOG)).push((op, block as usize, s));
            let results = &mut *core::ptr::addr_of_mut!(SWI_RESULTS);
            if results.is_empty() {
                -1
            } else {
                results.remove(0)
            }
        }
    }

    /// Both locks, formatter first (fixed order, no other suite takes
    /// both); restores the shipped defaults even when a test panics.
    struct Guards(MutexGuard<'static, ()>, MutexGuard<'static, ()>);

    impl Drop for Guards {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(TRACE_FORMAT).write(missing_trace_format);
                crate::stdio::semihost::tests::restore_swi();
                (*core::ptr::addr_of_mut!(SEEN)).clear();
                (*core::ptr::addr_of_mut!(RENDERED)).clear();
                (*core::ptr::addr_of_mut!(COUNTS)).clear();
                (*core::ptr::addr_of_mut!(FLUSH_LOG)).clear();
                (*core::ptr::addr_of_mut!(SWI_RESULTS)).clear();
                (*core::ptr::addr_of_mut!(TRACE_BUF)).fill(0);
            }
        }
    }

    /// Locks both boundaries, installs the mocks, resets all state.
    fn setup(rendered: &[&[u8]], counts: &[i32], swi_results: &[i32]) -> Guards {
        let fmt_guard = FORMATTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let swi_guard = SWI_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(SEEN)).clear();
            *core::ptr::addr_of_mut!(RENDERED) = rendered.iter().map(|s| s.to_vec()).collect();
            *core::ptr::addr_of_mut!(COUNTS) = counts.to_vec();
            *core::ptr::addr_of_mut!(FLUSH_LOG) = Vec::new();
            *core::ptr::addr_of_mut!(SWI_RESULTS) = swi_results.to_vec();
            (*core::ptr::addr_of_mut!(TRACE_BUF)).fill(0);
            core::ptr::addr_of_mut!(TRACE_FORMAT).write(recording_formatter);
            super::super::semihost::SEMIHOST_SWI = recording_swi;
        }
        Guards(fmt_guard, swi_guard)
    }

    fn seen() -> Vec<(*const u8, *mut u8, VaList)> {
        unsafe { (*core::ptr::addr_of!(SEEN)).clone() }
    }

    fn flushes() -> Vec<(usize, String)> {
        unsafe {
            (*core::ptr::addr_of!(FLUSH_LOG))
                .iter()
                .map(|(op, _, s)| (*op, String::from_utf8_lossy(s).into_owned()))
                .collect()
        }
    }

    #[test]
    fn formats_into_the_static_buffer_then_emits_it_via_sys_write0() {
        let _guard = setup(&[b"Clock rate is 520 Hz\0"], &[20], &[0]);
        // The stock shape: `(H'Clock rate is',I5,H' Hz',N)`-style rows.
        let fmt = b"(H'Clock rate is',I5,N)\0";
        let args: [u32; 1] = [520];

        let rc = unsafe { trace_printf(fmt.as_ptr(), args.as_ptr()) };

        assert_eq!(rc, 0, "the SWI's r0 result is returned");
        let s = seen();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].0, fmt.as_ptr() as *const u8, "format passes untouched");
        assert_eq!(
            s[0].1,
            core::ptr::addr_of!(TRACE_BUF) as *mut u8,
            "the render target IS the static TRACE_BUF"
        );
        assert_eq!(s[0].2, args.as_ptr() as VaList, "argument words pass untouched");
        let f = flushes();
        assert_eq!(f.len(), 1, "exactly one SWI per call");
        assert_eq!(f[0].0, SYS_WRITE0, "Angel op 0x04");
        assert_eq!(f[0].1, "Clock rate is 520 Hz", "what the formatter wrote");
    }

    #[test]
    fn returns_the_swi_result_not_the_formatter_count() {
        // `mov r0, #4` clobbers the formatter's return before the SWI,
        // so the observable result is the SWI's r0 alone.
        let _guard = setup(&[b"x\0"], &[0x1234], &[-1]);
        let fmt = b"\0";

        let rc = unsafe { trace_printf(fmt.as_ptr(), core::ptr::null()) };

        assert_eq!(rc, -1, "the formatter's count 0x1234 is discarded");
    }

    #[test]
    fn reuses_one_static_line_buffer_across_calls() {
        let _guard = setup(&[b"one\0", b"two\0"], &[3, 3], &[0, 0]);
        let fmt = b"\0";

        unsafe {
            trace_printf(fmt.as_ptr(), core::ptr::null());
            trace_printf(fmt.as_ptr(), core::ptr::null());
        }

        let s = seen();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].1, s[1].1, "both calls render into the same buffer");
        assert_eq!(s[0].1, core::ptr::addr_of!(TRACE_BUF) as *mut u8);
        // Each line overwrites from the base; the second flush carries
        // only the second rendering.
        assert_eq!(flushes()[1].1, "two");
    }

    #[test]
    fn null_format_reaches_the_formatter_and_the_swi_still_fires() {
        // No guard exists in the original; the ten blne sites gate on
        // their own value comparisons, not on the format pointer.
        let _guard = setup(&[], &[], &[]);

        let rc = unsafe { trace_printf(core::ptr::null(), core::ptr::null()) };

        assert_eq!(rc, -1, "the fail-stub SWI result");
        let s = seen();
        assert_eq!(s.len(), 1, "the formatter is entered even so");
        assert!(s[0].0.is_null());
        assert_eq!(flushes().len(), 1, "and the SWI fires regardless");
    }

    #[test]
    fn empty_rendering_still_issues_the_write0_with_the_buffer_base() {
        // A formatter that writes nothing leaves the zeroed buffer, so
        // SYS_WRITE0 sees an empty string — the SWI is unconditional.
        let _guard = setup(&[b""], &[0], &[7]);
        let fmt = b"\0";

        let rc = unsafe { trace_printf(fmt.as_ptr(), core::ptr::null()) };

        assert_eq!(rc, 7, "scripted SWI result passes through");
        assert_eq!(flushes(), std::vec![(SYS_WRITE0, String::new())]);
    }

    #[test]
    fn the_swi_receives_the_buffer_pointer_directly_not_a_block() {
        // SYS_WRITE0's r1 IS the string base (no parameter block); the
        // recorded r1 must be the buffer address itself.
        let _guard = setup(&[b"abc\0"], &[3], &[0]);
        let fmt = b"\0";

        unsafe { trace_printf(fmt.as_ptr(), core::ptr::null()) };

        let log = unsafe { &*core::ptr::addr_of!(FLUSH_LOG) };
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].1, core::ptr::addr_of!(TRACE_BUF) as usize, "r1 = buffer base");
        assert_eq!(
            String::from_utf8_lossy(&log[0].2),
            "abc",
            "the string read at r1 is what the formatter rendered"
        );
    }
}
