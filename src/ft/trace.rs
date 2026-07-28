//! FreeType's `FT_ERROR` / `FT_TRACE` output sink — the single varargs
//! shim every `FT_Stream_*` reader and most driver error paths of this
//! debug build funnel their messages through (359 `bl` + 7 `b` call
//! sites, binary-scanned, easily the busiest FreeType routine in the
//! image).
//!
//! The original is a pure forwarder:
//!
//! ```text
//! push {r0, r1, r2, r3}      ; home the argument registers
//! push {r4, lr}
//! ldr  r1, [sp, #8]          ; r1 = format (the spilled r0)
//! ldr  r0, [pc, #20]         ; r0 = logger context, 0x08b1c9dc
//! add  r2, sp, #12           ; r2 = va_list -> the spilled r1..r3,
//! bl   0x0802f654            ;      continuing into the caller's stack
//! ldr  r0, [pc, #8]          ; args
//! bl   0x08050f80            ; flush/terminate the log record
//! ```
//!
//! # Deviations
//!
//! The two firmware routines behind it (`0x0802f654`, a `vfprintf`-style
//! logger taking the context at 0x08b1c9dc, and `0x08050f80`, its record
//! terminator) are not ported yet, so this module reproduces the
//! *contract* rather than the printf path: [`ft_error_trace`] hands the
//! format string and the register-passed arguments to an installable
//! [`FtTraceSink`], and does nothing at all when none is installed —
//! which is also the observable behavior on retail hardware, where the
//! log has no destination. Wiring the real logger is a matter of
//! installing a sink once those two addresses are ported.
//!
//! The original builds a genuine `va_list`, so a format string with more
//! than three conversions keeps reading the caller's stack. The port
//! takes the three variadic slots AAPCS passes in `r1`-`r3`, which
//! covers every call site in the image (the widest format in the
//! FreeType strings is `" invalid i/o; pos = 0x%lx, size = 0x%lx\n"`,
//! two arguments); a hypothetical four-argument call would lose its
//! fourth argument instead of reading stack memory.

/// A `FT_ERROR`/`FT_TRACE` consumer: the format string plus the three
/// variadic slots AAPCS passes in registers.
pub type FtTraceSink = unsafe extern "C" fn(format: *const u8, arg1: u32, arg2: u32, arg3: u32);

/// The installed sink, or `None` for "discard" — the boot state, and
/// what the stock firmware effectively does on retail hardware.
static mut FT_TRACE_SINK: Option<FtTraceSink> = None;

/// Installs (or with `None` removes) the trace sink, returning the
/// previous one. ADDITION — the original has no such switch; see the
/// module header.
///
/// # Safety
/// Not re-entrant: no other thread or interrupt may be inside
/// [`ft_error_trace`] while the sink is swapped.
pub unsafe fn ft_set_trace_sink(sink: Option<FtTraceSink>) -> Option<FtTraceSink> {
    let slot = core::ptr::addr_of_mut!(FT_TRACE_SINK);
    let previous = slot.read_volatile();
    slot.write_volatile(sink);
    previous
}

/// ft_error_trace (FreeType's `FT_ERROR`/`FT_TRACE` sink) — original:
/// `FUN_0804d17c` @ 0x0804d17c (40 bytes; 359 `bl` + 7 `b` call sites).
///
/// Forwards `format` and its arguments to the installed [`FtTraceSink`]
/// (none by default — see the module header for the deviation).
///
/// # Safety
/// `format` must be a NUL-terminated string valid for the installed
/// sink, and the arguments must match its conversions.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_error_trace(format: *const u8, arg1: u32, arg2: u32, arg3: u32) {
    if let Some(sink) = core::ptr::addr_of!(FT_TRACE_SINK).read_volatile() {
        sink(format, arg1, arg2, arg3);
    }
}

#[cfg(test)]
extern crate std;

/// Serializes the tests that swap the global sink (see PORTING.md's
/// test-harness rule: one guard per `#[test]`, never shadowed).
#[cfg(test)]
pub(crate) static TEST_TRACE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test-only sink that records what [`ft_error_trace`] was handed.
#[cfg(test)]
pub(crate) mod capture {
    use super::*;
    use std::{string::String, vec::Vec};

    pub(crate) const CAP: usize = 8;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    pub(crate) struct TraceCall {
        pub format: *const u8,
        pub args: [u32; 3],
    }

    static mut CALLS: [TraceCall; CAP] = [TraceCall { format: core::ptr::null(), args: [0; 3] };
        CAP];
    static mut COUNT: usize = 0;

    unsafe extern "C" fn record(format: *const u8, arg1: u32, arg2: u32, arg3: u32) {
        let count = core::ptr::addr_of_mut!(COUNT);
        if *count < CAP {
            (*core::ptr::addr_of_mut!(CALLS))[*count] = TraceCall { format, args: [arg1, arg2, arg3] };
            *count += 1;
        }
    }

    /// Installs the recorder and clears the log. Call under
    /// `TEST_TRACE_LOCK`.
    pub(crate) unsafe fn start() {
        *core::ptr::addr_of_mut!(COUNT) = 0;
        ft_set_trace_sink(Some(record));
    }

    /// Removes the recorder and returns what was logged.
    pub(crate) unsafe fn finish() -> Vec<TraceCall> {
        ft_set_trace_sink(None);
        let count = *core::ptr::addr_of!(COUNT);
        core::slice::from_raw_parts(core::ptr::addr_of!(CALLS).cast::<TraceCall>(), count).to_vec()
    }

    /// The format strings seen, as Rust strings (NUL-terminated in the
    /// original data).
    pub(crate) unsafe fn formats(calls: &[TraceCall]) -> Vec<String> {
        calls
            .iter()
            .map(|call| {
                let mut end = call.format;
                while *end != 0 {
                    end = end.add(1);
                }
                let len = end.offset_from(call.format) as usize;
                String::from_utf8_lossy(core::slice::from_raw_parts(call.format, len)).into_owned()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sink_installed_discards_the_message() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        unsafe {
            assert!(ft_set_trace_sink(None).is_none());
            ft_error_trace(b"nobody is listening\0".as_ptr(), 1, 2, 3);
        }
    }

    #[test]
    fn installed_sink_receives_format_and_register_arguments() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        let format = b"pos = 0x%lx, size = 0x%lx\0";
        let calls = unsafe {
            capture::start();
            ft_error_trace(format.as_ptr(), 0x1234, 0x5678, 0);
            ft_error_trace(format.as_ptr(), 0, 0, 0);
            capture::finish()
        };
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].format, format.as_ptr());
        assert_eq!(calls[0].args, [0x1234, 0x5678, 0]);
        assert_eq!(calls[1].args, [0, 0, 0]);
        assert_eq!(
            unsafe { capture::formats(&calls) }[0],
            "pos = 0x%lx, size = 0x%lx"
        );
    }

    #[test]
    fn set_trace_sink_returns_the_previous_sink() {
        let _guard = TEST_TRACE_LOCK.lock().unwrap();
        unsafe extern "C" fn ignore(_: *const u8, _: u32, _: u32, _: u32) {}
        unsafe {
            assert!(ft_set_trace_sink(Some(ignore)).is_none());
            let previous = ft_set_trace_sink(None);
            assert_eq!(previous.map(|f| f as usize), Some(ignore as usize));
        }
    }
}
