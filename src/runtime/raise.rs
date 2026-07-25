//! Ports of the ARM ADS 1.0.1 signal-dispatch runtime:
//!
//! - `raise` — original: `FUN_08035634` @ 0x08035634 (284 bytes total: a
//!   76-byte dispatch stub @ 0x08035634 plus the 208-byte
//!   `_default_signal_handler` body @ 0x08036bbc, which the stub reaches
//!   with a conditional branch — Ghidra treats both ranges as one
//!   function). Looks up the handler for `sig`; if none is registered it
//!   prints the signal name (and a reason string for SIGFPE/SIGRTRED/
//!   SIGRTMEM) via the semihosting debug console and returns 1.
//! - `__rt_raise` — original: `FUN_080320a8` @ 0x080320a8 (24 bytes; the
//!   neighboring veneers up to 0x080320d8 are unrelated one-instruction
//!   stubs). `bl raise; if result != 0 -> b 0x082b20a0` (OS terminate).
//!
//! Register-level contract (both functions): r0 = `sig`, r1 = `code`,
//! passed straight through to the registered handler / default handler;
//! return value in r0 (0 = handled, nonzero = unhandled). `__rt_div0`
//! @ 0x0803421c enters as `mov r0, #2; mov r1, #2; b __rt_raise`, i.e.
//! SIGFPE (2) with the "Divide By Zero" reason bits.
//!
//! Dispatch semantics recovered from the machine code:
//! - handler value -1 -> run the default handler (`cmn r0, #1; beq`).
//! - handler value -3 -> ignore, return 0 (`cmn r2, #3`).
//! - anything else    -> call `handler(sig, code)`, return 0.
//!
//! Signal numbers (name table @ 0x08986577, 14 entries x 23 bytes):
//! 1 SIGABRT, 2 SIGFPE, 3 SIGILL, 4 SIGINT, 5 SIGSEGV, 6 SIGTERM,
//! 7 SIGSTAK, 8 SIGRTRED, 9 SIGRTMEM, 10 SIGUSR1, 11 SIGUSR2, 12 SIGPVFN,
//! 13 SIGCPPL, 14 "Out of heap". Valid range is exactly 1..=14
//! (`sub r2, r0, #1; cmp r2, #14; bcs` -> "Unknown signal").
//!
//! Deviations from the original:
//! - In the stock binary the handler-table lookup inside `raise` is a
//!   literal `mvn r0, #0; mov r0, r0` @ 0x08035644-0x08035648: retailOS
//!   was linked with no signal table, so the lookup was constant-folded
//!   to "no handler" (-1) and every raise lands in the default handler.
//!   There is consequently no `signal()` registration function anywhere
//!   in osos either. This port models the missing table as a documented
//!   `static mut SIGNAL_HANDLERS` and adds a small `signal()`-like
//!   registration helper (marked ADDITION below) so handlers can be
//!   installed and the dispatch paths exercised; the table starts
//!   all-default, which reproduces the stock behavior exactly.
//! - The default handler's character output went through `_ttywrch`
//!   @ 0x08036d48 (`svc 0x123456` with r0=3, ARM semihosting SYS_WRITEC)
//!   — a debugger console write that is effectively discarded on retail
//!   hardware. Ported as the no-op stub `debug_wrch` (under `cfg(test)`
//!   it appends to a test buffer instead, so the output text is
//!   verifiable on the host).
//! - OS terminate @ 0x082b20a0 (`svc 0x123456` semihosting exit, then an
//!   infinite loop) is stubbed as `os_terminate() -> !`, which spins;
//!   noted for a future batch that will port the real OS routine. Under
//!   `cfg(test)` it records a flag and panics when called directly from
//!   Rust (panicking through the `extern "C"` raise frames would abort,
//!   so the full `__rt_raise` -> terminate chain is not host-testable —
//!   see the test module).
//! - The SIGRTRED (sig 8) detail string is the `code` word reinterpreted
//!   as a `char *` (`moveq r4, r1`). Faithful on the 32-bit target; on
//!   64-bit hosts a real pointer does not fit the i32 `code` word, so
//!   that one path cannot be exercised by the host tests (documented in
//!   the test module).

/// Handler-table sentinel: no handler registered — run the default
/// handler (the original compares with `cmn r0, #1`).
pub const SIGNAL_DEFAULT: isize = -1;

/// Handler-table sentinel: signal is ignored, `raise` returns 0 without
/// doing anything (the original compares with `cmn r2, #3`).
pub const SIGNAL_IGNORE: isize = -3;

/// Highest valid signal number (name-table entry count in the original).
pub const NUM_SIGNALS: i32 = 14;

/// Signal numbers as encoded in the original name table.
pub const SIGABRT: i32 = 1;
pub const SIGFPE: i32 = 2;
pub const SIGILL: i32 = 3;
pub const SIGINT: i32 = 4;
pub const SIGSEGV: i32 = 5;
pub const SIGTERM: i32 = 6;
pub const SIGSTAK: i32 = 7;
pub const SIGRTRED: i32 = 8;
pub const SIGRTMEM: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGUSR2: i32 = 11;
pub const SIGPVFN: i32 = 12;
pub const SIGCPPL: i32 = 13;

/// Registered handler shape: called with (sig, code) in r0/r1.
pub type SignalHandler = unsafe extern "C" fn(i32, i32);

/// The signal handler table. DEVIATION: dead-stripped in the stock
/// binary (see module header); modeled here as a `static mut` indexed by
/// signal number (slot 0 unused), all slots `SIGNAL_DEFAULT` at boot —
/// which reproduces the stock firmware's always-default behavior.
static mut SIGNAL_HANDLERS: [isize; NUM_SIGNALS as usize + 1] =
    [SIGNAL_DEFAULT; NUM_SIGNALS as usize + 1];

/// Signal name table — original: 14 entries x 23 bytes @ 0x08986577,
/// indexed by `sig - 1` (`mul` by 23 in the original). Byte-faithful
/// copy, NUL-terminated and zero-padded to the 23-byte stride.
#[rustfmt::skip]
static SIGNAL_NAMES: [[u8; 23]; NUM_SIGNALS as usize] = [
    *b"Abnormal termination\0\0\0",   // 1 SIGABRT
    *b"Arithmetic exception: \0",     // 2 SIGFPE
    *b"Illegal instruction\0\0\0\0",  // 3 SIGILL
    *b"Interrupt received\0\0\0\0\0", // 4 SIGINT
    *b"Illegal address\0\0\0\0\0\0\0\0", // 5 SIGSEGV
    *b"Termination request\0\0\0\0",  // 6 SIGTERM
    *b"Stack overflow\0\0\0\0\0\0\0\0\0", // 7 SIGSTAK
    *b"Redirect: can't open: \0",     // 8 SIGRTRED
    *b"Out of heap memory\0\0\0\0\0", // 9 SIGRTMEM
    *b"User-defined signal 1\0\0",    // 10 SIGUSR1
    *b"User-defined signal 2\0\0",    // 11 SIGUSR2
    *b"Pure virtual fn called\0",     // 12 SIGPVFN
    *b"C++ library exception\0\0",    // 13 SIGCPPL
    *b"Out of heap\0\0\0\0\0\0\0\0\0\0\0\0", // 14
];

/// "Unknown signal" — original @ 0x08036c90, used for sig outside 1..=14.
static UNKNOWN_SIGNAL: [u8; 15] = *b"Unknown signal\0";

/// Empty detail string — original @ 0x08036c8c (a zero word).
static EMPTY_DETAIL: [u8; 1] = [0];

/// SIGFPE reason strings — original @ 0x08036ca4-0x08036cf0, selected by
/// testing bits of `code` in this exact order (first match wins).
static FPE_INVALID_OPERATION: [u8; 18] = *b"Invalid Operation\0";
static FPE_DIVIDE_BY_ZERO: [u8; 15] = *b"Divide By Zero\0";
static FPE_OVERFLOW: [u8; 9] = *b"Overflow\0";
static FPE_UNDERFLOW: [u8; 10] = *b"Underflow\0";
static FPE_INEXACT_RESULT: [u8; 15] = *b"Inexact Result\0";

/// SIGRTMEM code==1 replacement name — original @ 0x08036cf0.
static HEAP_MEMORY_CORRUPTED: [u8; 24] = *b": Heap memory corrupted\0";

/// Handler lookup — DEVIATION: constant -1 in the stock binary (see
/// module header); here it reads the modeled table. Out-of-range signals
/// have no slot and fall through to the default handler. The read is
/// volatile: the table models firmware-visible runtime state (handlers
/// are installed behind the compiler's back, e.g. by future patch
/// payloads) and must not be constant-folded to the all-default boot
/// state.
#[inline]
unsafe fn lookup_signal_handler(sig: i32) -> isize {
    if (1..=NUM_SIGNALS).contains(&sig) {
        core::ptr::addr_of!(SIGNAL_HANDLERS).cast::<isize>().add(sig as usize).read_volatile()
    } else {
        SIGNAL_DEFAULT
    }
}

/// raise — original: `FUN_08035634` @ 0x08035634 (dispatch part).
///
/// r0 = `sig`, r1 = `code`. Handler == -1: tail-branch to the default
/// handler and return its result (1). Handler == -3: ignore, return 0.
/// Otherwise call `handler(sig, code)` (`mov lr, pc; mov pc, r2`) and
/// return 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn raise(sig: i32, code: i32) -> i32 {
    let handler = lookup_signal_handler(sig);
    if handler == SIGNAL_DEFAULT {
        return default_signal_handler(sig, code);
    }
    if handler != SIGNAL_IGNORE {
        let handler_fn: SignalHandler = core::mem::transmute(handler);
        handler_fn(sig, code);
    }
    0
}

/// signal — ADDITION (not present in the stock binary; see module
/// header). Registers `handler` for `sig` (1..=14): a `SignalHandler`
/// function address as `isize`, or one of the sentinels `SIGNAL_DEFAULT`
/// / `SIGNAL_IGNORE`. Returns the previous table entry, or
/// `SIGNAL_DEFAULT` for an out-of-range `sig` (which has no slot).
///
/// Deliberately NOT `#[no_mangle]`: exporting a C symbol named `signal`
/// collides with libc's `signal`, which the statically linked Rust std
/// runtime calls during test-binary startup (SIGPIPE setup) with libc
/// semantics our sentinel values don't satisfy.
pub unsafe extern "C" fn signal(sig: i32, handler: isize) -> isize {
    if !(1..=NUM_SIGNALS).contains(&sig) {
        return SIGNAL_DEFAULT;
    }
    let slot = core::ptr::addr_of_mut!(SIGNAL_HANDLERS).cast::<isize>().add(sig as usize);
    let previous = slot.read_volatile();
    slot.write_volatile(handler);
    previous
}

/// _default_signal_handler — original: part of `FUN_08035634`, body
/// @ 0x08036bbc (208 bytes). r0 = `sig`, r1 = `code`.
///
/// Selects the signal name from the 23-byte-stride table (or "Unknown
/// signal" outside 1..=14), picks a detail string for SIGFPE (reason
/// bits in `code`), SIGRTRED (`code` reinterpreted as `char *`) and
/// SIGRTMEM code==1 (name replaced by ": Heap memory corrupted"), then
/// prints '\n' + name + detail + '\n' via `_ttywrch` and returns 1.
unsafe fn default_signal_handler(sig: i32, code: i32) -> i32 {
    let mut name: *const u8;
    let mut detail: *const u8 = EMPTY_DETAIL.as_ptr();
    // `sub r2, r0, #1; cmp r2, #14; bcs` — unsigned: valid is 1..=14.
    if (sig as u32).wrapping_sub(1) >= NUM_SIGNALS as u32 {
        name = UNKNOWN_SIGNAL.as_ptr();
    } else {
        name = SIGNAL_NAMES[(sig - 1) as usize].as_ptr();
        if sig == SIGFPE {
            // `tst` chains, first matching bit set wins, in this order.
            let reason = code as u32;
            if reason & 0x0400_0000 != 0 {
                detail = FPE_INVALID_OPERATION.as_ptr();
            } else if reason & 0x8000_0002 != 0 {
                detail = FPE_DIVIDE_BY_ZERO.as_ptr();
            } else if reason & 0x1000_0000 != 0 {
                detail = FPE_OVERFLOW.as_ptr();
            } else if reason & 0x2000_0000 != 0 {
                detail = FPE_UNDERFLOW.as_ptr();
            } else if reason & 0x4000_0000 != 0 {
                detail = FPE_INEXACT_RESULT.as_ptr();
            }
        } else if sig == SIGRTRED {
            // `moveq r4, r1` — the code word IS the detail string.
            detail = code as isize as *const u8;
        } else if sig == SIGRTMEM && code == 1 {
            // `cmpeq r1, #1; adreq r5, ...` — replaces the NAME.
            name = HEAP_MEMORY_CORRUPTED.as_ptr();
        }
    }
    debug_wrch(b'\n');
    write_debug_cstr(name);
    write_debug_cstr(detail);
    debug_wrch(b'\n');
    1
}

/// Writes a NUL-terminated string byte by byte, matching the original's
/// `ldrb; cmp #0; bne putc` loops.
unsafe fn write_debug_cstr(mut s: *const u8) {
    while *s != 0 {
        debug_wrch(*s);
        s = s.add(1);
    }
}

/// _ttywrch — original @ 0x08036d48 (24 bytes): store the char on the
/// stack, `svc 0x123456` with r0=3 (ARM semihosting SYS_WRITEC). A debug
/// console write with no effect on retail hardware, so this stub is a
/// no-op on target; under `cfg(test)` it records into `TEST_TTY` so the
/// default handler's output can be asserted on the host.
fn debug_wrch(ch: u8) {
    #[cfg(test)]
    unsafe {
        let len = core::ptr::addr_of_mut!(TEST_TTY_LEN);
        if *len < TEST_TTY_CAP {
            (*core::ptr::addr_of_mut!(TEST_TTY))[*len] = ch;
            *len += 1;
        }
    }
    #[cfg(not(test))]
    let _ = ch;
}

/// OS terminate — original @ 0x082b20a0: `svc 0x123456` (semihosting
/// exit) followed by an infinite loop. STUB: spins forever until the
/// real OS routine is ported in a future batch. Under `cfg(test)` it
/// sets `TEST_TERMINATED` and panics instead of spinning; because
/// unwinding across the `extern "C"` frames of `raise`/`__rt_raise`
/// would abort the process, host tests may only call it directly from
/// Rust (see the test module).
fn os_terminate() -> ! {
    #[cfg(test)]
    {
        unsafe { *core::ptr::addr_of_mut!(TEST_TERMINATED) = true };
        panic!("os_terminate");
    }
    #[cfg(not(test))]
    loop {}
}

/// __rt_raise — original: `FUN_080320a8` @ 0x080320a8 (24 bytes).
///
/// r0 = `sig`, r1 = `code` — passed through to `raise` untouched.
/// `bl raise; cmp r0, #0; popeq {r4, pc}` — if the signal was handled
/// (raise returned 0) return 0 to the caller; otherwise fall through to
/// `b 0x082b20a0` (OS terminate), which never returns.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_raise(sig: i32, code: i32) -> i32 {
    if raise(sig, code) == 0 {
        return 0;
    }
    os_terminate();
}

/// Test-only capture buffer for `debug_wrch` output.
#[cfg(test)]
const TEST_TTY_CAP: usize = 512;
#[cfg(test)]
static mut TEST_TTY: [u8; TEST_TTY_CAP] = [0; TEST_TTY_CAP];
#[cfg(test)]
static mut TEST_TTY_LEN: usize = 0;

/// Test-only flag recording that `os_terminate` was reached.
#[cfg(test)]
static mut TEST_TERMINATED: bool = false;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// The handler table and TTY capture buffer are global state shared
    /// by all tests; serialize every test through this lock.
    static LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        unsafe {
            for slot in &mut *core::ptr::addr_of_mut!(SIGNAL_HANDLERS) {
                *slot = SIGNAL_DEFAULT;
            }
            *core::ptr::addr_of_mut!(TEST_TTY_LEN) = 0;
            *core::ptr::addr_of_mut!(TEST_TERMINATED) = false;
            handler_calls().clear();
        }
    }

    fn tty_output() -> String {
        unsafe {
            let tty = &*core::ptr::addr_of!(TEST_TTY);
            let len = *core::ptr::addr_of!(TEST_TTY_LEN);
            String::from_utf8(tty[..len].to_vec()).unwrap()
        }
    }

    // Recorded arguments of every test-handler invocation.
    static mut HANDLER_CALLS: Vec<(i32, i32)> = Vec::new();

    #[allow(static_mut_refs)]
    fn handler_calls() -> &'static mut Vec<(i32, i32)> {
        unsafe { &mut *core::ptr::addr_of_mut!(HANDLER_CALLS) }
    }

    unsafe extern "C" fn recording_handler(sig: i32, code: i32) {
        handler_calls().push((sig, code));
    }

    #[test]
    fn registered_handler_is_invoked_with_sig_and_code() {
        let _g = LOCK.lock().unwrap();
        reset_state();
        unsafe {
            let handler_addr = recording_handler as *const () as isize;
            let previous = signal(SIGSEGV, handler_addr);
            assert_eq!(previous, SIGNAL_DEFAULT);
            assert_eq!(raise(SIGSEGV, 42), 0);
            assert_eq!(*handler_calls(), [(SIGSEGV, 42)]);
            // signal() returns the previously registered entry.
            assert_eq!(signal(SIGSEGV, SIGNAL_DEFAULT), handler_addr);
        }
    }

    #[test]
    fn ignored_signal_returns_zero_without_output() {
        let _g = LOCK.lock().unwrap();
        reset_state();
        unsafe {
            assert_eq!(signal(SIGTERM, SIGNAL_IGNORE), SIGNAL_DEFAULT);
            assert_eq!(raise(SIGTERM, 7), 0);
            assert!(handler_calls().is_empty());
            assert_eq!(tty_output(), "");
        }
    }

    #[test]
    fn signal_out_of_range_has_no_slot() {
        let _g = LOCK.lock().unwrap();
        reset_state();
        unsafe {
            assert_eq!(signal(0, SIGNAL_IGNORE), SIGNAL_DEFAULT);
            assert_eq!(signal(15, SIGNAL_IGNORE), SIGNAL_DEFAULT);
            // Not stored: sig 15 still goes to the default handler.
            assert_eq!(raise(15, 0), 1);
            assert_eq!(tty_output(), "\nUnknown signal\n");
        }
    }

    #[test]
    fn default_handler_unknown_signal() {
        let _g = LOCK.lock().unwrap();
        reset_state();
        unsafe {
            for bad_sig in [0, -1, 15, 100] {
                reset_state();
                assert_eq!(raise(bad_sig, 0), 1);
                assert_eq!(tty_output(), "\nUnknown signal\n", "sig={bad_sig}");
            }
        }
    }

    /// The __rt_div0 path: sig=2 (SIGFPE), code=2 -> "Divide By Zero".
    #[test]
    fn default_handler_sigfpe_divide_by_zero() {
        let _g = LOCK.lock().unwrap();
        reset_state();
        unsafe {
            assert_eq!(raise(SIGFPE, 2), 1);
            assert_eq!(tty_output(), "\nArithmetic exception: Divide By Zero\n");
        }
    }

    #[test]
    fn default_handler_sigfpe_reason_bits() {
        let _g = LOCK.lock().unwrap();
        let cases: [(u32, &str); 5] = [
            (0x0400_0000, "\nArithmetic exception: Invalid Operation\n"),
            (0x8000_0002, "\nArithmetic exception: Divide By Zero\n"),
            (0x1000_0000, "\nArithmetic exception: Overflow\n"),
            (0x2000_0000, "\nArithmetic exception: Underflow\n"),
            (0x4000_0000, "\nArithmetic exception: Inexact Result\n"),
        ];
        unsafe {
            for (code, expected) in cases {
                reset_state();
                assert_eq!(raise(SIGFPE, code as i32), 1);
                assert_eq!(tty_output(), expected, "code={code:#x}");
            }
            // No reason bits: name only (empty detail string).
            reset_state();
            assert_eq!(raise(SIGFPE, 0), 1);
            assert_eq!(tty_output(), "\nArithmetic exception: \n");
            // First matching bit in the original's test order wins.
            reset_state();
            assert_eq!(raise(SIGFPE, 0x1400_0000u32 as i32), 1);
            assert_eq!(tty_output(), "\nArithmetic exception: Invalid Operation\n");
        }
    }

    #[test]
    fn default_handler_all_named_signals() {
        let _g = LOCK.lock().unwrap();
        let expected = [
            (SIGABRT, "\nAbnormal termination\n"),
            (SIGILL, "\nIllegal instruction\n"),
            (SIGINT, "\nInterrupt received\n"),
            (SIGSEGV, "\nIllegal address\n"),
            (SIGTERM, "\nTermination request\n"),
            (SIGSTAK, "\nStack overflow\n"),
            (SIGRTMEM, "\nOut of heap memory\n"),
            (SIGUSR1, "\nUser-defined signal 1\n"),
            (SIGUSR2, "\nUser-defined signal 2\n"),
            (SIGPVFN, "\nPure virtual fn called\n"),
            (SIGCPPL, "\nC++ library exception\n"),
            (14, "\nOut of heap\n"),
        ];
        unsafe {
            for (sig, text) in expected {
                reset_state();
                assert_eq!(raise(sig, 0), 1);
                assert_eq!(tty_output(), text, "sig={sig}");
            }
        }
    }

    /// SIGRTMEM with code==1 replaces the NAME (detail stays empty).
    #[test]
    fn default_handler_heap_corrupted() {
        let _g = LOCK.lock().unwrap();
        reset_state();
        unsafe {
            assert_eq!(raise(SIGRTMEM, 1), 1);
            assert_eq!(tty_output(), "\n: Heap memory corrupted\n");
        }
    }

    /// SIGRTRED (sig 8) reinterprets `code` as a `char *` detail string
    /// (`moveq r4, r1`). UNTESTABLE on 64-bit hosts: a valid string
    /// pointer does not fit the i32 `code` word, and any fabricated
    /// value (including 0) is a wild dereference on the host — whereas on
    /// the 32-bit target the path is a plain pointer cast, exactly as in
    /// the original. Only the code path is ported here; there is no host
    /// test for it.

    #[test]
    fn rt_raise_returns_zero_when_handled() {
        let _g = LOCK.lock().unwrap();
        reset_state();
        unsafe {
            signal(SIGSEGV, recording_handler as *const () as isize);
            assert_eq!(__rt_raise(SIGSEGV, 7), 0);
            assert_eq!(*handler_calls(), [(SIGSEGV, 7)]);
            // Ignored signals are also "handled" (raise returns 0).
            signal(SIGTERM, SIGNAL_IGNORE);
            assert_eq!(__rt_raise(SIGTERM, 0), 0);
        }
    }

    /// Unhandled signal (default handler ran, raise returned 1) means
    /// `__rt_raise` takes the terminate branch. The full
    /// `__rt_raise -> os_terminate` chain is NOT exercisable on the host:
    /// the stub's mock panic would have to unwind across the `extern "C"`
    /// frames of `raise`/`__rt_raise`, which aborts the process by design
    /// (panic_cannot_unwind). What is covered instead:
    /// - the branch condition inputs: `raise` returns 1 on the default
    ///   path (default_handler_* tests) and 0 when handled/ignored
    ///   (rt_raise_returns_zero_when_handled), and
    /// - the terminate stub itself, called directly from Rust here.
    #[test]
    fn os_terminate_stub_is_observable() {
        let _g = LOCK.lock().unwrap();
        reset_state();
        let result = std::panic::catch_unwind(os_terminate);
        assert!(result.is_err());
        unsafe {
            assert!(*core::ptr::addr_of!(TEST_TERMINATED));
        }
    }
}
