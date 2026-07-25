//! scanf front-end cluster for the stock firmware's scanf core
//! (ARM ADS 1.0.1): the string input source operations and the two
//! state-building entry veneers. The conversion engine itself is a
//! separate batch and is reached here through [`SCANF_ENGINE`].
//!
//! Ports:
//! - `string_getc`   @ 0x0803300c (56 bytes) — input getc for string
//!   sources: while `count != 0` and the next byte is non-NUL, return the
//!   byte, advance `ptr`, decrement `count`. Otherwise set the sticky
//!   `eof` flag and return -1. Register usage: r0 = state, result in r0.
//! - `string_ungetc` @ 0x08033044 (64 bytes) — one-character rewind:
//!   while `count != 0`, `eof` clear and `ptr > base`, step `ptr` back
//!   one and bump `count`, returning 0; else -1. Takes NO char argument
//!   (the "pushed back" char is simply whatever sits at `ptr - 1`).
//!   Register usage: r0 = state, result in r0.
//! - `getc_advance`  @ 0x0803328c (20 bytes) — cursor read + relative
//!   move used by the engine on the FORMAT string: return `**cursor`
//!   and set `*cursor += delta` (delta is 1 = consume, 0 = peek,
//!   -1 = put back). Register usage: r0 = cursor, r1 = delta, byte in r0.
//! - `sscanf`        @ 0x0802f92c (92 bytes) — builds a 52-byte
//!   [`ScanfState`] on the stack `{ptr=str, count=-1, base=str, eof=0,
//!   ap=<varargs>, getc=string_getc, ungetc=string_ungetc}` and calls
//!   the engine. Register usage: r0 = str, r1 = fmt, r2/r3... = varargs.
//! - `vsscanf`       @ 0x08033170 (108 bytes) — clears `input->eof`,
//!   builds a 36-byte [`ScanfConvState`] `{ap=<varargs>, flags=4,
//!   width=INT_MAX, getc=string_getc, ungetc=string_ungetc}` and calls
//!   the engine as `engine(0, input, consumed_out, &conv)`.
//!
//! [`ScanfState`]/[`ScanfConvState`] layouts are the ABI contract with
//! the scanf engine; offsets are taken from the original machine code
//! and must not change. The conv state is the tail of the full state:
//! `ScanfState` bytes 0x10..0x34 are layout-identical to
//! `ScanfConvState` bytes 0x00..0x24.
//!
//! Simplifications vs. the original (all in the two veneers):
//! - The original `sscanf` calls the ADS `_scanf` format engine prologue
//!   @ 0x080332a4 (which fills `fmt_cursor`, `fmt_getc`, `ctype`,
//!   `scanset_flag` and tail-calls the engine body @ 0x0803484c);
//!   `vsscanf` @ 0x08033170 calls a veneer to the numeric/float input
//!   engine @ 0x08036348. Both call targets are next-batch work, so both
//!   veneers instead call through the [`SCANF_ENGINE`] function pointer
//!   (default: [`scanf_engine_stub`]). The pointer takes four raw
//!   register-level `usize` args because the two call sites have
//!   different shapes: sscanf passes `(state, fmt, &state.ap, 0)` (the
//!   original sets only r0-r2; r3 was leftover), vsscanf passes
//!   `(0, input, consumed_out, &conv)`.
//! - The originals capture the variadic arguments by `push {r0-r3}` and
//!   set `ap` to the stacked r2 slot. Stable Rust cannot define
//!   C-variadic functions, so the Rust signatures keep only the fixed
//!   parameters (AAPCS-compatible with variadic call sites: the extra
//!   arguments land in r2/r3/stack and are simply not read) and both
//!   veneers store a null `ap`. Wiring a real va_list needs a
//!   two-instruction asm trampoline and lands with the engine batch.
//!   Everything else about the state (including passing `&state.ap` to
//!   the engine) is faithful.
//! - Fields the original leaves UNINITIALIZED (relying on the engine
//!   prologue to fill them) are zeroed/`None` here: `flags`, `width`,
//!   `fmt_cursor`, `scanset_flag`, `fmt_getc`, `ctype` in `sscanf`;
//!   `fmt_cursor`, `scanset_flag`, `fmt_getc`, `ctype` in `vsscanf`.
//!   `ctype` (original: the ctype-table lookup `FUN_082d7340`) stays
//!   `None` until the ctype port can be imported.
//! - Despite the name, `vsscanf` @ 0x08033170 is NOT ISO `vsscanf`:
//!   its caller (`FUN_080331dc`, a strtod-family wrapper) shows it scans
//!   ONE numeric/float conversion from an input state, reporting the
//!   consumed length through `consumed_out`. Named per batch assignment.

use core::ffi::c_void;

/// Input getc for scanf sources, called as `getc(state)` by the engine.
/// Returns the next character or -1 on EOF.
pub type GetcFn = unsafe extern "C" fn(state: *mut ScanfState) -> i32;

/// Input ungetc for scanf sources, called as `ungetc(state)` (no char
/// argument in this implementation). Returns 0 on success, -1 on failure.
pub type UngetcFn = unsafe extern "C" fn(state: *mut ScanfState) -> i32;

/// Format-string cursor read+move, called as `fmt_getc(&cursor, delta)`.
pub type GetcAdvanceFn = unsafe extern "C" fn(cursor: *mut *const u8, delta: i32) -> u8;

/// Whitespace test used by the engine, called as `ctype(c) != 0`.
/// Original: `FUN_082d7340` (ctype-table bit 0).
pub type CtypeFn = unsafe extern "C" fn(c: i32) -> i32;

/// Register-level engine entry: the two veneers pass different argument
/// shapes (see module docs), so the pointer is typed as four raw words.
/// Returns the engine result (conversion count / -1 on EOF-before-first).
pub type ScanfEngineFn = unsafe extern "C" fn(a0: usize, a1: usize, a2: usize, a3: usize) -> i32;

/// Full scanf state (52 bytes) as built by `sscanf` on its stack frame;
/// the ABI contract between the front-end and the engine. Offsets
/// recovered from the original machine code:
///
/// | off  | field          | evidence |
/// |------|----------------|----------|
/// | 0x00 | `ptr`          | `string_getc`/`string_ungetc` read+write `[r0]` |
/// | 0x04 | `count`        | `string_getc`/`string_ungetc` read+write `[r0,#4]`; sscanf stores -1 |
/// | 0x08 | `base`         | `string_ungetc` compares against `[r0,#8]`; sscanf stores `str` |
/// | 0x0c | `eof`          | `string_getc` writes 1 at `[r1,#12]`; `vsscanf` clears `[r1,#12]` |
/// | 0x10 | `ap`           | sscanf stores `&stacked r2`; engine prologue reads `param_3[0]` |
/// | 0x14 | `flags`        | engine writes `param_3[1]` per directive |
/// | 0x18 | `width`        | engine writes `param_3[2]` per directive |
/// | 0x1c | `fmt_cursor`   | engine prologue stores `fmt`; read via `fmt_getc` |
/// | 0x20 | `scanset_flag` | engine prologue stores 0; gates the `%[` bitmap buffer |
/// | 0x24 | `fmt_getc`     | engine prologue stores `getc_advance` |
/// | 0x28 | `getc`         | sscanf/vsscanf store `string_getc` |
/// | 0x2c | `ungetc`       | sscanf/vsscanf store `string_ungetc` |
/// | 0x30 | `ctype`        | engine prologue / vsscanf store `FUN_082d7340` |
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ScanfState {
    /// Current input position.
    pub ptr: *const u8,
    /// Remaining input budget; -1 = unlimited (decrements forever, never
    /// reaching 0 in practice). Reading stops when this hits 0.
    pub count: i32,
    /// Start of input; `ungetc` refuses to rewind below this.
    pub base: *const u8,
    /// Sticky EOF flag: set by `getc` at end of input, blocks `ungetc`.
    pub eof: i32,
    /// va_list cursor for conversion destinations (see module docs for
    /// the null-`ap` simplification).
    pub ap: *mut c_void,
    /// Conversion flags, written by the engine per directive.
    pub flags: u32,
    /// Field width, written by the engine per directive.
    pub width: i32,
    /// Format-string cursor (the engine reads the format through
    /// `fmt_getc(&fmt_cursor, delta)`).
    pub fmt_cursor: *const u8,
    /// 0 = `%[` scanset uses the engine's local bitmap buffer.
    pub scanset_flag: i32,
    /// Format-string reader (`getc_advance`).
    pub fmt_getc: Option<GetcAdvanceFn>,
    /// Input reader (`string_getc` for string sources).
    pub getc: Option<GetcFn>,
    /// Input rewinder (`string_ungetc` for string sources).
    pub ungetc: Option<UngetcFn>,
    /// Whitespace test (`FUN_082d7340` in the original).
    pub ctype: Option<CtypeFn>,
}

/// Conversion sub-state (36 bytes) as built by `vsscanf` on its stack
/// frame; layout-identical to `ScanfState` bytes 0x10..0x34 (the engine
/// addresses it as `param_4[0..8]`, matching the table above rebased to
/// 0x00).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ScanfConvState {
    /// 0x00: va_list cursor for conversion destinations.
    pub ap: *mut c_void,
    /// 0x04: conversion flags (vsscanf seeds 4; the format engine
    /// overwrites per directive).
    pub flags: u32,
    /// 0x08: field width (vsscanf seeds `i32::MAX`).
    pub width: i32,
    /// 0x0c: format cursor (unused by the numeric engine).
    pub fmt_cursor: *const u8,
    /// 0x10: scanset flag (unused by the numeric engine).
    pub scanset_flag: i32,
    /// 0x14: format reader (unused by the numeric engine).
    pub fmt_getc: Option<GetcAdvanceFn>,
    /// 0x18: input reader.
    pub getc: Option<GetcFn>,
    /// 0x1c: input rewinder.
    pub ungetc: Option<UngetcFn>,
    /// 0x20: whitespace test.
    pub ctype: Option<CtypeFn>,
}

/// Placeholder for the scanf engine (numeric/float input engine
/// @ 0x08036348 and the `_scanf` format engine @ 0x080332a4, both a
/// later batch). Reports "no conversions performed".
unsafe extern "C" fn scanf_engine_stub(_a0: usize, _a1: usize, _a2: usize, _a3: usize) -> i32 {
    0
}

/// Engine entry point called by both veneers; swap in the real engine
/// when its batch lands. Defaults to [`scanf_engine_stub`].
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut SCANF_ENGINE: ScanfEngineFn = scanf_engine_stub;

/// `string_getc` — original: `FUN_0803300c` @ 0x0803300c (56 bytes).
///
/// Reads one character from a string input state. Only while
/// `count != 0` and the byte at `ptr` is non-NUL: decrement `count`
/// (wrapping, matching `sub r2,r2,#1` — a -1 budget just ramps down
/// through the negatives), advance `ptr`, return the byte. Otherwise
/// set the sticky `eof` flag and return -1 WITHOUT advancing `ptr`
/// (the original's post-index writeback is discarded by the `strne`
/// guard).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_getc(state: *mut ScanfState) -> i32 {
    let s = &mut *state;
    if s.count != 0 {
        let c = *s.ptr;
        if c != 0 {
            s.count = s.count.wrapping_sub(1);
            s.ptr = s.ptr.add(1);
            return c as i32;
        }
    }
    s.eof = 1;
    -1
}

/// `string_ungetc` — original: `FUN_08033044` @ 0x08033044 (64 bytes).
///
/// Rewinds the input cursor by one character (no char argument — the
/// byte at `ptr - 1` is implicitly "pushed back"). Fails with -1 when
/// `count == 0`, when `eof` is set (EOF is sticky: a read that hit the
/// end cannot be unwound), or when `ptr == base`. NOT limited to one
/// level: repeated calls rewind down to `base`, bumping `count` each
/// time.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_ungetc(state: *mut ScanfState) -> i32 {
    let s = &mut *state;
    if s.count == 0 || s.eof != 0 {
        return -1;
    }
    if s.base != s.ptr {
        s.count = s.count.wrapping_add(1);
        s.ptr = s.ptr.sub(1);
        return 0;
    }
    -1
}

/// `getc_advance` — original: `FUN_0803328c` @ 0x0803328c (20 bytes).
///
/// Returns the byte at `*cursor` and then moves `*cursor` by `delta`
/// (1 = consume, 0 = peek, -1 = step back). The engine drives the
/// format string through this.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn getc_advance(cursor: *mut *const u8, delta: i32) -> u8 {
    let p = *cursor;
    *cursor = p.wrapping_offset(delta as isize);
    *p
}

/// `sscanf` — original: `FUN_0802f92c` @ 0x0802f92c (92 bytes).
///
/// Builds the 52-byte [`ScanfState`] for a NUL-terminated string source
/// (`ptr = base = str`, `count = -1` i.e. unlimited, `eof = 0`, string
/// getc/ungetc bound) and calls the scanf engine as
/// `engine(state, fmt, &state.ap)`. Returns the engine's result.
///
/// See the module docs for the two simplifications: the variadic `ap`
/// is null (stable Rust cannot define C-variadic functions or address
/// `...` arguments; the Rust signature keeps only the fixed params,
/// which is AAPCS-compatible with variadic call sites — extra arguments
/// simply land in r2/r3/stack unread) and the engine is reached through
/// [`SCANF_ENGINE`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sscanf(str: *const u8, fmt: *const u8) -> i32 {
    let mut state = ScanfState {
        ptr: str,
        count: -1,
        base: str,
        eof: 0,
        ap: core::ptr::null_mut(),
        // Uninitialized in the original; filled by the engine prologue.
        flags: 0,
        width: 0,
        fmt_cursor: core::ptr::null(),
        scanset_flag: 0,
        fmt_getc: None,
        getc: Some(string_getc),
        ungetc: Some(string_ungetc),
        ctype: None,
    };
    let engine = SCANF_ENGINE;
    engine(
        &mut state as *mut ScanfState as usize,
        fmt as usize,
        &mut state.ap as *mut *mut c_void as usize,
        0,
    )
}

/// `vsscanf` — original: `FUN_08033170` @ 0x08033170 (108 bytes).
///
/// Front for scanning a single numeric/float conversion from a string
/// input state (see the module docs for why this is not ISO `vsscanf`).
/// Clears `input->eof`, builds the 36-byte [`ScanfConvState`]
/// (`flags = 4`, `width = INT_MAX`, string getc/ungetc bound, `ap` from
/// the varargs) and calls the engine as
/// `engine(0, input, consumed_out, &conv)`.
///
/// Register usage: r0 = `consumed_out`, r1 = `input`, r2/r3... =
/// varargs (captured into `conv.ap`; null in this port, and the `...`
/// omitted from the Rust signature — see module docs).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vsscanf(consumed_out: *mut i32, input: *mut ScanfState) -> i32 {
    (*input).eof = 0;
    let mut conv = ScanfConvState {
        ap: core::ptr::null_mut(),
        flags: 4,
        width: i32::MAX,
        fmt_cursor: core::ptr::null(),
        scanset_flag: 0,
        fmt_getc: None,
        getc: Some(string_getc),
        ungetc: Some(string_ungetc),
        ctype: None,
    };
    let engine = SCANF_ENGINE;
    engine(
        0,
        input as usize,
        consumed_out as usize,
        &mut conv as *mut ScanfConvState as usize,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that swap SCANF_ENGINE (and the default-stub
    /// test, which must not observe a swapped engine).
    static ENGINE_LOCK: Mutex<()> = Mutex::new(());

    fn str_state(s: &[u8], count: i32) -> ScanfState {
        ScanfState {
            ptr: s.as_ptr(),
            count,
            base: s.as_ptr(),
            eof: 0,
            ap: core::ptr::null_mut(),
            flags: 0,
            width: 0,
            fmt_cursor: core::ptr::null(),
            scanset_flag: 0,
            fmt_getc: None,
            getc: None,
            ungetc: None,
            ctype: None,
        }
    }

    /// Raw offsets only hold on the 32-bit ARM target; on 64-bit hosts
    /// the pointer fields widen. Functional behavior is host-testable
    /// either way since all access goes through named fields.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn struct_layout_matches_original() {
        assert_eq!(core::mem::size_of::<ScanfState>(), 0x34);
        assert_eq!(core::mem::offset_of!(ScanfState, ptr), 0x00);
        assert_eq!(core::mem::offset_of!(ScanfState, count), 0x04);
        assert_eq!(core::mem::offset_of!(ScanfState, base), 0x08);
        assert_eq!(core::mem::offset_of!(ScanfState, eof), 0x0c);
        assert_eq!(core::mem::offset_of!(ScanfState, ap), 0x10);
        assert_eq!(core::mem::offset_of!(ScanfState, flags), 0x14);
        assert_eq!(core::mem::offset_of!(ScanfState, width), 0x18);
        assert_eq!(core::mem::offset_of!(ScanfState, fmt_cursor), 0x1c);
        assert_eq!(core::mem::offset_of!(ScanfState, scanset_flag), 0x20);
        assert_eq!(core::mem::offset_of!(ScanfState, fmt_getc), 0x24);
        assert_eq!(core::mem::offset_of!(ScanfState, getc), 0x28);
        assert_eq!(core::mem::offset_of!(ScanfState, ungetc), 0x2c);
        assert_eq!(core::mem::offset_of!(ScanfState, ctype), 0x30);
        assert_eq!(core::mem::size_of::<ScanfConvState>(), 0x24);
        assert_eq!(core::mem::offset_of!(ScanfConvState, ap), 0x00);
        assert_eq!(core::mem::offset_of!(ScanfConvState, flags), 0x04);
        assert_eq!(core::mem::offset_of!(ScanfConvState, width), 0x08);
        assert_eq!(core::mem::offset_of!(ScanfConvState, getc), 0x18);
        assert_eq!(core::mem::offset_of!(ScanfConvState, ungetc), 0x1c);
        assert_eq!(core::mem::offset_of!(ScanfConvState, ctype), 0x20);
    }

    /// The conv state is the tail of the full state (the engine
    /// addresses both as `param_4[N]`): every conv field must sit at the
    /// same offset past `ap` in both structs, on any pointer width.
    #[test]
    fn conv_state_is_full_state_tail() {
        use core::mem::offset_of;
        let full = offset_of!(ScanfState, ap);
        assert_eq!(offset_of!(ScanfState, flags) - full, offset_of!(ScanfConvState, flags));
        assert_eq!(offset_of!(ScanfState, width) - full, offset_of!(ScanfConvState, width));
        assert_eq!(offset_of!(ScanfState, fmt_cursor) - full, offset_of!(ScanfConvState, fmt_cursor));
        assert_eq!(
            offset_of!(ScanfState, scanset_flag) - full,
            offset_of!(ScanfConvState, scanset_flag)
        );
        assert_eq!(offset_of!(ScanfState, fmt_getc) - full, offset_of!(ScanfConvState, fmt_getc));
        assert_eq!(offset_of!(ScanfState, getc) - full, offset_of!(ScanfConvState, getc));
        assert_eq!(offset_of!(ScanfState, ungetc) - full, offset_of!(ScanfConvState, ungetc));
        assert_eq!(offset_of!(ScanfState, ctype) - full, offset_of!(ScanfConvState, ctype));
    }

    #[test]
    fn getc_returns_chars_and_advances() {
        let mut s = str_state(b"hi\0", -1);
        unsafe {
            assert_eq!(string_getc(&mut s), 'h' as i32);
            assert_eq!(s.ptr, b"hi\0".as_ptr().add(1));
            assert_eq!(s.count, -2);
            assert_eq!(string_getc(&mut s), 'i' as i32);
            assert_eq!(s.count, -3);
            assert_eq!(s.eof, 0);
        }
    }

    #[test]
    fn getc_reports_eof_at_nul_without_advancing() {
        let buf = b"a\0";
        let mut s = str_state(buf, -1);
        unsafe {
            assert_eq!(string_getc(&mut s), 'a' as i32);
            assert_eq!(string_getc(&mut s), -1);
            assert_eq!(s.eof, 1);
            // ptr stays ON the NUL (original discards the writeback).
            assert_eq!(s.ptr, buf.as_ptr().add(1));
            // EOF is sticky.
            assert_eq!(string_getc(&mut s), -1);
            assert_eq!(s.ptr, buf.as_ptr().add(1));
        }
    }

    #[test]
    fn getc_honors_count_budget() {
        let buf = b"ab\0";
        let mut s = str_state(buf, 1);
        unsafe {
            assert_eq!(string_getc(&mut s), 'a' as i32);
            assert_eq!(s.count, 0);
            // count == 0 stops reads even though input remains.
            assert_eq!(string_getc(&mut s), -1);
            assert_eq!(s.eof, 1);
            assert_eq!(s.ptr, buf.as_ptr().add(1));
        }
    }

    #[test]
    fn ungetc_rewinds_until_base() {
        let buf = b"ab\0";
        let mut s = str_state(buf, -1);
        unsafe {
            // Ungetc with nothing read: at base already.
            assert_eq!(string_ungetc(&mut s), -1);
            assert_eq!(string_getc(&mut s), 'a' as i32);
            assert_eq!(string_getc(&mut s), 'b' as i32);
            // Not one-level: rewinds repeatedly down to base.
            assert_eq!(string_ungetc(&mut s), 0);
            assert_eq!(s.ptr, buf.as_ptr().add(1));
            assert_eq!(s.count, -2);
            assert_eq!(string_ungetc(&mut s), 0);
            assert_eq!(s.ptr, buf.as_ptr());
            assert_eq!(s.count, -1);
            assert_eq!(string_ungetc(&mut s), -1);
            // Re-reads the same characters after rewind.
            assert_eq!(string_getc(&mut s), 'a' as i32);
        }
    }

    #[test]
    fn ungetc_fails_after_eof() {
        let buf = b"a\0";
        let mut s = str_state(buf, -1);
        unsafe {
            assert_eq!(string_getc(&mut s), 'a' as i32);
            assert_eq!(string_getc(&mut s), -1);
            // Sticky EOF blocks ungetc even though ptr > base.
            assert_eq!(string_ungetc(&mut s), -1);
            assert_eq!(s.ptr, buf.as_ptr().add(1));
        }
    }

    #[test]
    fn ungetc_fails_when_count_exhausted() {
        let buf = b"a\0";
        let mut s = str_state(buf, 0);
        unsafe {
            assert_eq!(string_ungetc(&mut s), -1);
        }
    }

    #[test]
    fn getc_advance_peek_consume_and_back() {
        let fmt = b"%d\0";
        let mut cursor = fmt.as_ptr();
        unsafe {
            // delta = 0: peek without moving.
            assert_eq!(getc_advance(&mut cursor, 0), b'%');
            assert_eq!(cursor, fmt.as_ptr());
            // delta = 1: consume.
            assert_eq!(getc_advance(&mut cursor, 1), b'%');
            assert_eq!(cursor, fmt.as_ptr().add(1));
            assert_eq!(getc_advance(&mut cursor, 1), b'd');
            // delta = -1: step back; re-read the same byte.
            assert_eq!(getc_advance(&mut cursor, -1), b'\0');
            assert_eq!(cursor, fmt.as_ptr().add(1));
            assert_eq!(getc_advance(&mut cursor, 0), b'd');
        }
    }

    /// Recording engine used to verify both veneers' calls. The states
    /// the veneers build live on THEIR stack frames, so the stub copies
    /// them out while the call is live.
    static mut RECORDED_ARGS: Option<(usize, usize, usize, usize)> = None;
    static mut RECORDED_STATE: Option<ScanfState> = None;
    static mut RECORDED_CONV: Option<ScanfConvState> = None;

    unsafe extern "C" fn recording_engine(a0: usize, a1: usize, a2: usize, a3: usize) -> i32 {
        RECORDED_ARGS = Some((a0, a1, a2, a3));
        // sscanf passes the full state in a0; vsscanf passes 0 there and
        // the conv state in a3.
        RECORDED_STATE = if a0 != 0 {
            Some(*(a0 as *const ScanfState))
        } else {
            None
        };
        RECORDED_CONV = if a3 != 0 {
            Some(*(a3 as *const ScanfConvState))
        } else {
            None
        };
        7
    }

    fn engine_lock() -> std::sync::MutexGuard<'static, ()> {
        // Stay usable even if an earlier test panicked mid-call.
        ENGINE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn sscanf_builds_state_and_calls_engine() {
        let _guard = engine_lock();
        let input = b"123 abc\0";
        let fmt = b"%d\0";
        unsafe {
            SCANF_ENGINE = recording_engine;
            RECORDED_ARGS = None;
            let ret = sscanf(input.as_ptr(), fmt.as_ptr());
            assert_eq!(ret, 7, "engine result is returned");
            let (a0, a1, a2, _) = RECORDED_ARGS.expect("engine invoked");
            assert_eq!(a1, fmt.as_ptr() as usize);
            assert_eq!(a2, a0 + core::mem::offset_of!(ScanfState, ap));
            let state = RECORDED_STATE.expect("sscanf passes the full state");
            assert_eq!(state.ptr, input.as_ptr());
            assert_eq!(state.base, input.as_ptr());
            assert_eq!(state.count, -1);
            assert_eq!(state.eof, 0);
            assert_eq!(state.getc.map(|f| f as usize), Some(string_getc as usize));
            assert_eq!(
                state.ungetc.map(|f| f as usize),
                Some(string_ungetc as usize)
            );
            SCANF_ENGINE = scanf_engine_stub;
        }
    }

    #[test]
    fn vsscanf_builds_conv_state_and_calls_engine() {
        let _guard = engine_lock();
        let buf = b"2.5\0";
        let mut input = str_state(buf, -1);
        input.eof = 1; // must be cleared by the front
        let mut consumed = -9i32;
        unsafe {
            SCANF_ENGINE = recording_engine;
            RECORDED_ARGS = None;
            let ret = vsscanf(&mut consumed, &mut input);
            assert_eq!(ret, 7);
            assert_eq!(input.eof, 0, "front clears the sticky eof flag");
            let (a0, a1, a2, _) = RECORDED_ARGS.expect("engine invoked");
            assert_eq!(a0, 0);
            assert_eq!(a1, &mut input as *mut _ as usize);
            assert_eq!(a2, &mut consumed as *mut _ as usize);
            let conv = RECORDED_CONV.expect("vsscanf passes a conv state");
            assert_eq!(conv.flags, 4);
            assert_eq!(conv.width, i32::MAX);
            assert_eq!(conv.getc.map(|f| f as usize), Some(string_getc as usize));
            assert_eq!(
                conv.ungetc.map(|f| f as usize),
                Some(string_ungetc as usize)
            );
            SCANF_ENGINE = scanf_engine_stub;
        }
    }

    #[test]
    fn default_engine_stub_reports_no_conversions() {
        let _guard = engine_lock();
        unsafe {
            assert_eq!(sscanf(b"1\0".as_ptr(), b"%d\0".as_ptr()), 0);
            let mut input = str_state(b"1\0", -1);
            let mut consumed = 0i32;
            assert_eq!(vsscanf(&mut consumed, &mut input), 0);
        }
    }
}
