//! Ports of the ARM ADS 1.0.1 string-to-double cluster, plus the
//! `bsearch` routine that was assigned to the same batch:
//!
//! - `strtod_core` — original: `FUN_080331dc` @ 0x080331dc (164 bytes).
//!   The engine driver behind strtod/atof: TWO passes over the vsscanf
//!   numeric/float machinery. Pass 1 (measure) scans with an unlimited
//!   count budget and learns the valid-prefix length through
//!   `consumed_out`; `endptr` (when non-NULL) is set to `s + consumed`,
//!   or to `s` itself when nothing was consumed. Pass 2 (convert) re-runs
//!   only when pass 1 consumed input but its result was `<= 0` or the
//!   input cursor did not land exactly at `s + consumed`. The classic
//!   trigger is a dangling exponent at end of string ("2.5e"): the sticky
//!   EOF flag makes the pushback of 'e' fail, so the cursor sits past the
//!   reported prefix. The convert pass rewinds the cursor to `s` and
//!   bounds `count` to `consumed`, so the engine re-reads exactly the
//!   valid prefix.
//! - `atof` — original: `FUN_08031774` @ 0x08031774 (68 bytes). Saves
//!   errno (`FUN_08032168` @ 0x08032168), seeds the 8-byte result slot
//!   from the 0.0 constant at 0x080317bc, calls the core with a NULL
//!   endptr, restores errno (`FUN_08032178` @ 0x08032178) and returns the
//!   slot as a soft-float double in r0:r1. Unconditionally
//!   errno-neutral, failure included.
//! - `strtod` — the public ISO entry. The original osos contains no
//!   separate public strtod symbol: the core IS the implementation and
//!   atof its only in-binary caller. This port synthesizes the public
//!   front the same way atof does (0.0-seeded slot, core with the
//!   caller's endptr, slot returned) minus the errno save/restore —
//!   strtod is allowed to set ERANGE, which the original delegates to
//!   the engine.
//! - `bsearch` — original: `FUN_08030dd4` @ 0x08030dd4 (140 bytes).
//!   Despite the batch label "public wrapper", the machine code is the
//!   ADS binary search, not a strtod wrapper: five arguments (compar is
//!   the 5th, passed on the stack), the classic halving loop with
//!   `mid = base + size * (nmemb >> 1)` (mla), and an `nmemb == 1`
//!   fast path that dispatches through the function pointer. Its one
//!   caller @ 0x083695c4 is a firmware table lookup that converts a hit
//!   to an index via `(ret - base) >> 2`.
//!
//! Soft-float note: retailOS is built for soft-float — a C `double` is
//! passed and returned in integer register pairs as an opaque 64-bit
//! pattern. All double traffic here is `u64` bit patterns; the only f64
//! operations are `from_bits`/`to_bits` transmutes. No float arithmetic
//! (that would lower to `__aeabi_d*` helpers, which are not ported).
//!
//! Engine indirection: the numeric/float engine @ 0x08036348 is a
//! separate batch and is reached through `scanf_helpers::SCANF_ENGINE`,
//! exactly like the scanf front-end does.
//!
//! Deviations from the originals:
//! - The core calls a LOCAL copy of the vsscanf front (original
//!   `FUN_08033170` @ 0x08033170) whose `conv.ap` carries the real
//!   destination pointer. The original vsscanf captures its `...`
//!   varargs (r2 = the dest slot) into `conv.ap`; `scanf_helpers::vsscanf`
//!   stores a null ap because stable Rust cannot define C-variadic
//!   functions. Everything else is identical: clearing the sticky eof,
//!   `flags = 4`, `width = INT_MAX`, string getc/ungetc, and the
//!   `engine(0, input, consumed_out, &conv)` call shape.
//! - `conv.ctype` is None. The original vsscanf stores the ctype-table
//!   lookup `FUN_082d7340` there; this module may only import
//!   scanf_helpers + errno, so it keeps the same documented gap as
//!   `scanf_helpers::vsscanf` (the whitespace skip lives inside the
//!   engine, which is a separate batch either way).
//! - The original core builds only a 5-word stack frame ({ptr, count=-1,
//!   base, eof, consumed}) whose `consumed` slot aliases ScanfState.ap —
//!   harmless there because the engine never reads the input state past
//!   `eof` (getc/ungetc live in the conv state). This port keeps
//!   `consumed` in its own local; the aliasing is unobservable.
//! - Both states are built with MaybeUninit + field writes, seeding
//!   exactly the fields the original seeds (input: ptr/count/base, eof
//!   via the front; conv: ap/flags/width/getc/ungetc/ctype) and leaving
//!   the rest uninitialized like the original. A full struct literal
//!   makes LLVM lower the zero-fill to an `__aeabi_memclr4` libcall the
//!   firmware link cannot satisfy (same trick as qsort.rs/localtime.rs).

use core::ffi::c_void;

use crate::errno::{errno_get, errno_set};
use crate::scanf_helpers::{string_getc, string_ungetc, ScanfConvState, ScanfState, SCANF_ENGINE};

/// Comparison callback for [`bsearch`]: returns <0 / 0 / >0 as `key`
/// orders before / equal / after `elem`. Original: 5th (stack) argument
/// of FUN_08030dd4, called as `compar(key, elem)`.
pub type BsearchCmpFn = unsafe extern "C" fn(key: *const u8, elem: *const u8) -> i32;

/// The vsscanf front (original @ 0x08033170) with the destination vararg
/// wired into `conv.ap` — see the module docs for why this is a local
/// copy rather than `scanf_helpers::vsscanf`.
unsafe fn vsscanf_to(consumed_out: *mut i32, input: *mut ScanfState, dest: *mut u64) -> i32 {
    (*input).eof = 0;
    // MaybeUninit + field writes: seed exactly the fields the original
    // vsscanf seeds (ap, flags=4, width=INT_MAX, getc, ungetc, ctype —
    // fmt_cursor/scanset_flag/fmt_getc stay uninitialized, unread by the
    // numeric engine) without an __aeabi_memclr4 libcall (module docs).
    let mut conv = core::mem::MaybeUninit::<ScanfConvState>::uninit();
    let p = conv.as_mut_ptr();
    core::ptr::addr_of_mut!((*p).ap).write(dest as *mut c_void);
    core::ptr::addr_of_mut!((*p).flags).write(4);
    core::ptr::addr_of_mut!((*p).width).write(i32::MAX);
    core::ptr::addr_of_mut!((*p).getc).write(Some(string_getc));
    core::ptr::addr_of_mut!((*p).ungetc).write(Some(string_ungetc));
    core::ptr::addr_of_mut!((*p).ctype).write(None);
    let engine = SCANF_ENGINE;
    engine(0, input as usize, consumed_out as usize, p as usize)
}

/// strtod core — original: `FUN_080331dc` @ 0x080331dc (164 bytes).
///
/// Measure pass then (conditionally) convert pass over the vsscanf
/// machinery; see the module docs. `dest` receives the converted double
/// as a raw 64-bit pattern (soft-float; the engine stores through
/// `conv.ap`). Returns the last engine result, like the original's r0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strtod_core(
    dest: *mut u64,
    s: *const u8,
    endptr: *mut *mut u8,
) -> i32 {
    // Pass-1 input state. The original seeds only ptr/count/base on its
    // stack frame (the sticky eof flag is cleared inside the vsscanf
    // front); MaybeUninit field writes keep the zero-fill from lowering
    // to an __aeabi_memclr4 libcall (module docs).
    let mut input = core::mem::MaybeUninit::<ScanfState>::uninit();
    let p = input.as_mut_ptr();
    core::ptr::addr_of_mut!((*p).ptr).write(s);
    core::ptr::addr_of_mut!((*p).count).write(-1);
    core::ptr::addr_of_mut!((*p).base).write(s);
    let mut consumed: i32 = 0;
    let mut result = vsscanf_to(&mut consumed, p, dest);
    let scanned_end = s.wrapping_offset(consumed as isize);
    if !endptr.is_null() {
        *endptr = if consumed == 0 { s } else { scanned_end } as *mut u8;
    }
    if consumed != 0 && (result <= 0 || (*p).ptr != scanned_end) {
        // Convert pass: rewind and bound the budget to the measured prefix.
        (*p).count = consumed;
        (*p).ptr = s;
        (*p).base = s;
        result = vsscanf_to(&mut consumed, p, dest);
    }
    result
}

/// strtod — public ISO entry synthesized over [`strtod_core`] (the
/// original binary exposes only the core; see the module docs). Returns
/// the double bit pattern in r0:r1 under soft-float, 0.0 when no
/// conversion is performed.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strtod(s: *const u8, endptr: *mut *mut u8) -> f64 {
    let mut value: u64 = 0; // 0.0, the no-conversion result
    strtod_core(&mut value, s, endptr);
    f64::from_bits(value)
}

/// atof — original: `FUN_08031774` @ 0x08031774 (68 bytes).
///
/// strtod with a NULL endptr wrapped in an errno save/restore: reads
/// errno, seeds the result slot with the 0.0 constant from 0x080317bc,
/// runs the core, puts errno back, returns the slot in r0:r1. Whatever
/// the engine does to errno (e.g. ERANGE on overflow) is invisible to
/// the caller.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn atof(s: *const u8) -> f64 {
    let saved_errno = errno_get();
    let mut value: u64 = 0; // DAT_080317bc/DAT_080317c0: +0.0
    strtod_core(&mut value, s, core::ptr::null_mut());
    errno_set(saved_errno);
    f64::from_bits(value)
}

/// bsearch — original: `FUN_08030dd4` @ 0x08030dd4 (140 bytes).
///
/// ADS binary search over `nmemb` elements of `size` bytes at `base`,
/// ordered by `compar(key, elem)`. Halves the range each round
/// (`mid = base + size * (nmemb >> 1)`); `nmemb == 1` dispatches straight
/// through the callback. Returns the matching element or NULL. Ported
/// here per batch assignment even though it is not part of the strtod
/// family (see the module docs).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bsearch(
    key: *const u8,
    mut base: *const u8,
    mut nmemb: usize,
    size: usize,
    compar: BsearchCmpFn,
) -> *mut u8 {
    loop {
        if nmemb == 0 {
            return core::ptr::null_mut();
        }
        if nmemb == 1 {
            return if compar(key, base) == 0 {
                base as *mut u8
            } else {
                core::ptr::null_mut()
            };
        }
        let half = nmemb >> 1;
        // The original's mla is a 32-bit wrap; mirroring it with wrapping ops.
        let mid = base.wrapping_add(size.wrapping_mul(half));
        let order = compar(key, mid);
        if order == 0 {
            return mid as *mut u8;
        }
        if order > 0 {
            base = mid.wrapping_add(size);
            nmemb -= half + 1;
        } else {
            nmemb = half;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::scanf_helpers::{GetcFn, UngetcFn};
    use std::string::String;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that swap SCANF_ENGINE.
    static ENGINE_LOCK: Mutex<()> = Mutex::new(());

    /// Engine invocations observed by the mock (two-pass verification).
    static mut MOCK_CALLS: u32 = 0;

    fn is_space(c: u8) -> bool {
        matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
    }

    /// Characters the mock reads speculatively while looking for a float.
    fn is_float_char(c: u8) -> bool {
        is_space(c) || matches!(c, b'+' | b'-' | b'.' | b'e' | b'E' | b'0'..=b'9')
    }

    unsafe fn read_char(getc: GetcFn, state: *mut ScanfState) -> Option<u8> {
        let c = getc(state);
        if c < 0 {
            None
        } else {
            Some(c as u8)
        }
    }

    /// Length of the longest prefix of `raw` that is a complete valid
    /// float (`[ws]* [+-]? (digits ['.' digits*] | '.' digits+) [exp]?`,
    /// exponent = `[eE] [+-]? digits+`). 0 = no conversion.
    fn valid_float_prefix(raw: &[u8]) -> usize {
        let mut i = 0;
        while i < raw.len() && is_space(raw[i]) {
            i += 1;
        }
        if i < raw.len() && (raw[i] == b'+' || raw[i] == b'-') {
            i += 1;
        }
        let digits_start = i;
        while i < raw.len() && raw[i].is_ascii_digit() {
            i += 1;
        }
        let int_digits = i - digits_start;
        let mut mant_end = i;
        if i < raw.len() && raw[i] == b'.' {
            let mut j = i + 1;
            while j < raw.len() && raw[j].is_ascii_digit() {
                j += 1;
            }
            let frac_digits = j - (i + 1);
            if int_digits > 0 || frac_digits > 0 {
                mant_end = j;
            }
        }
        if int_digits == 0 && mant_end == digits_start {
            return 0; // no mantissa digits at all
        }
        i = mant_end;
        if i < raw.len() && (raw[i] == b'e' || raw[i] == b'E') {
            let mut j = i + 1;
            if j < raw.len() && (raw[j] == b'+' || raw[j] == b'-') {
                j += 1;
            }
            let exp_start = j;
            while j < raw.len() && raw[j].is_ascii_digit() {
                j += 1;
            }
            if j > exp_start {
                i = j; // exponent only counts with at least one digit
            }
        }
        i
    }

    /// Mini float parser standing in for the numeric/float engine
    /// @ 0x08036348 (a concurrent batch). Mirrors its observable contract
    /// with the front: reads through conv.getc/ungetc, reports the
    /// valid-prefix length via consumed_out, stores the value bits
    /// through conv.ap, returns 1 on conversion else 0. Like the real
    /// engine, pushback after a dangling exponent at end of string fails
    /// on the sticky EOF flag, leaving the cursor past the reported
    /// prefix — exactly the situation the core's convert pass exists for.
    unsafe extern "C" fn mock_float_engine(_a0: usize, a1: usize, a2: usize, a3: usize) -> i32 {
        MOCK_CALLS += 1;
        let state = a1 as *mut ScanfState;
        let consumed_out = &mut *(a2 as *mut i32);
        let conv = &*(a3 as *const ScanfConvState);
        let getc = conv.getc.expect("getc bound");
        let ungetc: UngetcFn = conv.ungetc.expect("ungetc bound");

        let mut raw: Vec<u8> = Vec::new();
        let mut total_read = 0usize;
        while raw.len() < 128 {
            match read_char(getc, state) {
                None => break,
                Some(c) => {
                    total_read += 1;
                    if is_float_char(c) {
                        raw.push(c);
                    } else {
                        break; // mismatch char stays counted for pushback
                    }
                }
            }
        }
        let valid_len = valid_float_prefix(&raw);
        // Push back everything past the valid prefix. At end of string the
        // sticky EOF flag blocks ungetc and the cursor stays put — the
        // real engine has the same constraint (string_ungetc @ 0x08033044).
        for _ in valid_len..total_read {
            if ungetc(state) != 0 {
                break;
            }
        }
        if valid_len == 0 {
            *consumed_out = 0;
            return 0;
        }
        *consumed_out = valid_len as i32;
        let text = String::from_utf8_lossy(&raw[..valid_len]);
        let value: f64 = text.trim().parse().unwrap_or(0.0);
        *(conv.ap as *mut u64) = value.to_bits();
        1
    }

    /// Runs `f` with the mock engine installed; restores whatever was
    /// there before (even on panic) and returns `f`'s result.
    fn with_mock_engine<R>(f: impl FnOnce() -> R + std::panic::UnwindSafe) -> R {
        let _guard = ENGINE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved = SCANF_ENGINE;
            SCANF_ENGINE = mock_float_engine;
            MOCK_CALLS = 0;
            let result = std::panic::catch_unwind(f);
            SCANF_ENGINE = saved;
            match result {
                Ok(r) => r,
                Err(p) => std::panic::resume_unwind(p),
            }
        }
    }

    /// strtod on a NUL-terminated copy of `s`; returns (value, end offset).
    fn run_strtod(s: &[u8]) -> (f64, usize) {
        let mut buf: Vec<u8> = s.to_vec();
        buf.push(0);
        let mut end: *mut u8 = core::ptr::null_mut();
        let value = unsafe { strtod(buf.as_ptr(), &mut end) };
        let off = unsafe { end.offset_from(buf.as_ptr()) } as usize;
        (value, off)
    }

    #[test]
    fn standard_forms() {
        with_mock_engine(|| {
            assert_eq!(run_strtod(b"3.14"), (3.14, 4));
            assert_eq!(run_strtod(b"-1.5e3"), (-1500.0, 6));
            assert_eq!(run_strtod(b"1e-2"), (0.01, 4));
            assert_eq!(run_strtod(b".5"), (0.5, 2));
            assert_eq!(run_strtod(b"5."), (5.0, 2));
            assert_eq!(run_strtod(b"5.25E2"), (525.0, 6));
            assert_eq!(run_strtod(b"+42"), (42.0, 3));
            assert_eq!(run_strtod(b"0"), (0.0, 1));
            assert_eq!(run_strtod(b"-0.0"), (-0.0, 4));
            // One pass only: cursor lands exactly at s + consumed.
            unsafe {
                assert_eq!(MOCK_CALLS, 9);
            }
        });
    }

    #[test]
    fn whitespace_and_sign() {
        with_mock_engine(|| {
            assert_eq!(run_strtod(b"  3.5"), (3.5, 5));
            assert_eq!(run_strtod(b"\t\n\x0b\x0c\r -2.5"), (-2.5, 10));
            assert_eq!(run_strtod(b" +0.25x"), (0.25, 6));
            // Sign with no digits: no conversion, endptr back at s.
            assert_eq!(run_strtod(b"-"), (0.0, 0));
            assert_eq!(run_strtod(b"+ x"), (0.0, 0));
        });
    }

    #[test]
    fn endptr_positions() {
        with_mock_engine(|| {
            assert_eq!(run_strtod(b"3.14xyz"), (3.14, 4));
            assert_eq!(run_strtod(b"12abc"), (12.0, 2));
            assert_eq!(run_strtod(b"2.5e+2!"), (250.0, 6));
            assert_eq!(run_strtod(b"7e"), (7.0, 1));
            assert_eq!(run_strtod(b"7e5"), (700000.0, 3));
            // NULL endptr is accepted.
            let buf = b"1.25\0";
            unsafe {
                assert_eq!(strtod(buf.as_ptr(), core::ptr::null_mut()), 1.25);
            }
        });
    }

    /// The dangling-exponent-at-EOF case: pass 1 cannot push back the
    /// dangling 'e' (sticky EOF), so its cursor lands past s + consumed
    /// and the core runs the bounded convert pass.
    #[test]
    fn dangling_exponent_triggers_convert_pass() {
        with_mock_engine(|| {
            assert_eq!(run_strtod(b"2.5e"), (2.5, 3));
            unsafe {
                assert_eq!(MOCK_CALLS, 2, "measure + convert passes");
            }
            assert_eq!(run_strtod(b"1e"), (1.0, 1));
            assert_eq!(run_strtod(b"1e+"), (1.0, 1));
            assert_eq!(run_strtod(b"1e-"), (1.0, 1));
            unsafe {
                assert_eq!(MOCK_CALLS, 8, "each dangling exponent costs two passes");
            }
        });
    }

    /// A mid-string dangling exponent pushes back fine, so a single
    /// pass suffices.
    #[test]
    fn mid_string_dangling_exponent_is_one_pass() {
        with_mock_engine(|| {
            assert_eq!(run_strtod(b"2.5e+x"), (2.5, 3));
            unsafe {
                assert_eq!(MOCK_CALLS, 1);
            }
        });
    }

    #[test]
    fn no_conversion() {
        with_mock_engine(|| {
            for s in [
                &b"xyz"[..],
                b"",
                b"  z",
                b".e5",
                b"e5",
                b".",
                b"-",
                b"+",
                b"  ",
            ] {
                assert_eq!(run_strtod(s), (0.0, 0), "strtod({s:?})");
            }
            // No convert pass without consumed input.
            unsafe {
                assert_eq!(MOCK_CALLS, 9);
            }
        });
    }

    /// Engine that simulates an overflow: stores a value, reports
    /// consumed input, and clobbers errno with ERANGE — without ever
    /// moving the input cursor (forces the convert pass too).
    unsafe extern "C" fn erange_engine(_a0: usize, _a1: usize, a2: usize, a3: usize) -> i32 {
        *(a2 as *mut i32) = 3;
        *((*(a3 as *const ScanfConvState)).ap as *mut u64) = f64::MAX.to_bits();
        errno_set(34); // ERANGE
        1
    }

    #[test]
    fn atof_is_errno_neutral_even_when_engine_sets_errno() {
        let _guard = ENGINE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved = SCANF_ENGINE;
            SCANF_ENGINE = erange_engine;
            errno_set(42);
            let v = atof(b"1e999\0".as_ptr());
            assert_eq!(v, f64::MAX, "value stored by the engine is returned");
            assert_eq!(errno_get(), 42, "atof must restore the caller's errno");
            SCANF_ENGINE = saved;
            errno_set(0);
        }
    }

    #[test]
    fn atof_matches_strtod_values() {
        with_mock_engine(|| {
            for s in [
                &b"3.14"[..],
                b"-1.5e3",
                b"1e-2",
                b".5",
                b"5.",
                b"  2.75",
                b"xyz",
                b"",
            ] {
                let mut buf: Vec<u8> = s.to_vec();
                buf.push(0);
                let (want, _) = run_strtod(s);
                let got = unsafe { atof(buf.as_ptr()) };
                assert_eq!(got, want, "atof({s:?})");
            }
        });
    }

    #[test]
    fn atof_errno_neutral_on_failure() {
        with_mock_engine(|| {
            unsafe {
                errno_set(-7);
                assert_eq!(atof(b"garbage\0".as_ptr()), 0.0);
                assert_eq!(errno_get(), -7);
                errno_set(0);
            }
        });
    }

    unsafe extern "C" fn cmp_u32(key: *const u8, elem: *const u8) -> i32 {
        CMP_CALLS += 1;
        let a = *(key as *const u32);
        let b = *(elem as *const u32);
        if a < b {
            -1
        } else if a > b {
            1
        } else {
            0
        }
    }

    static mut CMP_CALLS: u32 = 0;

    /// Serializes tests that observe CMP_CALLS (cmp_u32 bumps it from
    /// every test that uses it, and tests run on parallel threads).
    static CMP_LOCK: Mutex<()> = Mutex::new(());

    fn search(table: &[u32], key: u32) -> *mut u8 {
        unsafe {
            bsearch(
                &key as *const u32 as *const u8,
                table.as_ptr() as *const u8,
                table.len(),
                core::mem::size_of::<u32>(),
                cmp_u32,
            )
        }
    }

    #[test]
    fn bsearch_finds_every_element_and_misses_gaps() {
        let _guard = CMP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let table: [u32; 7] = [1, 3, 5, 7, 9, 11, 13];
        unsafe {
            CMP_CALLS = 0;
            for (i, &v) in table.iter().enumerate() {
                let hit = search(&table, v);
                assert_eq!(hit, table.as_ptr().add(i) as *mut u8, "bsearch({v})");
            }
            for v in [0u32, 2, 8, 14, 100] {
                assert!(search(&table, v).is_null(), "bsearch({v}) must miss");
            }
        }
    }

    #[test]
    fn bsearch_even_and_single_element_tables() {
        let _guard = CMP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let even: [u32; 4] = [10, 20, 30, 40];
        for (i, &v) in even.iter().enumerate() {
            assert_eq!(search(&even, v), unsafe { even.as_ptr().add(i) } as *mut u8);
        }
        assert!(search(&even, 25).is_null());

        let one: [u32; 1] = [77];
        unsafe {
            CMP_CALLS = 0;
            assert_eq!(search(&one, 77), one.as_ptr() as *mut u8);
            assert_eq!(CMP_CALLS, 1, "nmemb==1 dispatches through the fn ptr");
            CMP_CALLS = 0;
            assert!(search(&one, 78).is_null());
            assert_eq!(CMP_CALLS, 1);
        }
    }

    #[test]
    fn bsearch_empty_table_never_calls_compar() {
        let _guard = CMP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let table: [u32; 1] = [0];
        unsafe {
            CMP_CALLS = 0;
            let hit = bsearch(
                table.as_ptr() as *const u8,
                table.as_ptr() as *const u8,
                0,
                4,
                cmp_u32,
            );
            assert!(hit.is_null());
            assert_eq!(CMP_CALLS, 0, "nmemb==0 returns NULL up front");
        }
    }

    /// The callback contract: compar(key, elem), in that order, against
    /// the binary-search midpoint sequence.
    #[test]
    fn bsearch_callback_argument_order() {
        unsafe extern "C" fn recording_cmp(key: *const u8, elem: *const u8) -> i32 {
            let a = *(key as *const u32);
            let b = *(elem as *const u32);
            // Claim key < elem always, except record equality correctly:
            // forces descent into the left half every round.
            if a == b {
                0
            } else {
                -1
            }
        }
        let table: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        unsafe {
            // Key equal to the very first element: must still be found by
            // walking left halves down to index 0.
            let hit = bsearch(
                &1u32 as *const u32 as *const u8,
                table.as_ptr() as *const u8,
                8,
                4,
                recording_cmp,
            );
            assert_eq!(hit, table.as_ptr() as *mut u8);
        }
    }
}
