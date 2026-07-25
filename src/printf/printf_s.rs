//! printf `%s` converter: measures the argument string, shrinks
//! `pad_remaining` by its length, and brackets the content between the
//! leading/trailing pad emitters from `printf_helpers`.
//!
//! Port:
//! - `convert_s` @ 0x0802f2e8 (156 bytes) — string converter. Length is a
//!   plain NUL scan, truncated to `precision` chars when
//!   FLAG_PRECISION_GIVEN. Then: `pad_remaining -= len`, [`pad_emit`]
//!   (leading pad), `emit_str(state, s, s + len)` for the content,
//!   `count += len`, [`pad_emit_zero`] (trailing pad).
//!
//! Simplifications / deviations vs. the original:
//! - The original takes a third argument `min_len` in r2: 0xffffffff (-1)
//!   for `%s`, 1 for `%c` (so `%c` of `'\0'` still measures length 1). The
//!   scan looped while `len < min_len || s[len] != '\0'`; with
//!   `min_len == -1` that signed test is a no-op, so the `%s` path is
//!   exactly a plain NUL scan and this port drops the parameter. A `%c`
//!   converter must handle its own one-char case instead of reusing this
//!   function with `min_len == 1`.
//! - NULL `s`: the original performs no NULL check — it reads the string
//!   from address 0 and prints whatever bytes happen to live there. A null
//!   raw-pointer read is UB in Rust (and untestable on the host), so this
//!   port treats NULL as an empty string: only field-width padding is
//!   emitted.
//! - Zero pad: like the original, FLAG_ZERO_PAD is NOT special-cased for
//!   `%s`; right-justified fields are padded with `'0'` by [`pad_emit`]
//!   (glibc prints "000ab" for "%05s" too). Trailing padding for
//!   left-justified fields is always spaces, via [`pad_emit_zero`].
//! - The unbounded (no-precision) scan is expressed as the precision loop
//!   with limit `i32::MAX` so LLVM does not rewrite it into a `strlen`
//!   libcall the original does not make (the crate has no `strlen`).

use crate::printf_helpers::{pad_emit, pad_emit_zero, PrintfState, FLAG_PRECISION_GIVEN};

/// `convert_s` — original: `FUN_0802f2e8` @ 0x0802f2e8 (156 bytes).
///
/// `%s` converter: emits the NUL-terminated string at `s` (at most
/// `precision` chars when FLAG_PRECISION_GIVEN) with field-width padding
/// on the correct side. The content itself goes out through the state's
/// `emit_str` hook as a `[begin, end)` slice; padding goes through the
/// state's `putc`. `count` is bumped by the content length (the pad
/// emitters account for their own chars).
///
/// `emit_str` must be set — the original calls through the pointer at
/// state+0x20 unconditionally.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn convert_s(state: *mut PrintfState, s: *const u8) {
    // Measure: plain NUL scan, truncated to `precision` when given.
    // Original loop: `cmp precision,len; ble done` (signed), so a
    // non-positive precision yields length 0. The unbounded scan is
    // written as the same loop with limit i32::MAX: identical semantics
    // (a >2 GiB string is impossible on this target), and it stops LLVM
    // from idiom-recognizing the loop into a `strlen` libcall the
    // original does not make.
    let mut len: i32 = 0;
    if !s.is_null() {
        let limit = if (*state).flags & FLAG_PRECISION_GIVEN != 0 {
            (*state).precision
        } else {
            i32::MAX
        };
        while len < limit && *s.add(len as usize) != 0 {
            len += 1;
        }
    }

    (*state).pad_remaining -= len;
    pad_emit(state);
    let emit_str = (*state).emit_str.unwrap_unchecked();
    emit_str(state, s, s.wrapping_add(len as usize));
    // Re-read after the hook: the original loads count after emit_str
    // returns, so a hook that mutates the state is honored.
    (*state).count += len;
    pad_emit_zero(state);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::printf_helpers::{PutcFn, FLAG_LEFT_JUSTIFY, FLAG_ZERO_PAD};
    use core::ffi::c_void;
    use std::vec::Vec;

    /// Records the exact output stream: pad chars arrive via `putc`,
    /// content via `emit_str`. `calls` captures the raw begin/end pointer
    /// pairs so slice boundaries can be asserted too.
    struct Recorder {
        out: Vec<u8>,
        calls: Vec<(usize, usize)>,
    }

    unsafe extern "C" fn rec_putc(c: u8, ctx: *mut c_void) {
        (*(ctx as *mut Recorder)).out.push(c);
    }

    unsafe extern "C" fn rec_emit_str(state: *mut PrintfState, begin: *const u8, end: *const u8) {
        let rec = &mut *((*state).putc_ctx as *mut Recorder);
        rec.calls.push((begin as usize, end as usize));
        // Pointer arithmetic only: begin may be null (empty content).
        let n = (end as usize).wrapping_sub(begin as usize);
        for i in 0..n {
            rec.out.push(*begin.add(i));
        }
    }

    fn run(flags: u32, width: i32, precision: i32, s: *const u8) -> (Recorder, PrintfState) {
        let mut rec = Recorder {
            out: Vec::new(),
            calls: Vec::new(),
        };
        let mut st = PrintfState {
            reserved_00: [0; 2],
            prefix: core::ptr::null(),
            reserved_0c: [0; 3],
            flags,
            putc: rec_putc as PutcFn,
            emit_str: Some(rec_emit_str),
            putc_ctx: &mut rec as *mut Recorder as *mut c_void,
            reserved_28: [0; 3],
            pad_remaining: width,
            precision,
            count: 0,
        };
        unsafe { convert_s(&mut st, s) };
        (rec, st)
    }

    #[test]
    fn plain_string_no_padding() {
        let (rec, st) = run(0, 0, 0, b"hello\0".as_ptr());
        assert_eq!(rec.out, b"hello");
        assert_eq!(rec.calls.len(), 1);
        assert_eq!(rec.calls[0].1 - rec.calls[0].0, 5);
        assert_eq!(st.count, 5);
        assert_eq!(st.pad_remaining, -5);
    }

    #[test]
    fn right_justified_width_pads_leading_spaces() {
        let (rec, st) = run(0, 8, 0, b"hello\0".as_ptr());
        assert_eq!(rec.out, b"   hello");
        assert_eq!(st.count, 8);
        // convert_s only subtracts the content length; pad_emit does not
        // consume the field.
        assert_eq!(st.pad_remaining, 3);
    }

    #[test]
    fn left_justified_width_pads_trailing_spaces() {
        let (rec, st) = run(FLAG_LEFT_JUSTIFY, 8, 0, b"hello\0".as_ptr());
        assert_eq!(rec.out, b"hello   ");
        assert_eq!(st.count, 8);
    }

    #[test]
    fn zero_pad_uses_zeros_when_right_justified() {
        // The original does not suppress the 0 flag for %s: pad_emit fills
        // with '0' (glibc behaves the same). Trailing pad stays spaces.
        let (rec, st) = run(FLAG_ZERO_PAD, 8, 0, b"hello\0".as_ptr());
        assert_eq!(rec.out, b"000hello");
        assert_eq!(st.count, 8);

        let (rec, _) = run(FLAG_LEFT_JUSTIFY | FLAG_ZERO_PAD, 8, 0, b"hello\0".as_ptr());
        assert_eq!(rec.out, b"hello   ");
    }

    #[test]
    fn precision_truncates() {
        let (rec, st) = run(FLAG_PRECISION_GIVEN, 0, 3, b"hello\0".as_ptr());
        assert_eq!(rec.out, b"hel");
        assert_eq!(rec.calls[0].1 - rec.calls[0].0, 3);
        assert_eq!(st.count, 3);
    }

    #[test]
    fn precision_longer_than_string_stops_at_nul() {
        let (rec, st) = run(FLAG_PRECISION_GIVEN, 0, 10, b"hi\0".as_ptr());
        assert_eq!(rec.out, b"hi");
        assert_eq!(st.count, 2);
    }

    #[test]
    fn precision_zero_emits_only_padding() {
        let (rec, st) = run(FLAG_PRECISION_GIVEN, 4, 0, b"hello\0".as_ptr());
        assert_eq!(rec.out, b"    ");
        assert_eq!(rec.calls[0].1 - rec.calls[0].0, 0);
        assert_eq!(st.count, 4);
    }

    #[test]
    fn negative_precision_emits_nothing() {
        // Original: signed `ble` exits the scan immediately.
        let (rec, st) = run(FLAG_PRECISION_GIVEN, 0, -1, b"hello\0".as_ptr());
        assert_eq!(rec.out, b"");
        assert_eq!(st.count, 0);
    }

    #[test]
    fn precision_with_width_and_justify() {
        // "%-8.3s" of "hello": "hel" + 5 trailing spaces.
        let (rec, st) = run(FLAG_LEFT_JUSTIFY | FLAG_PRECISION_GIVEN, 8, 3, b"hello\0".as_ptr());
        assert_eq!(rec.out, b"hel     ");
        assert_eq!(st.count, 8);
        // "%8.3s": 5 leading spaces + "hel".
        let (rec, st) = run(FLAG_PRECISION_GIVEN, 8, 3, b"hello\0".as_ptr());
        assert_eq!(rec.out, b"     hel");
        assert_eq!(st.count, 8);
    }

    #[test]
    fn empty_string_emits_only_padding() {
        let (rec, st) = run(0, 3, 0, b"\0".as_ptr());
        assert_eq!(rec.out, b"   ");
        assert_eq!(rec.calls[0].1 - rec.calls[0].0, 0);
        assert_eq!(st.count, 3);
    }

    #[test]
    fn null_pointer_treated_as_empty() {
        // Deviation from the original (which dereferences address 0); see
        // the module header. Padding still honors the field width.
        let (rec, st) = run(0, 4, 0, core::ptr::null());
        assert_eq!(rec.out, b"    ");
        assert_eq!(rec.calls, std::vec![(0, 0)]);
        assert_eq!(st.count, 4);
        // Same with a precision given.
        let (rec, _) = run(FLAG_PRECISION_GIVEN, 0, 6, core::ptr::null());
        assert_eq!(rec.out, b"");
        assert_eq!(rec.calls, std::vec![(0, 0)]);
    }
}
