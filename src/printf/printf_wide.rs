//! Port of the printf `%ls` wide-string converter — original:
//! `FUN_0803218c` @ 0x0803218c (316 bytes), called from the `%s`/`%S`
//! dispatch inside the printf core (`FUN_08034374`, call site
//! 0x080346c0) with the argument pointer and a third parameter the core
//! always sets to -1.
//!
//! Algorithm (from the disassembly), two passes over the u16 wide string:
//! 1. Measure: for each wide char, convert it with the wcrtomb-family
//!    converter @ 0x08035588 ([`crate::mbrtowc::wcrtomb`]) into an 8-byte
//!    stack buffer, accumulating the total *byte* length. With
//!    FLAG_PRECISION_GIVEN the loop stops once `precision <= byte_len`
//!    (loop head, signed) or when the next char would push the total past
//!    `precision` (unsigned compare) — precision is in BYTES of converted
//!    output, not wide chars. Chars the converter rejects (-1, in the C
//!    locale everything >= 0x80) are silently skipped: they add no bytes
//!    but do not stop the scan. The scan ends at the first NUL wide char.
//! 2. `pad_remaining -= byte_len`, then leading [`pad_emit`].
//! 3. Emit: re-convert the chars scanned in pass 1 and push each
//!    resulting byte through the state putc. Rejected chars are skipped
//!    again (the re-conversion is deterministic, so exactly the measured
//!    bytes come out).
//! 4. `count += byte_len`, then trailing [`pad_emit_zero`].
//!
//! Wide chars are u16 (`ldrh`), so only the BMP is representable — no
//! surrogate-pair handling exists in the original or here.
//!
//! Deviations from the original:
//! - The original takes a third parameter (a signed minimum char count:
//!    the scan runs unconditionally while `i < min_chars`, only checking
//!    for NUL once `i >= min_chars`). Its sole caller always passes -1,
//!    which reduces the check to a plain NUL termination, so the
//!    parameter is dropped from the signature.
//! - The conversion `mbstate` word is a fresh zeroed local per pass. The
//!    original reloads it from a global word @ 0x08985ef0 before each
//!    pass; that word is 0 in the firmware image, nothing ever writes
//!    it, and the C-locale wcrtomb path ignores it entirely.
//! - Ghidra shows the putc call masked with 0xfffffffc; the actual
//!    `mov pc, r2` has no mask, so none is applied (same as
//!    `printf_helpers`).

use crate::mbrtowc::wcrtomb;
use crate::printf_helpers::{pad_emit, pad_emit_zero, PrintfState, FLAG_PRECISION_GIVEN};

/// Conversion scratch buffer size, matching the original's 8-byte stack
/// frame (two pushed argument slots reused as scratch). The C-locale
/// converter writes at most one byte; the locale-converter path (dead on
/// retail firmware) could use the rest.
const MBUF_LEN: usize = 8;

/// convert_ls — original: `FUN_0803218c` @ 0x0803218c (316 bytes).
///
/// Emits the NUL-terminated wide string `ws` through the state putc,
/// converting each u16 wide char to bytes with [`wcrtomb`], honoring
/// FLAG_PRECISION_GIVEN (a byte budget on the converted output) and the
/// field-width padding protocol (`pad_remaining` / [`pad_emit`] /
/// [`pad_emit_zero`]).
#[no_mangle]
pub unsafe extern "C" fn convert_ls(state: *mut PrintfState, ws: *const u16) {
    let mut mbuf = [0u8; MBUF_LEN];
    let mut byte_len: i32 = 0;
    let mut char_count: i32 = 0;

    // Pass 1: measure the converted byte length (precision-capped).
    let mut mbstate: u32 = 0;
    loop {
        if (*state).flags & FLAG_PRECISION_GIVEN != 0 && (*state).precision <= byte_len {
            break;
        }
        let wc = ws.add(char_count as usize).read();
        if wc == 0 {
            break;
        }
        let n = wcrtomb(mbuf.as_mut_ptr(), wc as u32, &mut mbstate);
        if n != -1 {
            if (*state).flags & FLAG_PRECISION_GIVEN != 0
                && (byte_len.wrapping_add(n)) as u32 > (*state).precision as u32
            {
                break;
            }
            byte_len += n;
        }
        char_count += 1;
    }

    (*state).pad_remaining -= byte_len;
    pad_emit(state);

    // Pass 2: re-convert the measured chars and emit byte by byte.
    let mut mbstate: u32 = 0;
    for k in 0..char_count {
        let wc = ws.add(k as usize).read();
        let n = wcrtomb(mbuf.as_mut_ptr(), wc as u32, &mut mbstate);
        if n != -1 {
            for j in 0..n as usize {
                // Unchecked like the original's `ldrb [fp, r5]`: wcrtomb
                // wrote at most n bytes into mbuf, and the stock C-locale
                // converter never returns more than 1. A checked index
                // would drag in panic_bounds_check on device.
                let byte = *mbuf.get_unchecked(j);
                ((*state).putc)(byte, (*state).putc_ctx);
            }
        }
    }

    (*state).count += byte_len;
    pad_emit_zero(state);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::printf_helpers::FLAG_LEFT_JUSTIFY;
    use core::ffi::c_void;
    use std::vec::Vec;

    /// Recording sink, same pattern as the printf_helpers tests.
    struct Sink {
        buf: Vec<u8>,
    }

    unsafe extern "C" fn sink_putc(c: u8, ctx: *mut c_void) {
        (*(ctx as *mut Sink)).buf.push(c);
    }

    fn state(flags: u32, pad_remaining: i32, precision: i32, sink: &mut Sink) -> PrintfState {
        PrintfState {
            reserved_00: [0; 2],
            prefix: core::ptr::null(),
            reserved_0c: [0; 3],
            flags,
            putc: sink_putc,
            emit_str: None,
            putc_ctx: sink as *mut Sink as *mut c_void,
            reserved_28: [0; 3],
            pad_remaining,
            precision,
            count: 0,
        }
    }

    fn run(st: &mut PrintfState, ws: &[u16]) {
        unsafe { convert_ls(st, ws.as_ptr()) };
    }

    #[test]
    fn ascii_wide_string_plain() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(0, 0, 0, &mut sink);
        let ws: Vec<u16> = "hello".encode_utf16().chain([0]).collect();
        run(&mut st, &ws);
        assert_eq!(sink.buf, b"hello");
        assert_eq!(st.count, 5);
        assert_eq!(st.pad_remaining, -5);
    }

    #[test]
    fn empty_wide_string() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(0, 0, 0, &mut sink);
        run(&mut st, &[0]);
        assert!(sink.buf.is_empty());
        assert_eq!(st.count, 0);
        assert_eq!(st.pad_remaining, 0);
    }

    /// Wide chars < 0x80 convert; >= 0x80 are rejected by the C-locale
    /// dead path (see mbrtowc.rs) and silently skipped — the scan does
    /// NOT stop at them.
    #[test]
    fn non_ascii_wide_chars_skipped() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(0, 0, 0, &mut sink);
        // 'A', 0x80 (C locale: flag byte 0), 'B', 0x20ac (euro, > 0xff),
        // 'C', 0xff (flag byte 0), NUL.
        let ws = [0x41u16, 0x80, 0x42, 0x20ac, 0x43, 0xff, 0];
        run(&mut st, &ws);
        assert_eq!(sink.buf, b"ABC");
        assert_eq!(st.count, 3);
    }

    /// 0x7f is the last convertible value; its ctype flag (0x40) is
    /// nonzero so it passes even though it is not printable.
    #[test]
    fn boundary_char_0x7f_passes() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(0, 0, 0, &mut sink);
        let ws = [0x7fu16, 0];
        run(&mut st, &ws);
        assert_eq!(sink.buf, [0x7f]);
        assert_eq!(st.count, 1);
    }

    /// Precision is a byte budget on the converted output: the scan
    /// stops before the char that would exceed it, and padding/count are
    /// based on the truncated byte length.
    #[test]
    fn precision_truncates_bytes() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_PRECISION_GIVEN, 0, 3, &mut sink);
        let ws: Vec<u16> = "abcdef".encode_utf16().chain([0]).collect();
        run(&mut st, &ws);
        assert_eq!(sink.buf, b"abc");
        assert_eq!(st.count, 3);
        assert_eq!(st.pad_remaining, -3);
    }

    /// Precision zero emits nothing at all (loop head: 0 <= 0).
    #[test]
    fn precision_zero_emits_nothing() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_PRECISION_GIVEN, 0, 0, &mut sink);
        let ws: Vec<u16> = "abc".encode_utf16().chain([0]).collect();
        run(&mut st, &ws);
        assert!(sink.buf.is_empty());
        assert_eq!(st.count, 0);
        assert_eq!(st.pad_remaining, 0);
    }

    /// Precision larger than the string caps at the NUL terminator.
    #[test]
    fn precision_beyond_string_length() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_PRECISION_GIVEN, 0, 100, &mut sink);
        let ws: Vec<u16> = "abc".encode_utf16().chain([0]).collect();
        run(&mut st, &ws);
        assert_eq!(sink.buf, b"abc");
        assert_eq!(st.count, 3);
    }

    /// Skipped (rejected) chars consume no precision budget but do not
    /// end the scan: 'A', 0x100, 'B', 'C', 'D' with precision 2 -> "AB".
    #[test]
    fn rejected_chars_cost_no_precision() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_PRECISION_GIVEN, 0, 2, &mut sink);
        let ws = [0x41u16, 0x100, 0x42, 0x43, 0x44, 0];
        run(&mut st, &ws);
        assert_eq!(sink.buf, b"AB");
        assert_eq!(st.count, 2);
    }

    /// Right-justified field: the caller pre-loads pad_remaining with the
    /// field width; convert_ls subtracts the content bytes, pads in
    /// front, then emits the content.
    #[test]
    fn right_justified_padding() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(0, 8, 0, &mut sink);
        let ws: Vec<u16> = "ab".encode_utf16().chain([0]).collect();
        run(&mut st, &ws);
        assert_eq!(sink.buf, b"      ab");
        assert_eq!(st.count, 8);
        // pad_emit counts down a local copy; the field keeps width - len.
        assert_eq!(st.pad_remaining, 6);
    }

    /// Left-justified field: content first, trailing spaces after.
    #[test]
    fn left_justified_padding() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_LEFT_JUSTIFY, 8, 0, &mut sink);
        let ws: Vec<u16> = "ab".encode_utf16().chain([0]).collect();
        run(&mut st, &ws);
        assert_eq!(sink.buf, b"ab      ");
        assert_eq!(st.count, 8);
        assert_eq!(st.pad_remaining, 6);
    }

    /// Width already satisfied by the content: no padding either side.
    #[test]
    fn content_wider_than_field() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(0, 2, 0, &mut sink);
        let ws: Vec<u16> = "abcd".encode_utf16().chain([0]).collect();
        run(&mut st, &ws);
        assert_eq!(sink.buf, b"abcd");
        assert_eq!(st.count, 4);
        assert_eq!(st.pad_remaining, -2);
    }

    /// Precision and width together: "%8.3ls" of "abcdef".
    #[test]
    fn precision_with_padding() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_PRECISION_GIVEN, 8, 3, &mut sink);
        let ws: Vec<u16> = "abcdef".encode_utf16().chain([0]).collect();
        run(&mut st, &ws);
        assert_eq!(sink.buf, b"     abc");
        assert_eq!(st.count, 8);
        assert_eq!(st.pad_remaining, 5);
    }
}
