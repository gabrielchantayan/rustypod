//! `_scanf` format engine for the stock firmware's scanf core
//! (ARM ADS 1.0.1): the format-string prologue and the format walker.
//!
//! Ports:
//! - `scanf_engine_prologue` — original: `FUN_080332a4` @ 0x080332a4
//!   (44 bytes including the literal-pool word @ 0x080332cc). The ADS
//!   `_scanf` entry: fills the conv-state fields the veneers leave unset
//!   (`fmt_cursor = fmt`, `fmt_getc = getc_advance`,
//!   `ctype = ctype_is_space`, `scanset_flag = 0`) and tail-calls the
//!   walker. Register usage: r0 = `input`, r1 = `fmt`, r2 = `conv`
//!   (r3 is ignored — the sscanf veneer passes a leftover there).
//!   ABI-compatible with the 4-word [`crate::scanf_helpers::SCANF_ENGINE`]
//!   slot: the extra register is simply not read.
//! - `scanf_engine_walk` — original: `FUN_0803484c` @ 0x0803484c
//!   (1564 bytes). The format walker. Register usage: r0 = `input`
//!   (full [`ScanfState`], the getc/ungetc argument), r1 = `conv`
//!   ([`ScanfConvState`]). Result in r0: number of conversions assigned,
//!   or -1 when EOF hit before the first field completed.
//!
//! Walker algorithm (recovered from the machine code, cross-checked
//! against the Ghidra decompile):
//! 1. Main loop reads the format through `fmt_getc(&conv.fmt_cursor, d)`
//!    (d = 1 consume, 0 peek, -1 put back). NUL ends the format and
//!    returns the conversion count.
//! 2. A whitespace char in the format consumes the rest of the format
//!    whitespace run, then matches ANY amount of input whitespace (each
//!    input char counted in `consumed`); the terminating input char is
//!    pushed back with `ungetc`.
//! 3. Any other non-`%` char must match the next input char exactly
//!    (counted in `consumed`). On mismatch the input char is pushed back
//!    and the walk ends: plain mismatch returns the count, EOF returns
//!    -1 only when no conversion has completed yet.
//! 4. `%` directives: optional `*` (SUPPRESS), optional decimal width
//!    (parse overflows — width > INT_MAX/10 before accumulation, or a
//!    negative result after — end the walk returning the count; no width
//!    defaults to INT_MAX), optional length modifier (`l`/`ll`, `L`,
//!    `h`/`hh`, `j` = `ll`, `t`/`z` = no flag). `conv.flags`/`conv.width`
//!    are stored before dispatch.
//! 5. Dispatch: `%d`/`%u` (base 10), `%i` (base 0), `%o` (base 8),
//!    `%x`/`%X`/`%p` (base 16) set SIGN_OK (except `%p`, which also
//!    clears hh/h/l/ll) and tail-call [`scanf_convert_int`]. `%%` matches
//!    a literal `%` (not a conversion). `%n` stores `consumed` through
//!    the next `ap` slot (byte/halfword/word, plus a sign-extension word
//!    with `ll`) WITHOUT checking SUPPRESS and without counting. Unknown
//!    directives end the walk returning the count.
//! 6. Converter results: >= 0 adds to `consumed`, bumps the conversion
//!    count unless SUPPRESS, and clears the "first field" flag; -1 (EOF)
//!    returns -1 only while the first-field flag is still set, else the
//!    count; -2 (matching failure) returns the count.
//!
//! The `%s`/`%c`/`%[` STRING CONVERTERS DO NOT EXIST in this build: all
//! four call sites in the original (local bitmap vs. external scanset,
//! crossed with narrow vs. `l`) are literal `nop`s (0x08034dd4/0x0dc/
//! 0x0e0c/0x0e14), so r0 keeps its incoming -2 and these directives
//! ALWAYS end the walk as a matching failure. The same is true for the
//! `%ll` integer converter (0x08034bb0). What the walker still does for
//! `%[` — and what is ported here — is the INLINE scanset parse: `^`
//! negation, a leading `]` as a literal set member, a 256-bit bitmap in
//! an 8-word stack buffer, and NO `-` range support (a `-` is just a
//! set member).
//!
//! Simplifications / deviations vs. the original:
//! - Float directives (`%e`/`%E`/`%f`/`%g`/`%a`/`%A`/`%F`/`%G`) are
//!   dispatched through the [`SCANF_FLOAT_ENGINE`] hook (default:
//!   [`scanf_float_engine_stub`] = matching failure) instead of the
//!   original's direct `bl` to the thunk @ 0x083ed1b8 (`b 0x08036348`):
//!   the float input engine @ 0x08036348 is a concurrent batch port and
//!   cannot be imported yet. The hook mirrors the original call site's
//!   ABI exactly (r0 = -2 unused, r1 = input, r2 = scratch out-int on
//!   the walker's frame, r3 = conv), so wiring is a one-line assignment.
//! - The ctype fn stored by the prologue is a private copy of
//!   `FUN_082d7340`'s semantics (ADS ctype table bit 0 = whitespace:
//!   space plus \t..\r). The original would resolve a -1 (EOF) argument
//!   by reading the byte before the table; this port simply returns 0
//!   for anything outside the whitespace set, which is the only
//!   observable behavior the walker relies on (EOF terminates the
//!   whitespace loops).
//! - The original's signed-shift dance for the scanset bit index
//!   (`c + (c>>31 >>> 27)` etc.) handles negative characters; format
//!   chars are u8 (0..=255), so plain unsigned indexing is used.
//! - Ghidra shows getc/ungetc/ctype/fmt_getc calls through
//!   `fn_ptr & 0xfffffffc` (Thumb-bit clear); the firmware is pure ARM,
//!   so the mask is omitted. The conv-state fn pointers are `Option`s in
//!   the shared struct; the original blindly calls them, so this port
//!   uses `unwrap_unchecked`.
//! - `scanset_flag != 0` (external scanset living in the format text,
//!   chars counted instead of bitmap bits) is dead in practice — the
//!   prologue always stores 0 — but is ported faithfully.

use crate::scanf_helpers::{getc_advance, ScanfConvState, ScanfState};
use crate::scanf_int::{
    scanf_convert_int, SCANF_FLAG_H, SCANF_FLAG_HH, SCANF_FLAG_LL, SCANF_FLAG_SIGN_OK,
    SCANF_FLAG_SUPPRESS,
};
use core::ffi::c_void;

/// `l` length modifier (single).
pub const SCANF_FLAG_L: u32 = 0x004;
/// A field width was given (`%5d` etc.); without it the width defaults
/// to INT_MAX (and `%c` defaults to 1).
pub const SCANF_FLAG_WIDTH_GIVEN: u32 = 0x010;
/// `L` length modifier (long double). Carried in the flag word; the
/// float engine is the only consumer.
pub const SCANF_FLAG_LONG_DOUBLE: u32 = 0x020;

/// Overflow guard for the field-width parse (INT_MAX / 10): the original
/// bails out when the accumulated width exceeds this BEFORE the next
/// `width = width*10 + digit` step, or when that step wraps negative.
const WIDTH_PARSE_GUARD: i32 = 0x0ccc_cccc;

/// Float engine entry, mirroring the walker's call site to the thunk
/// @ 0x083ed1b8 (which tail-branches to `FUN_08036348` @ 0x08036348).
/// `scratch_out` is a 4-byte stack slot the float engine writes digit
/// counts into (its `param_3`, `*local_2c = ...`); the walker never
/// reads it back. Returns consumed count >= 0, -1 on EOF before the
/// field, -2 on matching failure — same contract as
/// [`scanf_convert_int`].
pub type ScanfFloatEngineFn = unsafe extern "C" fn(
    unused_r0: i32,
    input: *mut ScanfState,
    scratch_out: *mut i32,
    conv: *mut ScanfConvState,
) -> i32;

/// Placeholder for the float input engine @ 0x08036348 (a concurrent
/// batch port). Reports a matching failure, which is also what every
/// `%e`/`%f`/`%g` directive degrades to until the hook is wired.
unsafe extern "C" fn scanf_float_engine_stub(
    _unused_r0: i32,
    _input: *mut ScanfState,
    _scratch_out: *mut i32,
    _conv: *mut ScanfConvState,
) -> i32 {
    -2
}

/// Float-engine entry point called by the walker for the float
/// directives; swap in the real port of `FUN_08036348` when its batch
/// lands. Defaults to [`scanf_float_engine_stub`].
#[no_mangle]
pub static mut SCANF_FLOAT_ENGINE: ScanfFloatEngineFn = scanf_float_engine_stub;

/// Whitespace test stored in `conv.ctype` by the prologue, standing in
/// for the original's `FUN_082d7340` @ 0x082d7340 (ADS ctype-table
/// lookup, bit 0 = whitespace). The ADS whitespace set is space plus
/// \t..\r; anything else — including EOF's -1 — tests as non-whitespace.
unsafe extern "C" fn ctype_is_space(c: i32) -> i32 {
    match c {
        0x20 | 0x09..=0x0d => 1,
        _ => 0,
    }
}

/// `scanf_engine_prologue` — original: `FUN_080332a4` @ 0x080332a4
/// (44 bytes).
///
/// The ADS `_scanf` entry: fills the conv state's format-engine fields
/// and tail-calls [`scanf_engine_walk`]. See the module docs for the ABI
/// and the simplifications (private ctype copy, r3 ignored).
#[no_mangle]
pub unsafe extern "C" fn scanf_engine_prologue(
    input: *mut ScanfState,
    fmt: *const u8,
    conv: *mut ScanfConvState,
) -> i32 {
    let conv = &mut *conv;
    conv.fmt_cursor = fmt;
    conv.fmt_getc = Some(getc_advance);
    conv.ctype = Some(ctype_is_space);
    conv.scanset_flag = 0;
    scanf_engine_walk(input, conv)
}

/// The `%s`/`%c`/`%[` converter body does not exist in this build: the
/// four call sites that would invoke it (external scanset vs. local
/// bitmap, crossed with the `l` flag) are literal `nop`s in the original
/// machine code, so r0 keeps the -2 it was loaded with and the directive
/// always fails to match. This helper stands in for those nopped calls;
/// it takes (and ignores) the exact arguments the original set up so the
/// scanset parse stays live. `#[inline(never)]` keeps the argument
/// materialization visible to `match.py`.
#[inline(never)]
fn string_conversion_nopped(
    scanset: *const u8,
    is_char: i32,
    external_len: i32,
    negate: i32,
) -> i32 {
    let _ = (scanset, is_char, external_len, negate);
    core::hint::black_box(-2)
}

/// `scanf_engine_walk` — original: `FUN_0803484c` @ 0x0803484c
/// (1564 bytes).
///
/// See the module docs for the full algorithm. Returns the number of
/// conversions assigned (suppressed `*` conversions do not count), or
/// -1 when EOF hit before the first field completed.
#[no_mangle]
pub unsafe extern "C" fn scanf_engine_walk(
    input: *mut ScanfState,
    conv: *mut ScanfConvState,
) -> i32 {
    let conv = &mut *conv;
    let fmt_getc = conv.fmt_getc.unwrap_unchecked();
    let getc = conv.getc.unwrap_unchecked();
    let ungetc = conv.ungetc.unwrap_unchecked();
    let ctype = conv.ctype.unwrap_unchecked();

    let mut conversions: i32 = 0; // r7: conversions assigned
    let mut consumed: i32 = 0; // r6: net input characters consumed
    let mut first_field = true; // [sp,#0x30]: cleared by the first converter result >= 0
    let mut float_scratch: i32 = 0; // sp+0x2c: aux out-int for the float engine
    let mut scanset = [0u32; 8]; // sp+0x10: %[ bitmap, 256 bits

    'format: loop {
        let mut fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
        if fc == 0 {
            return conversions;
        }
        if fc != b'%' as i32 {
            if ctype(fc) != 0 {
                // Whitespace in the format: skip the rest of the format
                // run (the terminating char is put back)...
                while ctype(fmt_getc(&mut conv.fmt_cursor, 1) as i32) != 0 {}
                fmt_getc(&mut conv.fmt_cursor, -1);
                // ...then match any amount of input whitespace.
                loop {
                    let ic = getc(input);
                    if ctype(ic) == 0 {
                        break;
                    }
                    consumed = consumed.wrapping_add(1);
                }
                ungetc(input);
                continue;
            }
            // Literal character: must equal the next input character.
            let ic = getc(input);
            if ic == fc {
                consumed = consumed.wrapping_add(1);
                continue;
            }
            ungetc(input);
            if ic != -1 {
                return conversions;
            }
            if conversions != 0 {
                return conversions;
            }
            return -1;
        }

        // --- '%' directive: suppression, width, length ---
        let mut flags: u32 = 0; // r5
        let mut width: i32 = 0; // r8
        fc = fmt_getc(&mut conv.fmt_cursor, 0) as i32; // peek
        if fc == b'*' as i32 {
            fmt_getc(&mut conv.fmt_cursor, 1);
            flags |= SCANF_FLAG_SUPPRESS;
        }
        loop {
            fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
            if (fc.wrapping_sub(0x30)) as u32 >= 10 {
                break;
            }
            if width > WIDTH_PARSE_GUARD {
                return conversions;
            }
            width = fc.wrapping_add(width.wrapping_mul(10)).wrapping_sub(0x30);
            if width < 0 {
                return conversions;
            }
            flags |= SCANF_FLAG_WIDTH_GIVEN;
        }
        if flags & SCANF_FLAG_WIDTH_GIVEN == 0 {
            width = i32::MAX;
        }
        if fc == b'l' as i32 {
            fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
            if fc == b'l' as i32 {
                flags |= SCANF_FLAG_LL;
                fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
            } else {
                flags |= SCANF_FLAG_L;
            }
        } else if fc == b'L' as i32 {
            flags |= SCANF_FLAG_LONG_DOUBLE;
            fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
        } else if fc == b'h' as i32 {
            fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
            if fc == b'h' as i32 {
                flags |= SCANF_FLAG_HH;
                fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
            } else {
                flags |= SCANF_FLAG_H;
            }
        } else if fc == b'j' as i32 {
            flags |= SCANF_FLAG_LL;
            fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
        } else if fc == b't' as i32 || fc == b'z' as i32 {
            fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
        }
        conv.flags = flags;
        conv.width = width;

        // --- dispatch on the conversion character (fc is 0..=255) ---
        let result: i32 = match fc as u8 {
            b'e' | b'E' | b'f' | b'g' | b'a' | b'A' | b'F' | b'G' => {
                let float_engine = SCANF_FLOAT_ENGINE;
                float_engine(-2, input, &mut float_scratch, conv)
            }
            b'%' => {
                // Literal '%': matched against the input, not a conversion.
                let ic = getc(input);
                if ic == b'%' as i32 {
                    consumed = consumed.wrapping_add(1);
                    continue 'format;
                }
                ungetc(input);
                if ic == -1 && conversions == 0 {
                    return -1;
                }
                return conversions;
            }
            b'n' => {
                // Store `consumed` through the next ap slot. The original
                // does NOT test SUPPRESS here and never counts %n.
                let slot = conv.ap as *const *mut u8;
                let dest = *slot;
                conv.ap = (conv.ap as *mut u8).add(4) as *mut c_void;
                if flags & SCANF_FLAG_HH != 0 {
                    *dest = consumed as u8;
                } else if flags & SCANF_FLAG_H != 0 {
                    *(dest as *mut u16) = consumed as u16;
                } else {
                    *(dest as *mut i32) = consumed;
                    if flags & SCANF_FLAG_LL != 0 {
                        *(dest as *mut i32).add(1) = consumed >> 31;
                    }
                }
                continue 'format;
            }
            b'p' => {
                // Pointer: unsigned hex, no sign, length modifiers cleared.
                conv.flags = flags
                    & !(SCANF_FLAG_HH | SCANF_FLAG_H | SCANF_FLAG_L | SCANF_FLAG_LL);
                scanf_convert_int(-2, input, 16, conv)
            }
            b'x' | b'X' => {
                conv.flags = flags | SCANF_FLAG_SIGN_OK;
                if flags & SCANF_FLAG_LL != 0 {
                    -2 // %llx call site is a nop in this build
                } else {
                    scanf_convert_int(-2, input, 16, conv)
                }
            }
            b'd' | b'u' => {
                conv.flags = flags | SCANF_FLAG_SIGN_OK;
                if flags & SCANF_FLAG_LL != 0 {
                    -2 // %lld call site is a nop in this build
                } else {
                    scanf_convert_int(-2, input, 10, conv)
                }
            }
            b'i' => {
                conv.flags = flags | SCANF_FLAG_SIGN_OK;
                if flags & SCANF_FLAG_LL != 0 {
                    -2 // %lli call site is a nop in this build
                } else {
                    scanf_convert_int(-2, input, 0, conv)
                }
            }
            b'o' => {
                conv.flags = flags | SCANF_FLAG_SIGN_OK;
                if flags & SCANF_FLAG_LL != 0 {
                    -2 // %llo call site is a nop in this build
                } else {
                    scanf_convert_int(-2, input, 8, conv)
                }
            }
            b's' | b'c' | b'[' => {
                let mut is_char: i32 = 0; // [sp,#0x0c]
                let mut external_len: i32 = 0; // r8: length of an external scanset
                let mut negate: i32 = 0; // r9
                let mut scanset_ptr: *const u8 = core::ptr::null(); // r1 / fp
                if fc == b'c' as i32 {
                    if flags & SCANF_FLAG_WIDTH_GIVEN == 0 {
                        conv.width = 1;
                    }
                    is_char = 1;
                } else if fc == b'[' as i32 {
                    fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
                    if fc == b'^' as i32 {
                        negate = 1;
                        fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
                    }
                    if conv.scanset_flag != 0 {
                        // External scanset: the set text stays in the
                        // format string; fp points at its first character
                        // (fmt_cursor sits two past it: '['/'^' + char).
                        scanset_ptr = conv.fmt_cursor.sub(2);
                    } else {
                        scanset = [0; 8];
                    }
                    // First character is always a set member — that is
                    // what makes "%[]]" and "%[^]]" work. NO '-' ranges:
                    // a '-' is just a member like any other.
                    loop {
                        if fc == 0 {
                            return conversions; // unterminated scanset
                        }
                        if conv.scanset_flag != 0 {
                            external_len += 1;
                        } else {
                            scanset[(fc as usize) >> 5] |= 1u32 << (fc & 31);
                        }
                        fc = fmt_getc(&mut conv.fmt_cursor, 1) as i32;
                        if fc == b']' as i32 {
                            break;
                        }
                    }
                    if negate != 0 {
                        for word in scanset.iter_mut() {
                            *word = !*word;
                        }
                    }
                    if conv.scanset_flag == 0 {
                        scanset_ptr = scanset.as_ptr() as *const u8;
                    }
                }
                // The converters themselves are nopped out in this build;
                // this is always a matching failure (see module docs).
                // black_box keeps the scanset parse (bitmap, counts)
                // materialized like the original, which also spends the
                // instructions before its nopped call sites.
                string_conversion_nopped(
                    core::hint::black_box(scanset_ptr),
                    is_char,
                    external_len,
                    negate,
                )
            }
            _ => return conversions, // unknown directive ends the walk
        };

        // --- converter result accounting ---
        if result < 0 {
            if result == -1 && first_field {
                return -1; // EOF before the first field completed
            }
            return conversions;
        }
        consumed = consumed.wrapping_add(result);
        if flags & SCANF_FLAG_SUPPRESS == 0 {
            conversions += 1;
        }
        first_field = false;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::scanf_helpers::{string_getc, string_ungetc};
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes the tests that swap SCANF_FLOAT_ENGINE.
    static FLOAT_HOOK_LOCK: Mutex<()> = Mutex::new(());

    /// The state pair the sscanf veneer builds, kept separate (the
    /// original overlaps them; functional behavior is identical since
    /// all access goes through named fields).
    struct Scan {
        input: ScanfState,
        conv: ScanfConvState,
        _argbuf: Vec<u8>, // backing store for conv.ap; must outlive the call
    }

    /// Packs a destination pointer the way the 32-bit varargs layout
    /// needs it: `ap` advances 4 bytes per slot while each host read
    /// fetches a full (8-byte) pointer, so slot k sits at byte offset
    /// 4k. CONSEQUENCE: adjacent slots overlap by 4 bytes on a 64-bit
    /// host, so a single scan call can only have ONE conversion that
    /// actually reads ap (any further conversions in the format must be
    /// suppressed, fail before storing, or go through the fake float
    /// engine, none of which touch ap).
    fn pack_ap(dests: &[*mut u8]) -> Vec<u8> {
        assert!(dests.len() <= 1, "one real ap read per scan call (see doc)");
        let mut buf = std::vec![0u8; dests.len() * 4 + 8];
        for (k, d) in dests.iter().enumerate() {
            let bytes = (*d as usize).to_ne_bytes();
            buf[4 * k..4 * k + 8].copy_from_slice(&bytes);
        }
        buf
    }

    /// Runs the prologue+walker over (fmt, input) with the given
    /// destination slots; returns (result, states).
    fn scan(input: &[u8], fmt: &[u8], dests: &[*mut u8]) -> (i32, Scan) {
        let argbuf = pack_ap(dests);
        let ap = argbuf.as_ptr() as *mut c_void;
        let mut s = Scan {
            input: ScanfState {
                ptr: input.as_ptr(),
                count: -1,
                base: input.as_ptr(),
                eof: 0,
                ap: core::ptr::null_mut(),
                flags: 0,
                width: 0,
                fmt_cursor: core::ptr::null(),
                scanset_flag: 0,
                fmt_getc: None,
                getc: Some(string_getc),
                ungetc: Some(string_ungetc),
                ctype: None,
            },
            conv: ScanfConvState {
                ap,
                flags: 0,
                width: 0,
                fmt_cursor: core::ptr::null(),
                scanset_flag: 0,
                fmt_getc: None,
                getc: Some(string_getc),
                ungetc: Some(string_ungetc),
                ctype: None,
            },
            _argbuf: argbuf,
        };
        let ret = unsafe { scanf_engine_prologue(&mut s.input, fmt.as_ptr(), &mut s.conv) };
        (ret, s)
    }

    /// One u32 destination slot.
    fn scan_u32(input: &[u8], fmt: &[u8]) -> (i32, u32, Scan) {
        let mut dest: u32 = 0xDEAD_BEEF;
        let (ret, s) = scan(input, fmt, &[&mut dest as *mut u32 as *mut u8]);
        (ret, dest, s)
    }

    #[test]
    fn prologue_fills_conv_fields() {
        let fmt = b"\0"; // NUL-terminated empty format (a readable byte)
        let (ret, s) = scan(b"\0", fmt, &[]);
        assert_eq!(ret, 0, "empty format yields zero conversions");
        // The terminating NUL was consumed by the walk.
        assert_eq!(s.conv.fmt_cursor, unsafe { fmt.as_ptr().add(1) });
        assert_eq!(s.conv.fmt_getc.map(|f| f as usize), Some(getc_advance as usize));
        assert!(s.conv.ctype.is_some());
        assert_eq!(s.conv.scanset_flag, 0);
    }

    #[test]
    fn decimal_basic() {
        let (ret, value, _) = scan_u32(b"42\0", b"%d\0");
        assert_eq!((ret, value), (1, 42));
    }

    #[test]
    fn decimal_with_leading_whitespace() {
        let (ret, value, _) = scan_u32(b"  \t17x\0", b"%d\0");
        assert_eq!((ret, value), (1, 17));
    }

    #[test]
    fn field_width_limits_digits() {
        let (ret, value, s) = scan_u32(b"12345\0", b"%3d\0");
        assert_eq!((ret, value), (1, 123));
        // The 4th digit is still in the input.
        let mut input = s.input;
        assert_eq!(unsafe { string_getc(&mut input) }, b'4' as i32);
    }

    #[test]
    fn hex_and_auto_and_octal() {
        let (ret, value, _) = scan_u32(b"1f!\0", b"%x\0");
        assert_eq!((ret, value), (1, 0x1f));
        let (ret, value, _) = scan_u32(b"0x1a\0", b"%i\0");
        assert_eq!((ret, value), (1, 26));
        let (ret, value, _) = scan_u32(b"017\0", b"%i\0");
        assert_eq!((ret, value), (1, 15));
        let (ret, value, _) = scan_u32(b"17\0", b"%o\0");
        assert_eq!((ret, value), (1, 15));
        let (ret, value, _) = scan_u32(b"4294967295\0", b"%u\0");
        assert_eq!((ret, value), (1, u32::MAX));
    }

    #[test]
    fn pointer_conversion_is_unsigned_hex() {
        let (ret, value, _) = scan_u32(b"1a\0", b"%p\0");
        assert_eq!((ret, value), (1, 0x1a));
        // No SIGN_OK for %p: a leading '-' is a matching failure.
        let (ret, _, _) = scan_u32(b"-1\0", b"%p\0");
        assert_eq!(ret, 0);
        // %p clears the length modifiers.
        let (ret, value, _) = scan_u32(b"ff\0", b"%hp\0");
        assert_eq!((ret, value), (1, 0xff), "h cleared: word store");
    }

    #[test]
    fn two_conversions_with_format_whitespace() {
        // NOTE: on a 64-bit host only ONE real store per scan call can
        // have a valid destination (the engine's ap advances 4 bytes per
        // slot while a host pointer read is 8 bytes — see pack_ap), so
        // the first conversion goes through the fake float engine, which
        // never touches ap.
        let _guard = FLOAT_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            SCANF_FLOAT_ENGINE = fake_float_engine;
            FAKE_FLOAT_RESULT = 1;
        }
        let mut b: u32 = 0;
        let (ret, _) = scan(b" 2\0", b"%f %d\0", &[&mut b as *mut u32 as *mut u8]);
        assert_eq!(ret, 2, "float + int conversions both count");
        assert_eq!(b, 2);
        unsafe {
            SCANF_FLOAT_ENGINE = scanf_float_engine_stub;
        }
    }

    #[test]
    fn format_whitespace_matches_empty_input_whitespace() {
        let (ret, value, _) = scan_u32(b"7\0", b"  %d  \0");
        assert_eq!((ret, value), (1, 7));
    }

    #[test]
    fn literal_characters_must_match() {
        // Match: conversion proceeds.
        let (ret, value, _) = scan_u32(b"a5\0", b"a%d\0");
        assert_eq!((ret, value), (1, 5));
        // Mismatch: walk ends with the conversions so far (none), the
        // offending input char pushed back.
        let (ret, _, s) = scan_u32(b"b5\0", b"a%d\0");
        assert_eq!(ret, 0);
        let mut input = s.input;
        assert_eq!(unsafe { string_getc(&mut input) }, b'b' as i32);
    }

    #[test]
    fn literal_eof_after_conversions_returns_count() {
        // "%d," on "5": the comma hits EOF after one conversion -> 1.
        let (ret, value, _) = scan_u32(b"5\0", b"%d,\0");
        assert_eq!((ret, value), (1, 5));
    }

    #[test]
    fn literal_eof_before_anything_returns_minus1() {
        let (ret, _, _) = scan_u32(b"\0", b"a%d\0");
        assert_eq!(ret, -1);
    }

    #[test]
    fn string_directives_are_nopped_out() {
        // %s/%c/%[ always fail to match in this build (call sites are
        // literal nops): the walk ends with the conversions so far.
        let (ret, _) = scan(b"hello\0", b"%s\0", &[]);
        assert_eq!(ret, 0);
        let (ret, _) = scan(b"x\0", b"%c\0", &[]);
        assert_eq!(ret, 0);
        let (ret, _) = scan(b"abc\0", b"%[a-z]\0", &[]);
        assert_eq!(ret, 0);
        let (ret, _) = scan(b"abc,def\0", b"%[^,]\0", &[]);
        assert_eq!(ret, 0);
        let (ret, _) = scan(b"]]\0", b"%[]]\0", &[]);
        assert_eq!(ret, 0);
        // Unterminated scanset: also just ends the walk.
        let (ret, _) = scan(b"abc\0", b"%[ab\0", &[]);
        assert_eq!(ret, 0);
        // A conversion before the string directive is still reported.
        let (ret, value, _) = scan_u32(b"1x\0", b"%d%c\0");
        assert_eq!((ret, value), (1, 1));
        // %c with explicit width also fails the same way.
        let (ret, _) = scan(b"xyz\0", b"%3c\0", &[]);
        assert_eq!(ret, 0);
    }

    #[test]
    fn percent_percent_matches_literal() {
        // "%%" on "%": matches, counts as consumed but NOT a conversion.
        let (ret, s) = scan(b"%\0", b"%%\0", &[]);
        assert_eq!(ret, 0);
        let mut input = s.input;
        assert_eq!(unsafe { string_getc(&mut input) }, -1, "the '%' was consumed");
        // Mismatch: walk ends with zero conversions.
        let (ret, _) = scan(b"x\0", b"%%\0", &[]);
        assert_eq!(ret, 0);
        // EOF: -1 before any conversion.
        let (ret, _) = scan(b"\0", b"%%\0", &[]);
        assert_eq!(ret, -1);
        // "%%%d": literal '%' then a directive.
        let (ret, value, _) = scan_u32(b"%5\0", b"%%%d\0");
        assert_eq!((ret, value), (1, 5));
    }

    #[test]
    fn length_modifiers_narrow_the_store() {
        let mut dest16: u16 = 0;
        let (ret, _) = scan(b"74565\0", b"%hd\0", &[&mut dest16 as *mut u16 as *mut u8]);
        assert_eq!(ret, 1);
        assert_eq!(dest16, 0x2345); // 74565 = 0x12345, truncated
        let mut dest8: u8 = 0;
        let (ret, _) = scan(b"300\0", b"%hhd\0", &[&mut dest8 as *mut u8]);
        assert_eq!(ret, 1);
        assert_eq!(dest8, 44); // 300 truncated to a byte
        // %ld stores a full word (l is just "word" on this 32-bit ABI).
        let (ret, value, _) = scan_u32(b"74565\0", b"%ld\0");
        assert_eq!((ret, value), (1, 74565));
        // %ll integer sites are nopped: matching failure.
        let (ret, _, _) = scan_u32(b"5\0", b"%lld\0");
        assert_eq!(ret, 0);
        // j/t/z length modifiers are accepted (j = ll -> nopped; t/z no flag).
        let (ret, value, _) = scan_u32(b"9\0", b"%td\0");
        assert_eq!((ret, value), (1, 9));
        let (ret, value, _) = scan_u32(b"9\0", b"%zd\0");
        assert_eq!((ret, value), (1, 9));
        let (ret, _, _) = scan_u32(b"9\0", b"%jd\0");
        assert_eq!(ret, 0);
    }

    #[test]
    fn suppression_consumes_without_counting() {
        let mut b: u32 = 0;
        let (ret, _) = scan(b"1 2\0", b"%*d %d\0", &[&mut b as *mut u32 as *mut u8]);
        assert_eq!(ret, 1, "only the assigned conversion counts");
        assert_eq!(b, 2);
        let (ret, _) = scan(b"1\0", b"%*d\0", &[]);
        assert_eq!(ret, 0);
    }

    #[test]
    fn suppressed_success_clears_the_first_field_flag() {
        // "%*d %d" on "1": the suppressed field consumed the input, the
        // second %d hits EOF. first_field was cleared, so the result is
        // the conversion count (0), NOT -1.
        let mut b: u32 = 0;
        let (ret, _) = scan(b"1\0", b"%*d %d\0", &[&mut b as *mut u32 as *mut u8]);
        assert_eq!(ret, 0);
    }

    #[test]
    fn eof_mid_directive() {
        // EOF before the very first field: -1.
        let (ret, _) = scan(b"\0", b"%d\0", &[]);
        assert_eq!(ret, -1);
        let (ret, _) = scan(b"   \0", b"%d\0", &[]);
        assert_eq!(ret, -1);
        // EOF before a later field: conversions so far. (One real dest:
        // the second %d returns -1 before it would read ap.)
        let mut a: u32 = 0;
        let (ret, _) = scan(b"1 \0", b"%d %d\0", &[&mut a as *mut u32 as *mut u8]);
        assert_eq!(ret, 1);
        assert_eq!(a, 1);
    }

    #[test]
    fn return_counts_assigned_not_matched() {
        // (One real dest: the second %d fails to match before reading ap.)
        let mut a: u32 = 0;
        let (ret, _) = scan(b"5 x\0", b"%d %d\0", &[&mut a as *mut u32 as *mut u8]);
        assert_eq!(ret, 1, "matching failure stops the walk");
        assert_eq!(a, 5);
    }

    #[test]
    fn percent_n_stores_consumed_chars() {
        // Plain %n: nothing consumed yet, not counted as a conversion.
        let mut n: i32 = -1;
        let (ret, _) = scan(b"\0", b"%n\0", &[&mut n as *mut i32 as *mut u8]);
        assert_eq!(ret, 0);
        assert_eq!(n, 0);
        // Input whitespace (matched by the format ws) and suppressed
        // conversions count toward %n; the suppressed %d never reads ap,
        // so %n gets slot 0.
        let mut n: i32 = -1;
        let (ret, _) = scan(b"  42\0", b" %*d%n\0", &[&mut n as *mut i32 as *mut u8]);
        assert_eq!(ret, 0, "%n is not counted");
        assert_eq!(n, 4, "2 input ws + 2 digits");
        // hh narrows the %n store to a byte.
        let mut n8: u8 = 0xEE;
        let (ret, _) = scan(b"ab\0", b"ab%hhn\0", &[&mut n8 as *mut u8]);
        assert_eq!(ret, 0);
        assert_eq!(n8, 2, "'a' + 'b' consumed");
        // ll adds a sign-extension word after the count.
        let mut n64 = [-1i32; 2];
        let (ret, _) = scan(b"ab\0", b"ab%lln\0", &[n64.as_mut_ptr() as *mut u8]);
        assert_eq!(ret, 0);
        assert_eq!(n64, [2, 0], "low word = count, high word = sign extension");
        // A conversion's consumed count flows into %n (fake float engine
        // reports 3 and never touches ap).
        let _guard = FLOAT_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            SCANF_FLOAT_ENGINE = fake_float_engine;
            FAKE_FLOAT_RESULT = 3;
        }
        let mut n: i32 = -1;
        let (ret, _) = scan(b"1.5\0", b"%f%n\0", &[&mut n as *mut i32 as *mut u8]);
        assert_eq!(ret, 1);
        assert_eq!(n, 3);
        unsafe {
            SCANF_FLOAT_ENGINE = scanf_float_engine_stub;
        }
    }

    #[test]
    fn width_parse_overflow_ends_the_walk() {
        // 214748364*10 + 8 wraps negative -> return the count (0).
        let (ret, _, _) = scan_u32(b"5\0", b"%2147483648d\0");
        assert_eq!(ret, 0);
        // Far beyond the guard: same.
        let (ret, _, _) = scan_u32(b"5\0", b"%999999999999d\0");
        assert_eq!(ret, 0);
        // INT_MAX itself is still a valid width.
        let (ret, value, _) = scan_u32(b"5\0", b"%2147483647d\0");
        assert_eq!((ret, value), (1, 5));
    }

    #[test]
    fn unknown_directive_ends_the_walk() {
        let (ret, _, _) = scan_u32(b"5\0", b"%q\0");
        assert_eq!(ret, 0);
        // Conversions before the unknown directive are reported.
        let (ret, value, _) = scan_u32(b"5\0", b"%d%q\0");
        assert_eq!((ret, value), (1, 5));
    }

    #[test]
    fn percent_at_end_of_format_is_unknown() {
        let (ret, value, _) = scan_u32(b"5\0", b"%d%\0");
        assert_eq!((ret, value), (1, 5));
    }

    // --- float directive dispatch through SCANF_FLOAT_ENGINE ---

    static mut FAKE_FLOAT_RESULT: i32 = -2;
    static mut FAKE_FLOAT_CALLS: u32 = 0;
    static mut FAKE_FLOAT_R0: i32 = 0;
    static mut FAKE_FLOAT_SCRATCH_OK: bool = false;

    unsafe extern "C" fn fake_float_engine(
        unused_r0: i32,
        _input: *mut ScanfState,
        scratch_out: *mut i32,
        _conv: *mut ScanfConvState,
    ) -> i32 {
        FAKE_FLOAT_CALLS += 1;
        FAKE_FLOAT_R0 = unused_r0;
        if !scratch_out.is_null() {
            *scratch_out = 1234;
            FAKE_FLOAT_SCRATCH_OK = true;
        }
        FAKE_FLOAT_RESULT
    }

    #[test]
    fn float_directive_uses_hook_default_is_failure() {
        // Default stub: matching failure -> zero conversions.
        let _guard = FLOAT_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (ret, _) = scan(b"1.5\0", b"%f\0", &[]);
        assert_eq!(ret, 0);
    }

    #[test]
    fn float_directive_dispatches_with_original_abi() {
        let _guard = FLOAT_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            SCANF_FLOAT_ENGINE = fake_float_engine;
            FAKE_FLOAT_CALLS = 0;
            FAKE_FLOAT_RESULT = 3; // pretend 3 input chars were consumed
            FAKE_FLOAT_SCRATCH_OK = false;
        }
        let mut n: i32 = -1;
        let (ret, s) = scan(b"1.5\0", b"%f%n\0", &[&mut n as *mut i32 as *mut u8]);
        assert_eq!(ret, 1, "the float conversion counts");
        assert_eq!(n, 3, "the walker's consumed grew by the engine result");
        assert_eq!(unsafe { FAKE_FLOAT_CALLS }, 1);
        assert_eq!(unsafe { FAKE_FLOAT_R0 }, -2, "r0 = -2 like the original call site");
        assert!(unsafe { FAKE_FLOAT_SCRATCH_OK }, "scratch out-int was writable");
        assert_eq!(s.conv.flags, 0, "no SIGN_OK for float directives");
        // EOF result before the first field: -1.
        unsafe {
            FAKE_FLOAT_RESULT = -1;
        }
        let (ret, _) = scan(b"\0", b"%f\0", &[]);
        assert_eq!(ret, -1);
        unsafe {
            SCANF_FLOAT_ENGINE = scanf_float_engine_stub;
        }
    }

    #[test]
    fn float_suppression_does_not_count() {
        let _guard = FLOAT_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            SCANF_FLOAT_ENGINE = fake_float_engine;
            FAKE_FLOAT_RESULT = 2;
        }
        let (ret, _) = scan(b"1.5\0", b"%*f\0", &[]);
        assert_eq!(ret, 0, "suppressed float conversion consumed but not counted");
        unsafe {
            SCANF_FLOAT_ENGINE = scanf_float_engine_stub;
        }
    }
}
