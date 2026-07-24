//! printf format engine and the `_vsnprintf` dispatcher (ARM ADS 1.0.1).
//!
//! Ports:
//! - `_printf`    @ 0x08034374 (1164 bytes) — the format-string engine.
//!   Walks the format, accumulates plain-text runs (counted char by char
//!   and flushed through the state's `emit_str` hook as [begin, end)
//!   slices), then for each `%` parses flags (`-`/`+`/space/`#`/`0` via
//!   the 17-byte table @ 0x08986234, indexed by char - 0x20), width and
//!   precision (decimal or `*`, the latter fetching an int argument; a
//!   negative `*` precision cancels FLAG_PRECISION_GIVEN, a negative
//!   width negates to left-justify), length modifiers (`h`/`hh`/`l`/`ll`;
//!   `j` acts as `ll`, `L`/`t`/`z` are consumed with no flag), and
//!   dispatches on the conversion char. Unknown conversion chars —
//!   including `%` itself (this is how `%%` works) and `S` — are printed
//!   verbatim through `putc` with `count` bumped. A NUL conversion char
//!   ends the scan silently. Returns `state.count` (the original leaves
//!   it in r0).
//! - `_vsnprintf` @ 0x08032f14 (76 bytes) — dispatcher. Recovered
//!   argument order from the machine code: `(fmt, putc, putc_ctx, args)`
//!   — r1 lands in state+0x1c (putc), r2 in state+0x24 (putc_ctx), r3
//!   becomes `_printf`'s argument pointer, and r0 (fmt) is stored where
//!   the string getter walks it. Installs the default `emit_str` and
//!   zeroes state+0x30 (string-disable flag).
//! - `str_emit`   @ 0x08034804 (48 bytes) — the default `emit_str` hook:
//!   pushes [begin, end) through the state `putc`. Does NOT bump `count`
//!   (the engine pre-counts plain chars; the converters count their own
//!   content).
//!
//! Argument fetch (AAPCS va_list as a `*const u32` cursor): 32-bit args
//! consume one word; 64-bit args (`ll`, floats) first align the cursor
//! up to 8 bytes (`(p + 7) & !7`, possibly skipping one slot), then
//! consume a lo/hi pair (original: `add r1, r4, #7; bic r1, r1, #7;
//! ldm r1, {r2, r3}`).
//!
//! Simplifications / deviations vs. the original:
//! - The original reads the FORMAT string through a getter hook at
//!   state+0x28/0x2c (the dispatcher installs `sgetc` @ 0x08034838 over a
//!   cell holding fmt), so its `_printf` takes `(state, args)` and the
//!   plain-run slices are pointer ranges into the walked source. This
//!   port takes `fmt` directly (fixed port signature) and walks it with
//!   a local cursor; state offsets 0x28/0x2c stay zero. `sgetc` is
//!   therefore not ported.
//! - `%e/%E/%f/%F/%g/%G` (and `%a/%A`): routed through the
//!   [`FLOAT_CONVERTER`] hook because the float wrapper FUN_08032d70 @
//!   0x08032d70 is not yet ported; the default is a documented no-op
//!   stub. (`%a/%A` in the original bl's a veneer @ 0x083ed07c that is a
//!   bare `mov pc, lr` — dead in this build — so the no-op default is
//!   behavior-identical there.) The argument is still fetched as an
//!   8-aligned u64 bit pattern, exactly like the original.
//! - `%llx/%llX/%llp/%llo`: the committed hex/octal converters are
//!   u32-only, so the high word of the fetched pair is dropped and only
//!   the low 32 bits print (the original's converters walk all 64 bits
//!   with a funnel shift). The argument pair is still consumed
//!   8-aligned, keeping the va_list in sync.
//! - `%c` is inlined instead of calling `convert_s` with `min_len = 1`
//!   (the ported convert_s dropped that parameter; see printf_s.rs).
//!   Semantics preserved: exactly one content char — even `'\0'` —
//!   unless a given precision is <= 0, which prints nothing.
//! - `%lc` measures through the ported `convert_ls`, which dropped the
//!   original's `min_chars = 1` parameter: a NUL wide char converts to
//!   zero output bytes here vs. one in the original. All other values
//!   behave identically.
//! - The dead `tst/and` flag-probe sequence before the `%n` call
//!   (0x080346e8-0x080346f4, result unused — `store_n` re-tests the
//!   flags itself) is omitted, as is Ghidra's `& 0xfffffffc` on the hook
//!   pointers (pure-ARM firmware, no Thumb bit).
//! - Host testing: pointer-valued args (`%s`, `%n`, `%ls`) are fetched
//!   with a native-width read ([`fetch_ptr`]) so 64-bit hosts can pass
//!   real pointers. On the 32-bit target this lowers to the same
//!   `ldr`/`add #4` sequence as any other word fetch.
//! - `_vsnprintf` zero-initializes the whole state struct; the original
//!   leaves the reserved fields as uninitialized stack (nothing reads
//!   them).

use core::ffi::c_void;

use crate::printf_d::{convert_d, convert_u};
use crate::printf_helpers::{
    pad_emit, pad_emit_zero, PrintfState, PutcFn, FLAG_LEFT_JUSTIFY, FLAG_LEN_H, FLAG_LEN_HH,
    FLAG_PRECISION_GIVEN, FLAG_ZERO_PAD,
};
use crate::printf_ll::{convert_lld, convert_llu};
use crate::printf_o::convert_o;
use crate::printf_out::store_n;
use crate::printf_s::convert_s;
use crate::printf_wide::convert_ls;
use crate::printf_x::{convert_p, convert_x, convert_X};

/// Format flag: `+` — always show a sign on signed conversions.
/// (Consumed by the decimal converters; the core only accumulates it.)
const FLAG_SHOW_SIGN: u32 = 0x002;
/// Format flag: ` ` (space) — sign prefix for positive signed values.
const FLAG_SPACE_SIGN: u32 = 0x004;
/// Length modifier `l` (single): flag 0x40. 32-bit in this build — the
/// integer converters ignore it; `%ls`/`%lc` test it to go wide, and
/// `store_n` treats it as a plain word.
const FLAG_LEN_L: u32 = 0x040;
/// Length modifier `ll` (also `j`): the argument is a 64-bit pair.
const FLAG_LEN_LL: u32 = 0x080;

/// Flag-accumulation table — original: 17 bytes @ 0x08986234, indexed by
/// `char - 0x20`, covering `' '` (0x20) through `'0'` (0x30). A zero
/// entry ends the flag scan without consuming the char (this is how the
/// scan stops at `*` and `.`).
const FLAG_TABLE: [u8; 17] = [
    0x04, // ' '  -> space sign
    0, 0, // '!' '"'
    0x08, // '#'  -> alternate form
    0, 0, 0, 0, 0, 0, // '$' '%' '&' '\'' '(' ')'
    0,    // '*'  -> ends the flag scan
    0x02, // '+'  -> show sign
    0,    // ','
    0x01, // '-'  -> left justify
    0,    // '.'  -> ends the flag scan
    0,    // '/'
    0x10, // '0'  -> zero pad
];

/// Float conversion hook, called for `%e/%E/%f/%F/%g/%G/%a/%A` with the
/// conversion character and a pointer to the 8 argument bytes (the u64
/// bit pattern of the soft-float double). Original target: the float
/// wrapper FUN_08032d70 @ 0x08032d70 (not yet ported); `%a/%A` went to
/// the dead veneer @ 0x083ed07c.
pub type FloatConverterFn = unsafe extern "C" fn(state: *mut PrintfState, spec: u8, bits: *const u64);

/// Default [`FLOAT_CONVERTER`]: documented no-op stub standing in for
/// the unported float wrapper @ 0x08032d70.
unsafe extern "C" fn float_not_ported(_state: *mut PrintfState, _spec: u8, _bits: *const u64) {}

/// Installed float converter; see [`FloatConverterFn`]. Replace once the
/// float wrapper @ 0x08032d70 is ported.
pub static mut FLOAT_CONVERTER: FloatConverterFn = float_not_ported;

/// Fetch one 32-bit varargs word (original: `ldr rX, [r4], #4`).
#[inline(always)]
unsafe fn fetch_word(args: &mut *const u32) -> u32 {
    let value = **args;
    *args = args.add(1);
    value
}

/// Fetch a pointer-valued vararg. On the 32-bit target this is exactly
/// [`fetch_word`]; on 64-bit hosts (tests only) a native word is read so
/// real host pointers survive the round trip (see module header).
#[inline(always)]
unsafe fn fetch_ptr(args: &mut *const u32) -> *mut u8 {
    let slot = *args as *const usize;
    let value = *slot;
    *args = slot.add(1) as *const u32;
    value as *mut u8
}

/// Fetch a 64-bit varargs pair: align the cursor up to 8 bytes first
/// (original: `add r1, r4, #7; bic r1, r1, #7; ldm r1, {r2, r3}`), then
/// consume the lo/hi words. No 64-bit arithmetic beyond the assemble.
#[inline(always)]
unsafe fn fetch_pair(args: &mut *const u32) -> u64 {
    let aligned = ((*args as usize + 7) & !7) as *const u32;
    let lo = *aligned;
    let hi = *aligned.add(1);
    *args = aligned.add(2);
    lo as u64 | (hi as u64) << 32
}

/// Load the installed float converter. Volatile: with a single codegen
/// unit LLVM otherwise constant-folds the static to its initializer
/// (nothing in the crate writes it yet) and the hook vanishes.
#[inline(always)]
unsafe fn float_converter() -> FloatConverterFn {
    core::ptr::read_volatile(core::ptr::addr_of!(FLOAT_CONVERTER))
}

/// `str_emit` — original: `FUN_08034804` @ 0x08034804 (48 bytes).
///
/// Default `emit_str` hook installed by `_vsnprintf`: pushes the
/// [begin, end) slice through the state `putc` (original loop:
/// `cmp begin, end; bcc body` — unsigned pointer compare). Does not
/// touch `count`; callers account for the content themselves.
#[no_mangle]
pub unsafe extern "C" fn str_emit(state: *mut PrintfState, begin: *const u8, end: *const u8) {
    let mut p = begin;
    while (p as usize) < (end as usize) {
        ((*state).putc)(*p, (*state).putc_ctx);
        p = p.add(1);
    }
}

/// `_printf` — original: `FUN_08034374` @ 0x08034374 (1164 bytes).
///
/// The format engine; see the module header for the algorithm and the
/// deviations. Returns the number of characters emitted (`state.count`).
#[no_mangle]
pub unsafe extern "C" fn _printf(state: *mut PrintfState, fmt: *const u8, args: *const u32) -> i32 {
    let st = &mut *state;
    st.count = 0;
    let mut args = args;
    let mut cursor = fmt;
    let mut run_start = fmt;

    loop {
        // Plain-text run: scan to the next '%' or NUL, counting chars
        // (the original bumps count per char as it reads them).
        let mut c;
        loop {
            c = *cursor;
            if c == 0 || c == b'%' {
                break;
            }
            cursor = cursor.add(1);
            st.count += 1;
        }
        // Flush the run through the emit_str hook (skipped when empty).
        if cursor != run_start {
            (st.emit_str.unwrap_unchecked())(state, run_start, cursor);
        }
        if c == 0 {
            return st.count;
        }
        cursor = cursor.add(1); // consume '%'

        // Flags: table-driven over ' '(0x20)..='0'(0x30); a zero table
        // entry or an out-of-range char ends the scan unconsumed.
        let mut flags: u32 = 0;
        loop {
            c = *cursor;
            let bit = if (0x20..=0x30).contains(&c) {
                FLAG_TABLE[(c - 0x20) as usize]
            } else {
                0
            };
            if bit == 0 {
                break;
            }
            flags |= bit as u32;
            cursor = cursor.add(1);
        }

        // Width and precision. Field 0 = width (held in pad_remaining),
        // field 1 = precision; both reset per conversion.
        st.pad_remaining = 0;
        st.precision = 0;
        let mut field = 0u32;
        loop {
            if c == b'*' {
                let value = fetch_word(&mut args) as i32;
                if field == 0 {
                    st.pad_remaining = value;
                } else {
                    st.precision = value;
                }
                cursor = cursor.add(1);
                c = *cursor;
                if field == 1 {
                    // A negative '*' precision: as if '.' never appeared.
                    if st.precision < 0 {
                        flags &= !FLAG_PRECISION_GIVEN;
                    }
                    break;
                }
            } else {
                if c.is_ascii_digit() {
                    let mut value = (c - b'0') as i32;
                    loop {
                        cursor = cursor.add(1);
                        c = *cursor;
                        if !c.is_ascii_digit() {
                            break;
                        }
                        value = value * 10 + (c - b'0') as i32;
                    }
                    if field == 0 {
                        st.pad_remaining = value;
                    } else {
                        st.precision = value;
                    }
                }
                if field == 1 {
                    break;
                }
            }
            if c != b'.' {
                break;
            }
            cursor = cursor.add(1);
            c = *cursor;
            field = 1;
            flags |= FLAG_PRECISION_GIVEN;
        }

        // A negative width means left-justify with its absolute value
        // (the original XORs bit 0; it is always clear here, so the XOR
        // is equivalent to setting it).
        if st.pad_remaining < 0 {
            st.pad_remaining = -st.pad_remaining;
            flags ^= FLAG_LEFT_JUSTIFY;
        }
        // '-' wins over '0'; '+' wins over ' '.
        if flags & FLAG_LEFT_JUSTIFY != 0 {
            flags &= !FLAG_ZERO_PAD;
        }
        if flags & FLAG_SHOW_SIGN != 0 {
            flags &= !FLAG_SPACE_SIGN;
        }

        // Length modifiers. `h`/`l` double up to `hh`/`ll`; `j` is `ll`;
        // `L`/`t`/`z` are consumed but set no flag in this build.
        if c == b'l' || c == b'h' {
            let modifier = c;
            cursor = cursor.add(1);
            c = *cursor;
            if c == modifier {
                flags |= if modifier == b'l' { FLAG_LEN_LL } else { FLAG_LEN_HH };
                cursor = cursor.add(1);
                c = *cursor;
            } else {
                flags |= if modifier == b'l' { FLAG_LEN_L } else { FLAG_LEN_H };
            }
        } else if c == b'j' {
            flags |= FLAG_LEN_LL;
            cursor = cursor.add(1);
            c = *cursor;
        } else if c == b'L' || c == b't' || c == b'z' {
            cursor = cursor.add(1);
            c = *cursor;
        }
        st.flags = flags;

        match c {
            // "%<NUL>": the scan ends silently.
            0 => return st.count,
            b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => {
                let bits = fetch_pair(&mut args);
                float_converter()(state, c, &bits);
            }
            b'c' => {
                if flags & FLAG_LEN_L != 0 {
                    // %lc: wide char through a two-u16 scratch (original:
                    // `strh arg, [sp, #4]; strh 0, [sp, #6]`).
                    let wbuf = [fetch_word(&mut args) as u16, 0u16];
                    if st.reserved_28[2] == 0 {
                        convert_ls(state, wbuf.as_ptr());
                    }
                } else {
                    let cbuf = [fetch_word(&mut args) as u8, 0u8];
                    if st.reserved_28[2] == 0 {
                        // convert_s with min_len = 1: exactly one content
                        // char (even NUL), unless a given precision is
                        // <= 0, which prints nothing at all.
                        let len: i32 =
                            if flags & FLAG_PRECISION_GIVEN != 0 && st.precision <= 0 {
                                0
                            } else {
                                1
                            };
                        st.pad_remaining -= len;
                        pad_emit(state);
                        (st.emit_str.unwrap_unchecked())(
                            state,
                            cbuf.as_ptr(),
                            cbuf.as_ptr().add(len as usize),
                        );
                        st.count += len;
                        pad_emit_zero(state);
                    }
                }
            }
            b's' => {
                let s = fetch_ptr(&mut args);
                // state+0x30 (reserved_28[2]): string-disable flag. The
                // arg is consumed either way, like the original.
                if st.reserved_28[2] == 0 {
                    if flags & FLAG_LEN_L != 0 {
                        convert_ls(state, s as *const u16);
                    } else {
                        convert_s(state, s as *const u8);
                    }
                }
            }
            b'n' => {
                let dest = fetch_ptr(&mut args);
                store_n(state, dest);
            }
            b'x' | b'X' | b'p' => {
                // ll hex: the pair is consumed 8-aligned, but the ported
                // converters are u32-only — high word dropped (documented
                // in the module header).
                let value = if flags & FLAG_LEN_LL != 0 {
                    fetch_pair(&mut args) as u32
                } else {
                    fetch_word(&mut args)
                };
                match c {
                    b'x' => convert_x(state, value),
                    b'X' => convert_X(state, value),
                    _ => convert_p(state, value),
                }
            }
            b'o' => {
                let value = if flags & FLAG_LEN_LL != 0 {
                    fetch_pair(&mut args) as u32
                } else {
                    fetch_word(&mut args)
                };
                convert_o(state, value);
            }
            b'd' | b'i' | b'u' => {
                if flags & FLAG_LEN_LL != 0 {
                    let value = fetch_pair(&mut args);
                    if c == b'u' {
                        convert_llu(state, value);
                    } else {
                        convert_lld(state, value as i64);
                    }
                } else {
                    let value = fetch_word(&mut args);
                    if c == b'u' {
                        convert_u(state, value);
                    } else {
                        convert_d(state, value as i32);
                    }
                }
            }
            // Unknown conversion char (incl. '%' itself and 'S'): print
            // it verbatim through putc.
            _ => {
                (st.putc)(c, st.putc_ctx);
                st.count += 1;
            }
        }
        cursor = cursor.add(1); // consume the conversion character
        run_start = cursor;
    }
}

/// `_vsnprintf` — original: `FUN_08032f14` @ 0x08032f14 (76 bytes).
///
/// Builds the printf state on the stack and runs the engine. Argument
/// order recovered from the machine code: `(fmt, putc, putc_ctx, args)`
/// (see the module header). Installs [`str_emit`] as the default
/// `emit_str` hook and zeroes the string-disable flag; returns the
/// engine's character count (the original leaves it in r0).
#[no_mangle]
pub unsafe extern "C" fn _vsnprintf(
    fmt: *const u8,
    putc: PutcFn,
    putc_ctx: *mut c_void,
    args: *const u32,
) -> i32 {
    let mut state = PrintfState {
        reserved_00: [0; 2],
        prefix: core::ptr::null(),
        reserved_0c: [0; 3],
        flags: 0,
        putc,
        emit_str: Some(str_emit),
        putc_ctx,
        reserved_28: [0; 3],
        pad_remaining: 0,
        precision: 0,
        count: 0,
    };
    _printf(&mut state, fmt, args)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::printf_helpers::{bounded_putc, BoundedCursor};
    use std::string::String;
    use std::vec::Vec;

    struct Sink {
        buf: Vec<u8>,
    }

    unsafe extern "C" fn sink_putc(c: u8, ctx: *mut c_void) {
        (*(ctx as *mut Sink)).buf.push(c);
    }

    unsafe extern "C" fn sink_emit(state: *mut PrintfState, begin: *const u8, end: *const u8) {
        let sink = &mut *((*state).putc_ctx as *mut Sink);
        let mut p = begin;
        while (p as usize) < (end as usize) {
            sink.buf.push(*p);
            p = p.add(1);
        }
    }

    /// PutcFn-typed adapter over the stock bounded sink.
    unsafe extern "C" fn bounded_sink(c: u8, ctx: *mut c_void) {
        unsafe { bounded_putc(c, ctx as *mut BoundedCursor) };
    }

    fn make_state(sink: &mut Sink) -> PrintfState {
        PrintfState {
            reserved_00: [0; 2],
            prefix: core::ptr::null(),
            reserved_0c: [0; 3],
            flags: 0,
            putc: sink_putc,
            emit_str: Some(sink_emit),
            putc_ctx: sink as *mut Sink as *mut c_void,
            reserved_28: [0; 3],
            pad_remaining: 0,
            precision: 0,
            count: 0,
        }
    }

    /// Varargs buffer, 8-aligned like the AAPCS register-save area.
    #[repr(align(8))]
    struct ArgBuf([u32; 32]);

    /// Varargs builder replicating the AAPCS slot layout the engine
    /// expects: 32-bit args take one slot, pointers one native slot (two
    /// u32 on 64-bit hosts), 64-bit args start on an even slot.
    struct Args {
        buf: ArgBuf,
        len: usize,
    }

    impl Args {
        fn new() -> Args {
            Args {
                buf: ArgBuf([0; 32]),
                len: 0,
            }
        }
        fn int(mut self, value: u32) -> Args {
            self.buf.0[self.len] = value;
            self.len += 1;
            self
        }
        fn ptr(mut self, p: *const u8) -> Args {
            let value = p as usize;
            self.buf.0[self.len] = value as u32;
            self.len += 1;
            #[cfg(target_pointer_width = "64")]
            {
                self.buf.0[self.len] = (value >> 32) as u32;
                self.len += 1;
            }
            self
        }
        fn long(mut self, value: u64) -> Args {
            // 8-align the pair: with an 8-aligned base, even slot index.
            if self.len & 1 != 0 {
                self.len += 1;
            }
            self.buf.0[self.len] = value as u32;
            self.buf.0[self.len + 1] = (value >> 32) as u32;
            self.len += 2;
            self
        }
    }

    fn no_args() -> Args {
        Args::new()
    }

    /// Run the engine over a NUL-terminated format; asserts the return
    /// value is the emitted-char count.
    fn run(fmt: &[u8], args: &Args) -> (String, i32) {
        let mut sink = Sink { buf: Vec::new() };
        let mut state = make_state(&mut sink);
        let ret = unsafe { _printf(&mut state, fmt.as_ptr(), args.buf.0.as_ptr()) };
        assert_eq!(ret, state.count, "return value must be state.count");
        (String::from_utf8(sink.buf).unwrap(), ret)
    }

    #[test]
    fn plain_text_passthrough() {
        let (out, n) = run(b"hello world\0", &no_args());
        assert_eq!(out, "hello world");
        assert_eq!(n, 11);
        let (out, n) = run(b"\0", &no_args());
        assert_eq!(out, "");
        assert_eq!(n, 0);
    }

    #[test]
    fn decimal_signed() {
        assert_eq!(run(b"%d\0", &Args::new().int(42)).0, "42");
        assert_eq!(run(b"%d\0", &Args::new().int(-7i32 as u32)).0, "-7");
        assert_eq!(run(b"%i\0", &Args::new().int(0)).0, "0");
        assert_eq!(run(b"%u\0", &Args::new().int(u32::MAX)).0, "4294967295");
        assert_eq!(
            run(b"[%d][%d]\0", &Args::new().int(1).int(-1i32 as u32)).0,
            "[1][-1]"
        );
    }

    #[test]
    fn flags_width_precision_hex() {
        // The assignment's headline case: "%-8.3x".
        assert_eq!(run(b"%-8.3x\0", &Args::new().int(0xabc)).0, "abc     ");
        assert_eq!(run(b"%8.3x\0", &Args::new().int(0xabc)).0, "     abc");
        assert_eq!(run(b"%08x\0", &Args::new().int(0xabc)).0, "00000abc");
        assert_eq!(run(b"%#x\0", &Args::new().int(0xabc)).0, "0xabc");
        assert_eq!(run(b"%#X\0", &Args::new().int(0xabc)).0, "0XABC");
        assert_eq!(run(b"%X\0", &Args::new().int(0xdeadbeef)).0, "DEADBEEF");
        assert_eq!(run(b"%+d\0", &Args::new().int(5)).0, "+5");
        assert_eq!(run(b"% d\0", &Args::new().int(5)).0, " 5");
        // '+' wins over ' '; '-' wins over '0'.
        assert_eq!(run(b"%+ d\0", &Args::new().int(5)).0, "+5");
        assert_eq!(run(b"%-05d|\0", &Args::new().int(5)).0, "5    |");
    }

    #[test]
    fn strings() {
        let (out, _) = run(
            b"%s %-5s!\0",
            &Args::new().ptr(b"hello\0".as_ptr()).ptr(b"ab\0".as_ptr()),
        );
        assert_eq!(out, "hello ab   !");
        assert_eq!(run(b"%.3s\0", &Args::new().ptr(b"hello\0".as_ptr())).0, "hel");
        assert_eq!(
            run(b"%6.3s\0", &Args::new().ptr(b"hello\0".as_ptr())).0,
            "   hel"
        );
    }

    #[test]
    fn char_conversion() {
        assert_eq!(run(b"%c\0", &Args::new().int(b'A' as u32)).0, "A");
        assert_eq!(run(b"%5c\0", &Args::new().int(b'A' as u32)).0, "    A");
        assert_eq!(run(b"%-5c|\0", &Args::new().int(b'A' as u32)).0, "A    |");
        // A NUL char is still one content char (original: min_len = 1).
        let (out, n) = run(b"[%c]\0", &Args::new().int(0));
        assert_eq!(out.as_bytes(), &[b'[', 0, b']']);
        assert_eq!(n, 3);
        // A given precision <= 0 suppresses even the single char.
        assert_eq!(run(b"%.0c\0", &Args::new().int(b'A' as u32)).0, "");
        assert_eq!(run(b"%5.0c|\0", &Args::new().int(b'A' as u32)).0, "     |");
        // Precision >= 1 keeps the char.
        assert_eq!(run(b"%.3c\0", &Args::new().int(b'A' as u32)).0, "A");
    }

    #[test]
    fn long_long_decimal() {
        assert_eq!(run(b"%lld\0", &Args::new().long(0)).0, "0");
        assert_eq!(run(b"%lld\0", &Args::new().long(0x1_0000_0005)).0, "4294967301");
        assert_eq!(run(b"%lld\0", &Args::new().long(-1i64 as u64)).0, "-1");
        assert_eq!(
            run(b"%llu\0", &Args::new().long(u64::MAX)).0,
            "18446744073709551615"
        );
        assert_eq!(
            run(b"%lli\0", &Args::new().long(i64::MIN as u64)).0,
            "-9223372036854775808"
        );
        // The int before the ll leaves one padding slot for 8-alignment.
        assert_eq!(run(b"%d:%lld\0", &Args::new().int(7).long(3)).0, "7:3");
    }

    #[test]
    fn percent_escape_and_terminators() {
        assert_eq!(run(b"%%\0", &no_args()).0, "%");
        assert_eq!(run(b"a%%b\0", &no_args()).0, "a%b");
        assert_eq!(run(b"100%%\0", &no_args()).0, "100%");
        // A trailing lone '%' ends the scan silently.
        assert_eq!(run(b"abc%\0", &no_args()).0, "abc");
        // "%." with no digits: precision 0 given; '%' then prints.
        assert_eq!(run(b"%.%\0", &no_args()).0, "%");
    }

    #[test]
    fn unknown_conversions_print_verbatim() {
        // The original's default path emits the conversion char itself,
        // whatever flags/width were parsed before it.
        assert_eq!(run(b"%q\0", &no_args()).0, "q");
        assert_eq!(run(b"%-q\0", &no_args()).0, "q");
        assert_eq!(run(b"%5y\0", &no_args()).0, "y");
        // %S is NOT a wide-string conversion in this build.
        assert_eq!(run(b"%S\0", &no_args()).0, "S");
        // Interleaved with real conversions and plain text.
        assert_eq!(run(b"<%k|%d>\0", &Args::new().int(3)).0, "<k|3>");
    }

    #[test]
    fn store_n_writes_count() {
        let mut dest: i32 = -1;
        let (out, n) = run(
            b"abc%n\0",
            &Args::new().ptr(&mut dest as *mut i32 as *const u8),
        );
        assert_eq!(out, "abc");
        assert_eq!(dest, 3);
        assert_eq!(n, 3);

        // %hn narrows to 16 bits, %hhn to 8.
        let mut dest16: u16 = 0;
        run(
            b"abcdef%hn\0",
            &Args::new().ptr(&mut dest16 as *mut u16 as *const u8),
        );
        assert_eq!(dest16, 6);
        let mut dest8: u8 = 0;
        run(
            b"ab%hhn\0",
            &Args::new().ptr(&mut dest8 as *mut u8 as *const u8),
        );
        assert_eq!(dest8, 2);
    }

    #[test]
    fn star_width_and_precision() {
        assert_eq!(run(b"%*d\0", &Args::new().int(5).int(42)).0, "   42");
        // A negative '*' width left-justifies with the absolute value.
        assert_eq!(run(b"%*d|\0", &Args::new().int(-5i32 as u32).int(42)).0, "42   |");
        assert_eq!(run(b"%.*d\0", &Args::new().int(3).int(42)).0, "042");
        // A negative '*' precision is as if the precision were omitted.
        assert_eq!(run(b"%.*d\0", &Args::new().int(-1i32 as u32).int(42)).0, "42");
        assert_eq!(
            run(b"%*.*d\0", &Args::new().int(8).int(5).int(42)).0,
            "   00042"
        );
    }

    #[test]
    fn length_modifiers() {
        assert_eq!(run(b"%hhd\0", &Args::new().int(0xff)).0, "-1");
        assert_eq!(run(b"%hd\0", &Args::new().int(0x8000)).0, "-32768");
        assert_eq!(run(b"%hu\0", &Args::new().int(0x1ffff)).0, "65535");
        assert_eq!(run(b"%hhx\0", &Args::new().int(0x1ff)).0, "ff");
        // Single 'l' is 32-bit in this build.
        assert_eq!(run(b"%ld\0", &Args::new().int(-3i32 as u32)).0, "-3");
        assert_eq!(run(b"%lu\0", &Args::new().int(u32::MAX)).0, "4294967295");
        // 'z'/'t' are consumed but ignored; 'j' acts as ll.
        assert_eq!(run(b"%zd\0", &Args::new().int(9)).0, "9");
        assert_eq!(run(b"%td\0", &Args::new().int(9)).0, "9");
        assert_eq!(run(b"%jd\0", &Args::new().long(0x1_0000_0000)).0, "4294967296");
    }

    #[test]
    fn octal_and_pointer() {
        assert_eq!(run(b"%o\0", &Args::new().int(0o777)).0, "777");
        assert_eq!(run(b"%#o\0", &Args::new().int(8)).0, "010");
        assert_eq!(run(b"%p\0", &Args::new().int(0xabc)).0, "00000abc");
        assert_eq!(run(b"%p\0", &Args::new().int(0)).0, "00000000");
    }

    #[test]
    fn wide_string_via_ls() {
        let ws: [u16; 3] = [b'h' as u16, b'i' as u16, 0];
        assert_eq!(
            run(b"%ls\0", &Args::new().ptr(ws.as_ptr() as *const u8)).0,
            "hi"
        );
        // %lc of a BMP char converts like %ls of one char.
        let (out, _) = run(b"%lc\0", &Args::new().int(b'Z' as u32));
        assert_eq!(out, "Z");
    }

    #[test]
    fn ll_hex_and_octal_truncate_to_low_word() {
        // Documented deviation: the ported hex/octal converters are
        // u32-only, so only the low word prints (the original would
        // print "deadbeef000000ab"). The pair is still consumed
        // 8-aligned, keeping later args in sync.
        assert_eq!(
            run(b"%llx\0", &Args::new().long(0xdeadbeef_000000ab)).0,
            "ab"
        );
        assert_eq!(
            run(b"%llo|%d\0", &Args::new().long(0xffff_ffff_ffff_fff8).int(5)).0,
            "37777777770|5"
        );
    }

    #[test]
    fn real_retailos_format() {
        // "Clock = %d, mV = %04d" — a real retailOS format string.
        let (out, n) = run(
            b"Clock = %d, mV = %04d\0",
            &Args::new().int(1234).int(56),
        );
        assert_eq!(out, "Clock = 1234, mV = 0056");
        assert_eq!(n as usize, out.len());
    }

    #[test]
    fn string_disable_flag_suppresses_string_conversions() {
        // state+0x30 nonzero: %s/%c consume their args but emit nothing
        // (the original checks the flag before convert_s/convert_ls).
        let mut sink = Sink { buf: Vec::new() };
        let mut state = make_state(&mut sink);
        state.reserved_28[2] = 1;
        let args = Args::new()
            .ptr(b"hi\0".as_ptr())
            .int(b'A' as u32)
            .int(5);
        let ret = unsafe { _printf(&mut state, b"[%s][%c][%d]\0".as_ptr(), args.buf.0.as_ptr()) };
        assert_eq!(sink.buf, b"[][][5]");
        assert_eq!(ret, 7);
    }

    #[test]
    fn float_routes_through_converter_hook() {
        static mut SEEN: Option<(u8, u64)> = None;
        unsafe extern "C" fn record(_state: *mut PrintfState, spec: u8, bits: *const u64) {
            unsafe {
                *core::ptr::addr_of_mut!(SEEN) = Some((spec, *bits));
            }
        }
        unsafe {
            *core::ptr::addr_of_mut!(FLOAT_CONVERTER) = record;
        }
        // The hook receives the spec char and the raw double bits; the
        // default stub (and this recorder) emit nothing.
        let (out, _) = run(b"%f\0", &Args::new().long(0x3ff0000000000000));
        assert_eq!(out, "");
        assert_eq!(
            unsafe { *core::ptr::addr_of!(SEEN) },
            Some((b'f', 0x3ff0000000000000))
        );
        // %a goes through the same hook; the pair fetch stays 8-aligned
        // after a 32-bit arg.
        let _ = run(b"%d|%a\0", &Args::new().int(1).long(0x4000000000000000));
        assert_eq!(
            unsafe { *core::ptr::addr_of!(SEEN) },
            Some((b'a', 0x4000000000000000))
        );
        // Restore the documented stub for any later test.
        unsafe {
            *core::ptr::addr_of_mut!(FLOAT_CONVERTER) = float_not_ported;
        }
        assert_eq!(run(b"%g\0", &Args::new().long(0)).0, "");
    }

    #[test]
    fn vsnprintf_builds_state_and_formats() {
        // Drive the dispatcher with the stock bounded sink.
        let mut buf = [0u8; 32];
        let mut bounds = BoundedCursor {
            cursor: buf.as_mut_ptr(),
            end: unsafe { buf.as_mut_ptr().add(31) },
        };
        let args = Args::new().int(7).int(0x2a);
        let n = unsafe {
            _vsnprintf(
                b"a=%d b=%02x\0".as_ptr(),
                bounded_sink,
                &mut bounds as *mut BoundedCursor as *mut c_void,
                args.buf.0.as_ptr(),
            )
        };
        let written = unsafe { bounds.cursor.offset_from(buf.as_ptr()) } as usize;
        assert_eq!(&buf[..written], b"a=7 b=2a");
        assert_eq!(n as usize, written);
    }

    #[test]
    fn str_emit_pushes_slice_without_counting() {
        let mut sink = Sink { buf: Vec::new() };
        let mut state = make_state(&mut sink);
        unsafe {
            str_emit(&mut state, b"abcdef".as_ptr(), b"abcdef".as_ptr().add(3));
        }
        assert_eq!(sink.buf, b"abc");
        assert_eq!(state.count, 0);
        // Empty slice emits nothing.
        unsafe {
            str_emit(&mut state, b"x".as_ptr(), b"x".as_ptr());
        }
        assert_eq!(sink.buf, b"abc");
    }
}
