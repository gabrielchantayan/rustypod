//! printf support cluster: output sinks, field-width padding emitters, and
//! argument widening for the stock firmware's printf core (ARM ADS 1.0.1).
//!
//! Ports:
//! - `mem_putc`       @ 0x08032f68 (20 bytes) — unbounded sink for sprintf:
//!   store `c` at `*dest`, advance `*dest` by one.
//! - `bounded_putc`   @ 0x08032f7c (20 bytes) — bounded sink for snprintf:
//!   store only while `cursor < end`, silently dropping overflow.
//! - `pad_emit`       @ 0x0802f208 (84 bytes) — leading field-width padding:
//!   emits `pad_remaining` fill chars (`'0'` with FLAG_ZERO_PAD else `' '`)
//!   through the state putc, unless FLAG_LEFT_JUSTIFY is set.
//! - `pad_emit_zero`  @ 0x0802f25c (72 bytes) — trailing padding for
//!   left-justified fields: emits `pad_remaining` spaces, only when
//!   FLAG_LEFT_JUSTIFY is set.
//! - `widen_signed`   @ 0x0802f2a4 (36 bytes) — sign-extend an i32 argument
//!   from 8 bits (hh) or 16 bits (h) per the length flags.
//! - `widen_unsigned` @ 0x0802f2c8 (32 bytes) — same, zero-extending.
//!
//! The shared [`PrintfState`] layout below is the ABI contract with the
//! printf converter core (ported separately): field offsets are taken from
//! the original machine code and must not change.
//!
//! Simplifications vs. the original:
//! - Ghidra shows putc calls through `fn_ptr & 0xfffffffc` (Thumb-bit
//!   clear); the firmware is pure ARM, so the mask is omitted.
//! - The pad loops share one private helper (`emit_fill`); the originals
//!   duplicate the loop body verbatim. Semantics (signed `pad_remaining`
//!   countdown, count bump per emitted char) are identical.

use core::ffi::c_void;

/// Format flag: `-` — left-justify within the field width.
pub const FLAG_LEFT_JUSTIFY: u32 = 0x001;
/// Format flag: `0` — pad with zeros instead of spaces.
pub const FLAG_ZERO_PAD: u32 = 0x010;
/// Format flag: `.` — a precision was given (`precision` field is valid).
/// Not used by this module; consumed by the string/float converters.
pub const FLAG_PRECISION_GIVEN: u32 = 0x020;
/// Length modifier `h`: argument is 16-bit.
pub const FLAG_LEN_H: u32 = 0x100;
/// Length modifier `hh`: argument is 8-bit.
pub const FLAG_LEN_HH: u32 = 0x400;

/// Character sink used by the printf core, called as `putc(c, putc_ctx)`.
/// `mem_putc` / `bounded_putc` below are the two stock sinks.
pub type PutcFn = unsafe extern "C" fn(c: u8, ctx: *mut c_void);

/// String-slice emitter stored at offset 0x20, called as
/// `emit_str(state, begin, end)` by the string converter
/// (`FUN_0802f2e8`). Not used by this module.
pub type EmitStrFn = unsafe extern "C" fn(state: *mut PrintfState, begin: *const u8, end: *const u8);

/// Shared printf converter state (64 bytes), the ABI contract between the
/// printf core and its helpers. Offsets recovered from the original
/// machine code:
///
/// | off  | field           | evidence |
/// |------|-----------------|----------|
/// | 0x00 | `reserved_00`   | untouched by this cluster |
/// | 0x08 | `prefix`        | float converter (`FUN_08032d70`) reads `**prefix` — char* of the sign/prefix string ("-", "+", "0x", ...) |
/// | 0x0c | `reserved_0c`   | float converter sets 0x0c/0x10 to -1 (int/frac widths); 0x14 unseen by this cluster |
/// | 0x18 | `flags`         | tested here: bits 0x1 / 0x10 / 0x100 / 0x400; string converter also uses 0x20 |
/// | 0x1c | `putc`          | called by both pad emitters |
/// | 0x20 | `emit_str`      | called by string converter as `(state, begin, end)` |
/// | 0x24 | `putc_ctx`      | second argument to `putc` |
/// | 0x28 | `reserved_28`   | untouched by this cluster |
/// | 0x34 | `pad_remaining` | signed fill count, set by the converters as `width - content_len` |
/// | 0x38 | `precision`     | string converter loops to it when FLAG_PRECISION_GIVEN (default 6 for floats) |
/// | 0x3c | `count`         | total chars emitted, bumped per pad char and per content slice |
#[repr(C)]
pub struct PrintfState {
    pub reserved_00: [u32; 2],
    pub prefix: *const *const u8,
    pub reserved_0c: [i32; 3],
    pub flags: u32,
    pub putc: PutcFn,
    pub emit_str: Option<EmitStrFn>,
    pub putc_ctx: *mut c_void,
    pub reserved_28: [u32; 3],
    pub pad_remaining: i32,
    pub precision: i32,
    pub count: i32,
}

impl PrintfState {
    /// `-` flag: content is left-justified, padding goes on the right.
    pub fn is_left_justified(&self) -> bool {
        self.flags & FLAG_LEFT_JUSTIFY != 0
    }

    /// `0` flag: pad with zeros (only meaningful for right-justified
    /// numeric output).
    pub fn zero_pad(&self) -> bool {
        self.flags & FLAG_ZERO_PAD != 0
    }

    /// Fill character for leading padding: `'0'` with FLAG_ZERO_PAD,
    /// `' '` otherwise (original: `tst flags,#16; moveq ' '; movne '0'`).
    pub fn fill_char(&self) -> u8 {
        if self.zero_pad() {
            b'0'
        } else {
            b' '
        }
    }
}

/// `mem_putc` — original: `FUN_08032f68` @ 0x08032f68 (20 bytes).
///
/// sprintf sink: stores `c` at `*dest` and advances `*dest` by one.
/// `dest` points at the cursor word of the caller's output state (in the
/// original, an on-stack `{cursor, end}` pair whose `end` this sink
/// ignores).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mem_putc(c: u8, dest: *mut *mut u8) {
    let cursor = *dest;
    *cursor = c;
    *dest = cursor.add(1);
}

/// Cursor/end pair for [`bounded_putc`] (matches the on-stack pair the
/// original snprintf builds and passes by pointer).
#[repr(C)]
pub struct BoundedCursor {
    pub cursor: *mut u8,
    pub end: *const u8,
}

/// `bounded_putc` — original: `FUN_08032f7c` @ 0x08032f7c (20 bytes).
///
/// snprintf sink: stores `c` and advances the cursor only while
/// `cursor < end` (unsigned compare); overflow characters are silently
/// dropped so the caller's total count still reflects the untruncated
/// length.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bounded_putc(c: u8, bounds: *mut BoundedCursor) {
    let b = &mut *bounds;
    if (b.cursor as usize) < (b.end as usize) {
        let cursor = b.cursor;
        b.cursor = cursor.add(1);
        *cursor = c;
    }
}

/// Shared body of the two pad emitters: emit `fill` `pad_remaining` times
/// (signed countdown — non-positive counts emit nothing), bumping
/// `count` per character. Original loop: `subs r5,r5,#1; bpl body`.
unsafe fn emit_fill(state: *mut PrintfState, fill: u8) {
    let mut remaining = (*state).pad_remaining;
    loop {
        remaining -= 1;
        if remaining < 0 {
            break;
        }
        ((*state).putc)(fill, (*state).putc_ctx);
        (*state).count += 1;
    }
}

/// `pad_emit` — original: `FUN_0802f208` @ 0x0802f208 (84 bytes).
///
/// Leading field-width padding, called by the converters before the
/// content. No-op when FLAG_LEFT_JUSTIFY is set (padding then belongs
/// after the content, see [`pad_emit_zero`]). Fill is `'0'` with
/// FLAG_ZERO_PAD, `' '` otherwise.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pad_emit(state: *mut PrintfState) {
    let fill = (*state).fill_char();
    if (*state).is_left_justified() {
        return;
    }
    emit_fill(state, fill);
}

/// `pad_emit_zero` — original: `FUN_0802f25c` @ 0x0802f25c (72 bytes).
///
/// Trailing field-width padding, called by the converters after the
/// content. Emits spaces (never zeros) and only when FLAG_LEFT_JUSTIFY
/// is set; otherwise a no-op.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pad_emit_zero(state: *mut PrintfState) {
    if !(*state).is_left_justified() {
        return;
    }
    emit_fill(state, b' ');
}

/// `widen_signed` — original: `FUN_0802f2a4` @ 0x0802f2a4 (36 bytes).
///
/// Re-widens a signed conversion argument per the length flags: with
/// `hh` sign-extend from 8 bits, else with `h` from 16 bits, else pass
/// through. (`hh` wins if both bits are set, matching the original's
/// test order.)
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn widen_signed(value: i32, state: *const PrintfState) -> i32 {
    let flags = (*state).flags;
    if flags & FLAG_LEN_HH != 0 {
        value as i8 as i32
    } else if flags & FLAG_LEN_H != 0 {
        value as i16 as i32
    } else {
        value
    }
}

/// `widen_unsigned` — original: `FUN_0802f2c8` @ 0x0802f2c8 (32 bytes).
///
/// Unsigned twin of [`widen_signed`]: masks to 8 bits (`hh`) or 16 bits
/// (`h`), else passes through.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn widen_unsigned(value: u32, state: *const PrintfState) -> u32 {
    let flags = (*state).flags;
    if flags & FLAG_LEN_HH != 0 {
        value & 0xff
    } else if flags & FLAG_LEN_H != 0 {
        value & 0xffff
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Recording sink for the pad emitters.
    struct Sink {
        buf: Vec<u8>,
    }

    unsafe extern "C" fn sink_putc(c: u8, ctx: *mut c_void) {
        (*(ctx as *mut Sink)).buf.push(c);
    }

    fn state(flags: u32, pad_remaining: i32, sink: &mut Sink) -> PrintfState {
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
            precision: 0,
            count: 0,
        }
    }

    /// Raw offsets only hold on the 32-bit ARM target; on 64-bit hosts
    /// the pointer fields widen. Functional behavior is host-testable
    /// either way since all access goes through named fields.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn struct_layout_matches_original() {
        assert_eq!(core::mem::size_of::<PrintfState>(), 0x40);
        assert_eq!(core::mem::offset_of!(PrintfState, flags), 0x18);
        assert_eq!(core::mem::offset_of!(PrintfState, putc), 0x1c);
        assert_eq!(core::mem::offset_of!(PrintfState, emit_str), 0x20);
        assert_eq!(core::mem::offset_of!(PrintfState, putc_ctx), 0x24);
        assert_eq!(core::mem::offset_of!(PrintfState, pad_remaining), 0x34);
        assert_eq!(core::mem::offset_of!(PrintfState, precision), 0x38);
        assert_eq!(core::mem::offset_of!(PrintfState, count), 0x3c);
        assert_eq!(core::mem::size_of::<BoundedCursor>(), 8);
    }

    #[test]
    fn mem_putc_appends_and_advances() {
        let mut buf = [0u8; 8];
        let mut cursor = buf.as_mut_ptr();
        unsafe {
            for c in *b"abc" {
                mem_putc(c, &mut cursor);
            }
            assert_eq!(&buf[..3], b"abc");
            assert_eq!(cursor, buf.as_mut_ptr().add(3));
        }
    }

    #[test]
    fn bounded_putc_stops_at_end() {
        let mut buf = [0u8; 4];
        let mut bounds = BoundedCursor {
            cursor: buf.as_mut_ptr(),
            // Room for 3 chars, like snprintf reserving the NUL.
            end: unsafe { buf.as_mut_ptr().add(3) },
        };
        unsafe {
            for c in *b"abcdef" {
                bounded_putc(c, &mut bounds);
            }
            assert_eq!(&buf[..3], b"abc");
            assert_eq!(bounds.cursor, buf.as_mut_ptr().add(3));
        }
    }

    #[test]
    fn bounded_putc_empty_range_drops_everything() {
        let mut buf = [0u8; 1];
        let mut bounds = BoundedCursor {
            cursor: buf.as_mut_ptr(),
            end: buf.as_mut_ptr(),
        };
        unsafe {
            bounded_putc(b'x', &mut bounds);
            assert_eq!(bounds.cursor, buf.as_mut_ptr());
        }
    }

    #[test]
    fn pad_emit_spaces_when_right_justified() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(0, 3, &mut sink);
        unsafe { pad_emit(&mut st) };
        assert_eq!(sink.buf, b"   ");
        assert_eq!(st.count, 3);
    }

    #[test]
    fn pad_emit_zeros_with_zero_pad_flag() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_ZERO_PAD, 4, &mut sink);
        unsafe { pad_emit(&mut st) };
        assert_eq!(sink.buf, b"0000");
        assert_eq!(st.count, 4);
    }

    #[test]
    fn pad_emit_suppressed_when_left_justified() {
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_LEFT_JUSTIFY | FLAG_ZERO_PAD, 5, &mut sink);
        unsafe { pad_emit(&mut st) };
        assert!(sink.buf.is_empty());
        assert_eq!(st.count, 0);
    }

    #[test]
    fn pad_emit_nothing_for_nonpositive_count() {
        for pad in [-2, -1, 0] {
            let mut sink = Sink { buf: Vec::new() };
            let mut st = state(0, pad, &mut sink);
            unsafe { pad_emit(&mut st) };
            assert!(sink.buf.is_empty(), "pad={pad}");
            assert_eq!(st.count, 0);
        }
    }

    #[test]
    fn pad_emit_zero_trailing_spaces_only_when_left_justified() {
        // Left-justified: spaces after the content, zeros never used.
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_LEFT_JUSTIFY | FLAG_ZERO_PAD, 3, &mut sink);
        unsafe { pad_emit_zero(&mut st) };
        assert_eq!(sink.buf, b"   ");
        assert_eq!(st.count, 3);

        // Right-justified: no trailing pad.
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(0, 3, &mut sink);
        unsafe { pad_emit_zero(&mut st) };
        assert!(sink.buf.is_empty());
        assert_eq!(st.count, 0);
    }

    #[test]
    fn pads_around_content() {
        // Simulate "%-5d" of "12": no leading pad, content, 3 trailing.
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_LEFT_JUSTIFY, 3, &mut sink);
        unsafe {
            pad_emit(&mut st);
            for c in *b"12" {
                (st.putc)(c, st.putc_ctx);
                st.count += 1;
            }
            pad_emit_zero(&mut st);
        }
        assert_eq!(sink.buf, b"12   ");
        assert_eq!(st.count, 5);

        // Simulate "%05d" of "12": 3 leading zeros, content, no trailing.
        let mut sink = Sink { buf: Vec::new() };
        let mut st = state(FLAG_ZERO_PAD, 3, &mut sink);
        unsafe {
            pad_emit(&mut st);
            for c in *b"12" {
                (st.putc)(c, st.putc_ctx);
                st.count += 1;
            }
            pad_emit_zero(&mut st);
        }
        assert_eq!(sink.buf, b"00012");
        assert_eq!(st.count, 5);
    }

    #[test]
    fn widen_signed_extends_per_length_flags() {
        let mut sink = Sink { buf: Vec::new() };
        for (flags, value, expected) in [
            (0, 0x12345678u32 as i32, 0x12345678),
            (FLAG_LEN_HH, 0x80, -128),
            (FLAG_LEN_HH, 0x7f, 127),
            (FLAG_LEN_HH, 0xff, -1),
            (FLAG_LEN_H, 0x8000, -32768),
            (FLAG_LEN_H, 0x7fff, 32767),
            (FLAG_LEN_H, 0xffff, -1),
            // hh wins when both are set (original tests 0x400 first).
            (FLAG_LEN_H | FLAG_LEN_HH, 0x8080, -128),
        ] {
            let st = state(flags, 0, &mut sink);
            assert_eq!(unsafe { widen_signed(value, &st) }, expected, "flags={flags:#x} value={value:#x}");
        }
    }

    #[test]
    fn widen_unsigned_masks_per_length_flags() {
        let mut sink = Sink { buf: Vec::new() };
        for (flags, value, expected) in [
            (0, 0x12345678, 0x12345678),
            (FLAG_LEN_HH, 0xdeadbeef, 0xef),
            (FLAG_LEN_H, 0xdeadbeef, 0xbeef),
            (FLAG_LEN_H | FLAG_LEN_HH, 0xdeadbeef, 0xef),
        ] {
            let st = state(flags, 0, &mut sink);
            assert_eq!(unsafe { widen_unsigned(value, &st) }, expected, "flags={flags:#x} value={value:#x}");
        }
    }
}
