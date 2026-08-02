//! The RBSP bit cursor every H.264 syntax parser advances through.
//!
//! The cursor is a three-word object the decoder keeps on the stack of
//! whichever parse function owns the NAL unit:
//!
//! ```text
//! +0x00  const u8 *data   first byte of the NAL payload
//! +0x04  i32       bit_pos bit offset from `data` (signed: parsers rewind)
//! +0x08  const u8 *end    one past the last readable byte
//! ```
//!
//! Every read primitive (`0x082d0630`, `0x0809b040`, `0x082c5df0`)
//! leaves `bit_pos` alone and instead reports, through a caller-owned
//! `u8` flag, whether it had to step over an emulation-prevention byte
//! — the `0x03` an encoder inserts to break up a `00 00 0x` sequence,
//! which is part of the byte stream but not of the syntax. The parser
//! then calls [`h264_bitstream_advance`] to commit the read, and that
//! is where the extra byte is paid for.

use core::ptr::{addr_of, addr_of_mut};

/// The RBSP bit cursor (original layout: three words, see the module
/// header).
///
/// `data` and `end` are real pointers, so the struct is 12 bytes on the
/// armv5te target and wider on a 64-bit host. Nothing reads them at a
/// fixed byte offset — the port goes through these named `#[repr(C)]`
/// fields — so both layouts are correct.
#[repr(C)]
pub struct RbspBitReader {
    /// First byte of the NAL payload; `bit_pos` is relative to it.
    pub data: *const u8,
    /// Bit offset into the payload. Signed: `>> 3` is an arithmetic
    /// shift in the original (`add r1, r2, r1, asr #3`), so a negative
    /// offset rounds towards minus infinity, not towards zero.
    pub bit_pos: i32,
    /// One past the last readable byte.
    pub end: *const u8,
}

/// h264_bitstream_advance — original: `FUN_082b3258` @ 0x082b3258
/// (60 bytes, all code — no literal pool; 114 `bl` call sites, binary-
/// scanned by decoding every B/BL word in osos.dec. A leaf: no `push`,
/// ends in `bx lr`).
///
/// Commits a syntax element read: consumes the emulation-prevention
/// flag the read primitive just set, advances the cursor by `bits` (plus
/// the 8 bits of the skipped `0x03` byte when the flag was set), and
/// reports whether the new position is still inside the payload.
///
/// The flag is cleared unconditionally — including on the path where it
/// was already clear — so one flag variable serves a whole parse
/// function: `dec_ref_pic_marking` @ 0x08365640 declares a single
/// `local_14`, zeroes it once, and hands its address to every read and
/// every advance in the function.
///
/// The bounds test is `data + (bit_pos >> 3) < end`, an **unsigned**
/// pointer comparison (`movcc`/`movcs`) on the byte the new bit offset
/// lands in. It is a strict `<` against `end`, so a cursor that lands
/// exactly on `end` reports exhausted; and because it only looks at the
/// byte address, advancing to the last bit of the last byte still
/// reports "in bounds". The cursor is updated either way — the original
/// stores `bit_pos` before it tests anything, and callers that get
/// `false` abandon the whole NAL unit rather than re-reading.
///
/// Deliberate deviations: none. `bits` and `bit_pos` are added with
/// wrapping arithmetic, matching the original's `add` (Rust would
/// otherwise panic on overflow in a debug build); the pointer walk uses
/// `wrapping_offset` for the same reason.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn h264_bitstream_advance(
    reader: *mut RbspBitReader,
    bits: i32,
    emulation_byte_pending: *mut u8,
) -> bool {
    let skipped_byte = emulation_byte_pending.read() != 0;
    emulation_byte_pending.write(0);

    let consumed = if skipped_byte {
        bits.wrapping_add(8)
    } else {
        bits
    };
    let bit_pos = addr_of!((*reader).bit_pos).read().wrapping_add(consumed);
    addr_of_mut!((*reader).bit_pos).write(bit_pos);

    let data = addr_of!((*reader).data).read();
    let end = addr_of!((*reader).end).read();
    data.wrapping_offset((bit_pos >> 3) as isize) < end
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload of `len` bytes with the cursor at `bit_pos`.
    fn reader(payload: &[u8], bit_pos: i32) -> RbspBitReader {
        RbspBitReader {
            data: payload.as_ptr(),
            bit_pos,
            end: unsafe { payload.as_ptr().add(payload.len()) },
        }
    }

    /// The original, transcribed from the disassembly.
    fn reference(bit_pos: i32, bits: i32, flag: u8, len: i32) -> (i32, bool) {
        let consumed = if flag != 0 { bits.wrapping_add(8) } else { bits };
        let new_pos = bit_pos.wrapping_add(consumed);
        (new_pos, (new_pos >> 3) < len)
    }

    #[test]
    fn plain_advance_leaves_the_flag_clear() {
        let payload = [0u8; 8];
        let mut r = reader(&payload, 0);
        let mut flag = 0u8;
        assert!(unsafe { h264_bitstream_advance(&mut r, 5, &mut flag) });
        assert_eq!(r.bit_pos, 5);
        assert_eq!(flag, 0);
    }

    #[test]
    fn pending_emulation_byte_costs_eight_extra_bits_and_is_consumed() {
        let payload = [0u8; 8];
        let mut r = reader(&payload, 3);
        let mut flag = 1u8;
        assert!(unsafe { h264_bitstream_advance(&mut r, 5, &mut flag) });
        assert_eq!(r.bit_pos, 3 + 5 + 8);
        assert_eq!(flag, 0, "the flag is cleared for the next read");

        // A second advance with the flag now clear costs only `bits`.
        assert!(unsafe { h264_bitstream_advance(&mut r, 5, &mut flag) });
        assert_eq!(r.bit_pos, 3 + 5 + 8 + 5);
    }

    /// Any nonzero flag byte counts — the original's `cmp r3, #0` runs
    /// on the zero-extended `ldrb`, and the read primitives store 1.
    #[test]
    fn any_nonzero_flag_byte_counts() {
        for flag_in in [1u8, 2, 0x80, 0xff] {
            let payload = [0u8; 8];
            let mut r = reader(&payload, 0);
            let mut flag = flag_in;
            unsafe { h264_bitstream_advance(&mut r, 1, &mut flag) };
            assert_eq!(r.bit_pos, 9, "flag={flag_in:#x}");
            assert_eq!(flag, 0);
        }
    }

    #[test]
    fn landing_exactly_on_end_reports_exhausted() {
        let payload = [0u8; 4];

        // Last bit of the last byte: byte 3 < end, still in bounds.
        let mut r = reader(&payload, 31);
        let mut flag = 0u8;
        assert!(unsafe { h264_bitstream_advance(&mut r, 0, &mut flag) });

        // One more bit rolls into byte 4 == end: exhausted.
        let mut r = reader(&payload, 31);
        assert!(!unsafe { h264_bitstream_advance(&mut r, 1, &mut flag) });
        assert_eq!(r.bit_pos, 32, "the cursor moves even when it runs out");

        // Past the end stays exhausted.
        let mut r = reader(&payload, 32);
        assert!(!unsafe { h264_bitstream_advance(&mut r, 100, &mut flag) });
    }

    /// An empty payload (`data == end`) is exhausted before the first
    /// read, even for a zero-bit advance.
    #[test]
    fn empty_payload_is_exhausted_immediately() {
        let payload = [0u8; 0];
        let mut r = reader(&payload, 0);
        let mut flag = 0u8;
        assert!(!unsafe { h264_bitstream_advance(&mut r, 0, &mut flag) });
    }

    /// Parsers rewind (a failed trial parse restores `bit_pos`), so the
    /// shift has to be arithmetic: -1 must land in byte -1, not byte 0.
    #[test]
    fn negative_positions_round_towards_minus_infinity() {
        let payload = [0u8; 8];

        let mut r = reader(&payload, 0);
        let mut flag = 0u8;
        // -1 >> 3 == -1: one byte *before* `data`, which is still < end.
        assert!(unsafe { h264_bitstream_advance(&mut r, -1, &mut flag) });
        assert_eq!(r.bit_pos, -1);
        assert_eq!(-1i32 >> 3, -1, "arithmetic shift, not division");

        let mut r = reader(&payload, 4);
        assert!(unsafe { h264_bitstream_advance(&mut r, -12, &mut flag) });
        assert_eq!(r.bit_pos, -8);
    }

    #[test]
    fn matches_reference_over_positions_bit_counts_and_flags() {
        let payload = [0u8; 16];
        let len = payload.len() as i32;
        for bit_pos in [-16i32, -1, 0, 1, 7, 8, 63, 120, 127, 128, 200] {
            for bits in [-8i32, -1, 0, 1, 2, 5, 8, 16, 32, 64] {
                for flag in [0u8, 1] {
                    let mut r = reader(&payload, bit_pos);
                    let mut f = flag;
                    let got = unsafe { h264_bitstream_advance(&mut r, bits, &mut f) };
                    let (want_pos, want_in) = reference(bit_pos, bits, flag, len);
                    assert_eq!(r.bit_pos, want_pos, "{bit_pos} {bits} {flag}");
                    assert_eq!(got, want_in, "{bit_pos} {bits} {flag}");
                    assert_eq!(f, 0);
                }
            }
        }
    }

    /// Overflow wraps like the original's `add`, and does not panic.
    #[test]
    fn saturated_bit_positions_wrap_like_the_original() {
        let payload = [0u8; 8];
        let mut r = reader(&payload, i32::MAX);
        let mut flag = 1u8;
        // The verdict is not asserted: the wrapped-negative byte offset
        // lands at `data - 0x0fff_ffff`, whose unsigned comparison
        // against `end` depends on where the payload sits in the address
        // space. What matters is that the port wraps instead of
        // panicking, exactly like the original's `add`.
        unsafe { h264_bitstream_advance(&mut r, 1, &mut flag) };
        assert_eq!(r.bit_pos, i32::MAX.wrapping_add(9));
    }
}
