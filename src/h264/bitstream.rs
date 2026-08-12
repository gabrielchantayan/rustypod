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
//!
//! The module also hosts the MPEG-style video header parser's
//! read-and-advance primitive [`bitstream_read_advance`] @ 0x080ebbe0
//! (start codes 0x000001B5/B3/B2), which runs over the same
//! `{data @ +0x00, bit_pos @ +0x04}` word pair but knows no `end`
//! word: it fetches `bit_count` bits MSB-first through
//! [`bitstream_msb_fetch`] @ 0x080efa38 and commits them with a plain
//! `bit_pos += bit_count`, bounds-check free. Both functions address
//! the stream object's words by pointer-sized word index (byte-exact
//! +0x00/+0x04 on the 32-bit target, disjoint slots on a 64-bit host).

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

/// Emulation-prevention probe — original: `FUN_082c319c` @ 0x082c319c
/// (60 bytes, all code — no literal pool, no stack traffic, a leaf
/// ending `bx lr`; 5 `bl` call sites, all in the RBSP read
/// primitives: two here, three in read_bits @ 0x082d0630).
///
/// Reports whether `p` points at the `0x03` of an H.264
/// emulation-prevention sequence: the byte after `p` must exist
/// (`p + 1 < end`, an UNSIGNED comparison — `add r2,r0,#1; cmp r2,r1;
/// bcs`) and be `<= 3`, and the bytes at `p[-2]`, `p[-1]`, `p[0]`
/// must be `00 00 03`. The two bytes BEFORE `p` are read
/// unconditionally once the bounds test passes; in the firmware that
/// is always sound because the NAL payload follows the `00 00 01`
/// start code in flat DRAM. Host tests pad two readable bytes before
/// `data` for the same reason.
///
/// Unported elsewhere in the tree, so it is transcribed here as a
/// small local helper rather than put behind a dispatch seam: its
/// exact behavior is binary-verified from the 15-instruction body
/// above.
unsafe fn emulation_prevention_probe(p: *const u8, end: *const u8) -> bool {
    if p.wrapping_add(1) >= end {
        return false;
    }
    p.wrapping_sub(2).read() == 0
        && p.wrapping_sub(1).read() == 0
        && p.read() == 3
        && p.wrapping_add(1).read() <= 3
}

/// h264_bitstream_count_leading_zeros — original: `FUN_0809b040` @
/// 0x0809b040 (240 bytes, all code — no literal pool; exactly one
/// `bl` call site, in cg_exp_golomb_ue_read @ 0x082c5df0, which is
/// why the signature matches that reader's CG_EXP_GOLOMB_OPS slot;
/// two direct calls to the emulation-prevention probe @ 0x082c319c).
///
/// Counts the consecutive zero bits from the cursor's bit position to
/// the next `1` bit — the Exp-Golomb prefix length — WITHOUT moving
/// the cursor, stepping over emulation-prevention `0x03` bytes and
/// reporting through `emulation_byte_pending` each time it does.
///
/// Algorithm, exactly as the body has it:
///
/// ```text
/// *flag = 0                             // before any cursor load
/// p = data + (bit_pos asr 3)            // arithmetic: rewinds work
/// first = 8 - (bit_pos - (bit_pos & ~7))// bits left in byte, 1..=8
/// if first == 8 && probe(p, end):       // aligned start on a 0x03
///     p += 1; *flag = 1
/// window = (*p << (8 - first)) & 0xff   // low `first` bits, top-aligned
/// for i in 0..first:                    // zeros in the partial window
///     if window & 0x80: return count
///     window = (window & 0x7f) << 1; count += 1
/// loop:                                 // whole bytes from here on
///     if probe(p, end): skip = true; *flag = 1
///     if skip: p += 1; skip = false     // step over the 0x03
///     byte = *p; p += 1
///     for i in 0..8:
///         if byte & 0x80: return count
///         byte = (byte & 0x7f) << 1; count += 1
/// ```
///
/// Probes happen only at byte boundaries, before the byte is read;
/// the byte immediately after a skipped `0x03` is never re-probed,
/// and a misaligned first byte is never probed at all. The flag is a
/// plain store of 1 on every probe hit, cleared once at entry — never
/// an accumulation of the old value. The only bounds check anywhere
/// is inside the probe (`p + 1 < end`): the byte READS are unchecked,
/// so at `end` the probe fails and the byte at `end` is read anyway —
/// exactly like the original, and callers treat running out of NAL as
/// fatal to the whole unit rather than re-reading.
///
/// Deviations:
/// - The `iVar7 == 0` arm of the original (`cmp r7,#0; beq
///   LAB_0809b0f0`) is dead — `first = 8 - (bit_pos & 7)` lies in
///   1..=8 for every i32 — and is not reproduced; entering the
///   whole-byte loop with neither a probe nor a first-byte read is
///   unreachable.
/// - The probe @ 0x082c319c is unported; it is transcribed above as
///   [`emulation_prevention_probe`] (exact 15-instruction behavior
///   binary-verified), so no dispatch seam is introduced.
/// - `end` is reloaded from the cursor before every probe call, like
///   the original's per-call-site `ldr r1,[r6,#8]`.
/// - `count` wraps (`wrapping_add`) where the original uses `add`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn h264_bitstream_count_leading_zeros(
    reader: *mut RbspBitReader,
    emulation_byte_pending: *mut u8,
) -> u32 {
    emulation_byte_pending.write(0);

    let data = addr_of!((*reader).data).read();
    let bit_pos = addr_of!((*reader).bit_pos).read();

    let mut p = data.wrapping_offset((bit_pos >> 3) as isize);
    // Bits left in the first byte, 1..=8. `bit_pos - (bit_pos & !7)`
    // is the original's `bic`/`sub` pair: a non-negative bit-in-byte
    // index even for rewound (negative) positions.
    let first: i32 = 8 - (bit_pos - (bit_pos & !7));
    let mut count: u32 = 0;

    if first == 8 && emulation_prevention_probe(p, addr_of!((*reader).end).read()) {
        p = p.wrapping_add(1);
        emulation_byte_pending.write(1);
    }

    // First (possibly partial) byte: its low `first` bits, top-aligned.
    let mut window = (u32::from(p.read()) << ((8 - first) as u32)) & 0xff;
    p = p.wrapping_add(1);
    let mut i: i32 = 0;
    loop {
        if i >= first {
            break;
        }
        if window & 0x80 != 0 {
            return count;
        }
        window = (window & 0x7f) << 1;
        count = count.wrapping_add(1);
        i += 1;
    }

    // Whole bytes: probe at each boundary, step over a 0x03, then
    // count the byte's leading zeros.
    let mut skip = false;
    loop {
        if emulation_prevention_probe(p, addr_of!((*reader).end).read()) {
            skip = true;
            emulation_byte_pending.write(1);
        }
        if skip {
            p = p.wrapping_add(1);
            skip = false;
        }
        let mut byte = u32::from(p.read());
        p = p.wrapping_add(1);
        let mut i: i32 = 0;
        loop {
            if byte & 0x80 != 0 {
                return count;
            }
            byte = (byte & 0x7f) << 1;
            i += 1;
            count = count.wrapping_add(1);
            if i >= 8 {
                break;
            }
        }
    }
}

/// Pointer-sized word index of the bit-position word: byte +0x04 on
/// the 32-bit target, byte +0x08 on a 64-bit host. This is the house
/// word-index model: byte-exact on target while keeping the position
/// disjoint from the host's 8-byte data pointer.
const STREAM_BIT_POS_WORD: usize = 1;

/// bitstream_msb_fetch — original: `FUN_080efa38` @ 0x080efa38
/// (152 bytes, all code — no literal pool, no calls; a
/// `str lr,[sp,#-0x4]!` prologue and three `ldr pc,[sp],#0x4` exits:
/// the in-byte fast path, the whole-byte loop's zero-remaining exit,
/// and the partial tail. 4 `bl` call sites: 0x0807d730 and
/// 0x0807d754 in the start-code scan loop @ 0x0807d724 (counts 0x20
/// and 0x18), 0x080f0d10 (count 0x20), and 0x080ebbec inside
/// [`bitstream_read_advance`]. Ghidra treats the two `ldr pc,[sp],#0x4`
/// returns as unrecovered jump tables and loses the r0 result, but all
/// callers consume the returned bits.)
///
/// Returns the `bit_count` bits MSB-first from the +0x00 buffer at the
/// +0x04 bit position — bit `i` of the result is bit
/// `7 - ((pos + i) & 7)` of byte `(pos + i) >> 3` — WITHOUT moving
/// the position; [`bitstream_read_advance`] or the scan loop's own
/// `ldr`/`add`/`str` pays for the advance.
///
/// The byte index is an arithmetic shift (`asr #0x3`), so rewound
/// (negative) positions stay correct, and `pos & 7` falls out of a
/// `bic`/`sub` pair — the double `rsb r12,r12,#0x8` is an ADS identity
/// leaving `r12 = pos & 7`. The `bit_count` compares are signed
/// (`cmp r1,r3`/`movle` fast path, `cmp r1,#0x8`/`movge` loop): an
/// in-byte count returns `((first << (pos & 7)) & 0xff) >> (8 - count)`;
/// otherwise whole bytes shift into the accumulator eight at a time and
/// the partial tail takes the next byte's high `remaining` bits.
///
/// Deviations: the stream words use pointer-sized word indexing
/// (+0x00/+0x04 byte-exact on the 32-bit target, disjoint slots on a
/// 64-bit host — the `pfr_face_done` house model). Rust shifts also
/// differ from ARM register shifts for counts outside 0..=32: retail
/// uses the low eight shift-count bits and yields zero for 32..=255,
/// whereas a debug Rust build rejects an out-of-range shift. Every
/// retail call site passes 1, 2, 5, 8, 0x18, or 0x20.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bitstream_msb_fetch(stream: *mut u8, bit_count: u32) -> u32 {
    let stream_words = stream.cast::<*const u8>();
    let data = stream_words.read();
    let bit_pos = stream_words
        .add(STREAM_BIT_POS_WORD)
        .cast::<i32>()
        .read();
    let in_byte = (bit_pos & 7) as u32;
    let available = 8 - in_byte as i32;
    let first = u32::from(data.offset((bit_pos >> 3) as isize).read());
    let count = bit_count as i32;
    let shifted = (first << in_byte) & 0xff;

    if count <= available {
        return shifted >> (8 - count);
    }

    let mut value = shifted >> in_byte;
    let mut next_byte = data.offset((bit_pos >> 3) as isize + 1);
    let mut remaining = count - available;
    loop {
        if remaining == 0 {
            return value;
        }
        if remaining >= 8 {
            value = (value << 8) | u32::from(next_byte.read());
            next_byte = next_byte.add(1);
            remaining -= 8;
        } else {
            return (value << remaining)
                | (u32::from(next_byte.read()) >> (8 - remaining));
        }
    }
}

/// bitstream_read_advance — original: `FUN_080ebbe0` @ 0x080ebbe0
/// (32 bytes, all code — no literal pool; 64 `bl` call sites, all in
/// the video header parser cluster 0x0807d7xx..0x080f1xxx around the
/// start-code matchers at 0x080ed0e8/0x080f0cec; source:
/// `ipod-decomp/decomp/c/008/080ebbe0_FUN_080ebbe0.c`).
///
/// The read-and-advance primitive of the MPEG-style video header
/// parser (32-bit start codes 0x000001B5/B3/B2): returns the
/// `bit_count` bits [`bitstream_msb_fetch`] @ 0x080efa38 reads
/// MSB-first from the +0x00 buffer at the +0x04 bit position, then
/// advances +0x04 by `bit_count`. The complete retail body is
/// eight instructions: `stmdb sp!,{r4,r5,lr}; mov r5,r1; mov r4,r0;
/// bl 0x080efa38; ldr r1,[r4,#0x4]; add r1,r1,r5; str r1,[r4,#0x4];
/// ldmia sp!,{r4,r5,pc}`.
///
/// The stream object is the two-word `{data @ +0x00, bit_pos @ +0x04}`
/// pair whose initializer is `object_value_set_flags_clear` @
/// 0x08085344 and whose byte-alignment predicate is
/// `object_low_flags_clear` @ 0x0808539c (both ported in
/// cxx/object_flags.rs); it shares its layout prefix with
/// [`RbspBitReader`], but this function touches only +0x04 — the
/// fetch performs no bounds check and the advance is a plain wrapping
/// `add` with no end test, so a read can walk the position past the
/// buffer and nothing here reports it. The `ldr r1,[r4,#0x4]` FOLLOWS
/// the `bl`, so the advance starts from whatever position the fetch
/// left behind (the retail fetch never moves it, but the ordering is
/// observable). Callers pass small positive counts (1, 2, 5, 8, 0x20
/// across the 64 sites); Ghidra types the count `int` and the fetch's
/// compares are signed, but this body is a sign-agnostic `add`, so
/// the port keeps the `u32` of the house `BitstreamReadAdvance`
/// signature (cxx/object_flags.rs) and wraps on overflow like the
/// original's `add`.
///
/// Deviations: none in the body. The fetch is now ported in this module
/// and called directly, retiring the `BITSTREAM_MSB_FETCH` seam under the
/// house convention that a ported callee takes a direct call (as
/// `f32_to_fixed16_sat` does for its ported helpers). The position word
/// uses the shared pointer-sized word-index model, byte-exact at +0x04
/// on the 32-bit target and disjoint from the host pointer word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bitstream_read_advance(stream: *mut u8, bit_count: u32) -> u32 {
    let bits = bitstream_msb_fetch(stream, bit_count);
    let position = stream
        .cast::<*const u8>()
        .add(STREAM_BIT_POS_WORD)
        .cast::<i32>();
    position.write(position.read().wrapping_add(bit_count as i32));
    bits
}

/// mpeg_skip_user_data_to_start_code — original: `FUN_0807d724` @
/// 0x0807d724 (76 bytes, all code — two direct calls to
/// [`bitstream_msb_fetch`]).
///
/// If the next 32 bits are the MPEG user-data start code
/// `0x0000_01B2`, consumes that code and scans one byte at a time until
/// the next 24-bit `0x000001` start-code prefix. The prefix is left
/// unread for the caller's start-code parser. Any other initial code
/// leaves the cursor untouched. The cursor has no bounds word: exactly
/// like retailOS, a malformed user-data payload without a later prefix
/// keeps scanning.
///
/// The retail body fetches the first code before its first store, then
/// stores `bit_pos + 32` on each iteration, fetches 24 bits, and adds
/// eight after each non-prefix. All additions wrap like ARM `add`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mpeg_skip_user_data_to_start_code(stream: *mut u8) {
    const MPEG_USER_DATA_START_CODE: u32 = 0x0000_01B2;
    const MPEG_START_CODE_PREFIX: u32 = 0x0000_0001;

    if bitstream_msb_fetch(stream, 32) != MPEG_USER_DATA_START_CODE {
        return;
    }

    let position = stream
        .cast::<*const u8>()
        .add(STREAM_BIT_POS_WORD)
        .cast::<i32>();
    let mut scan_position = position.read().wrapping_add(32);
    loop {
        position.write(scan_position);
        if bitstream_msb_fetch(stream, 24) == MPEG_START_CODE_PREFIX {
            return;
        }
        scan_position = position.read().wrapping_add(8);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

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

    // --- bitstream_msb_fetch / bitstream_read_advance ---

    /// An aligned stand-in for the two-word stream object: a real data
    /// pointer at +0x00 and its position at pointer-sized word 1 (+0x04
    /// on the target, +0x08 on a 64-bit host).
    #[repr(C)]
    struct ReadStream {
        data: *const u8,
        bit_pos: i32,
    }

    /// Creates a stream whose data base is entry 1, so byte index -1
    /// (a rewound position) addresses `payload[0]`.
    fn stream_at(payload: &[u8], bit_pos: i32) -> ReadStream {
        ReadStream {
            data: unsafe { payload.as_ptr().add(1) },
            bit_pos,
        }
    }

    /// Independent per-bit formulation: bit `i` of the result is bit
    /// `7 - ((pos + i) & 7)` of byte `(pos + i) >> 3`. `payload[0]` is
    /// byte -1 relative to the stream's data pointer.
    fn reference_fetch(payload: &[u8], bit_pos: i32, bit_count: u32) -> u32 {
        let mut value = 0u32;
        for i in 0..bit_count as i32 {
            let position = bit_pos + i;
            let byte = payload[((position >> 3) + 1) as usize];
            value = (value << 1) | u32::from(byte >> (7 - (position & 7)) & 1);
        }
        value
    }

    const FETCH_PAYLOAD: [u8; 12] = [
        0b1011_0011,
        0b0100_1101,
        0xA5,
        0xFF,
        0x00,
        0x5A,
        0b1100_0011,
        0x69,
        0x96,
        0x0F,
        0xF0,
        0b0101_1010,
    ];

    /// A concrete four-byte fetch crosses the whole-byte loop and takes
    /// its zero-remaining exit, the path start-code scanners use.
    #[test]
    fn fetches_a_32_bit_start_code() {
        let bytes = [0xEE, 0x00, 0x00, 0x01, 0xB5];
        let mut stream = stream_at(&bytes, 0);
        assert_eq!(
            unsafe { bitstream_msb_fetch((&mut stream as *mut ReadStream).cast(), 32) },
            0x0000_01B5
        );
        assert_eq!(stream.bit_pos, 0, "the fetch does not advance");
    }

    /// Promotes the former seam's 210-case transcription check to the
    /// exported port: all in-byte alignments, fast/whole-byte/partial
    /// tails, and rewound negative positions agree with an independent
    /// per-bit model.
    #[test]
    fn fetch_matches_reference_over_positions_counts_and_alignments() {
        for start in [-8i32, -4, -1, 0, 1, 2, 3, 6, 7, 8, 9, 13, 16, 24] {
            for count in [0u32, 1, 2, 3, 4, 5, 7, 8, 9, 12, 16, 17, 24, 31, 32] {
                let mut stream = stream_at(&FETCH_PAYLOAD, start);
                let got = unsafe {
                    bitstream_msb_fetch((&mut stream as *mut ReadStream).cast(), count)
                };
                assert_eq!(
                    got,
                    reference_fetch(&FETCH_PAYLOAD, start, count),
                    "pos {start} count {count}"
                );
                assert_eq!(stream.bit_pos, start, "pos {start} count {count}");
            }
        }
    }

    #[test]
    fn zero_bit_fetch_returns_zero_without_moving_the_cursor() {
        let mut stream = stream_at(&FETCH_PAYLOAD, 5);
        assert_eq!(
            unsafe { bitstream_msb_fetch((&mut stream as *mut ReadStream).cast(), 0) },
            0
        );
        assert_eq!(stream.bit_pos, 5);
    }

    /// The direct `bl 0x080efa38` equivalent returns the fetched bits
    /// then reloads and advances the stream position, end to end.
    #[test]
    fn read_advance_matches_reference_and_commits_the_count() {
        for start in [-8i32, -4, -1, 0, 1, 2, 3, 6, 7, 8, 9, 13, 16, 24] {
            for count in [0u32, 1, 2, 3, 4, 5, 7, 8, 9, 12, 16, 17, 24, 31, 32] {
                let mut stream = stream_at(&FETCH_PAYLOAD, start);
                let got = unsafe {
                    bitstream_read_advance((&mut stream as *mut ReadStream).cast(), count)
                };
                assert_eq!(
                    got,
                    reference_fetch(&FETCH_PAYLOAD, start, count),
                    "pos {start} count {count}"
                );
                assert_eq!(
                    stream.bit_pos,
                    start.wrapping_add(count as i32),
                    "pos {start} count {count}"
                );
            }
        }
    }

    #[test]
    fn user_data_scan_leaves_non_user_start_codes_untouched() {
        let bytes = [0xCC, 0x00, 0x00, 0x01, 0xB3, 0x00, 0x00, 0x01, 0xB2];
        let mut stream = stream_at(&bytes, 0);
        unsafe { mpeg_skip_user_data_to_start_code((&mut stream as *mut ReadStream).cast()) };
        assert_eq!(stream.bit_pos, 0);
    }

    /// The loop commits the first user-data code, then takes every
    /// non-prefix byte before leaving the next start-code prefix unread.
    #[test]
    fn user_data_scan_stops_at_the_next_start_code_prefix() {
        for user_data_bytes in 0..=7i32 {
            let mut bytes = [0xA5; 17];
            bytes[0] = 0xCC;
            bytes[1..5].copy_from_slice(&[0x00, 0x00, 0x01, 0xB2]);
            let prefix_offset = 5 + user_data_bytes as usize;
            bytes[prefix_offset..prefix_offset + 5]
                .copy_from_slice(&[0x00, 0x00, 0x01, 0xB3, 0x00]);
            let mut stream = stream_at(&bytes, 0);

            unsafe { mpeg_skip_user_data_to_start_code((&mut stream as *mut ReadStream).cast()) };

            let prefix_position = 32 + user_data_bytes * 8;
            assert_eq!(stream.bit_pos, prefix_position, "payload bytes: {user_data_bytes}");
            assert_eq!(
                unsafe { bitstream_msb_fetch((&mut stream as *mut ReadStream).cast(), 32) },
                0x0000_01B3,
                "the next parser still owns its start code"
            );
        }
    }

    // --- h264_bitstream_count_leading_zeros ---

    /// A cursor over `buf[2..2 + len]`: the two leading bytes give the
    /// probe's unconditional `p[-2]`/`p[-1]` reads somewhere sound to
    /// land (in the firmware they are the start code's `00 00`), and
    /// the allocation extends past `end` so the unchecked reads the
    /// original performs at/past `end` stay inside readable memory.
    fn clz_cursor(buf: &[u8], len: usize, bit_pos: i32) -> RbspBitReader {
        RbspBitReader {
            data: unsafe { buf.as_ptr().add(2) },
            bit_pos,
            end: unsafe { buf.as_ptr().add(2 + len) },
        }
    }

    /// Independent model: walks bits MSB-first from the position,
    /// lazily removing emulation-prevention bytes by the H.264 rule —
    /// a `0x03` that directly follows two raw zero bytes and is itself
    /// followed by a readable byte `<= 3` is not RBSP. `len` is the
    /// payload length (the cursor covers `buf[2..2 + len]`); the
    /// probe's `p + 1 < end` bounds check is its only use, plain reads
    /// ignore it, like the original.
    /// Returns the leading-zero count and the emulation flag.
    fn reference_clz(buf: &[u8], len: usize, bit_pos: i32) -> (u32, bool) {
        let end: i32 = 2 + len as i32;
        let mut index: i32 = 2 + (bit_pos >> 3);
        let mut bit: i32 = bit_pos - (bit_pos & !7);
        let mut count: u32 = 0;
        let mut flag = false;
        // An aligned start probes its first byte; a misaligned one
        // begins mid-byte and cannot start on an emulation byte.
        let mut probe = bit == 0;
        loop {
            if probe
                && index + 1 < end
                && buf[(index - 2) as usize] == 0
                && buf[(index - 1) as usize] == 0
                && buf[index as usize] == 0x03
                && buf[(index + 1) as usize] <= 3
            {
                index += 1;
                flag = true;
            }
            probe = true;
            let byte = buf[index as usize];
            index += 1;
            for position in bit..8 {
                if byte & (0x80 >> position) != 0 {
                    return (count, flag);
                }
                count += 1;
            }
            bit = 0;
        }
    }

    /// Runs the port over `buf[2..2 + len]` at `bit_pos` and returns
    /// the count and the flag.
    fn run_clz(buf: &[u8], len: usize, bit_pos: i32) -> (u32, u8) {
        let mut r = clz_cursor(buf, len, bit_pos);
        let mut flag = 0u8;
        let count = unsafe { h264_bitstream_count_leading_zeros(&mut r, &mut flag) };
        assert_eq!(r.bit_pos, bit_pos, "the cursor never moves");
        (count, flag)
    }

    /// Hand-computed prefix lengths, including counts that span byte
    /// boundaries and every first-bit position within a byte. The
    /// `[0x00, 0x01]` padding mimics the start-code tail, so no
    /// emulation probe can hit at these positions.
    #[test]
    fn clz_counts_known_prefixes_across_byte_boundaries() {
        // (payload before the 0xFF terminator, bit_pos, expected count)
        let cases: &[(&[u8], i32, u32)] = &[
            (&[0x80], 0, 0),                    // leading 1: empty prefix
            (&[0x40], 0, 1),
            (&[0x01], 0, 7),                    // full first byte minus one
            (&[0x00, 0x80], 0, 8),              // exactly one zero byte
            (&[0x00, 0x40], 0, 9),
            (&[0x07], 0, 5),
            (&[0x0F], 2, 2),                    // misaligned: bits 2..8 are 001111
            (&[0x08], 4, 0),                    // bit 4 is the 1
            (&[0x00, 0x01], 3, 12),             // 5 + 7, spanning the boundary
            (&[0x00, 0x00, 0x00, 0x00, 0x10], 0, 35), // 32 + 3, four zero bytes
        ];
        for &(payload, bit_pos, expected) in cases {
            let mut buf = std::vec![0x00, 0x01];
            buf.extend_from_slice(payload);
            buf.push(0xFF); // terminator: any overlong walk still stops
            let len = buf.len() - 2;
            let (count, flag) = run_clz(&buf, len, bit_pos);
            assert_eq!(count, expected, "payload {payload:02x?} pos {bit_pos}");
            assert_eq!(flag, 0, "no emulation bytes here");
            assert_eq!(
                reference_clz(&buf, len, bit_pos),
                (expected, false),
                "reference agrees, payload {payload:02x?} pos {bit_pos}"
            );
        }
    }

    /// Every alignment 0..=7 (plus a few larger offsets) over three
    /// payloads agrees with the bit-walking reference.
    #[test]
    fn clz_matches_reference_at_every_alignment() {
        let payloads: &[&[u8]] = &[
            &[0b0000_0101, 0b1001_0110, 0xFF],
            &[0x00, 0xA5, 0xFF],
            &[0xFF],
        ];
        for payload in payloads {
            let mut buf = std::vec![0x00, 0x01];
            buf.extend_from_slice(payload);
            let len = buf.len() - 2;
            // Stay inside the payload: a position past the last byte's
            // last bit would walk the reference off the allocation.
            let last_bit = (len as i32 * 8 - 1).min(9);
            for bit_pos in 0..=last_bit {
                let (count, flag) = run_clz(&buf, len, bit_pos);
                let (want_count, want_flag) = reference_clz(&buf, len, bit_pos);
                assert_eq!(
                    (count, flag),
                    (want_count, want_flag as u8),
                    "payload {payload:02x?} pos {bit_pos}"
                );
            }
        }
    }

    /// `00 00 03 01` at an aligned start: the `0x03` is skipped, the
    /// flag is set, and the count covers the RBSP bits only — 16 zeros
    /// plus the 7 of `0x01`, not the 6 of a data `0x03`.
    #[test]
    fn clz_steps_over_emulation_byte_and_sets_the_flag() {
        let buf = [0x00, 0x01, 0x00, 0x00, 0x03, 0x01, 0xFF];
        let len = 5;
        let (count, flag) = run_clz(&buf, len, 0);
        assert_eq!(count, 23);
        assert_eq!(flag, 1);
        assert_eq!(reference_clz(&buf, len, 0), (23, true));
    }

    /// A misaligned start never probes its first byte; the emulation
    /// skip happens at the next byte boundary instead. 4 zeros of the
    /// partial byte, 8 of the next, the `0x03` skipped, 7 of `0x01`.
    #[test]
    fn clz_probes_only_at_byte_boundaries() {
        let buf = [0x00, 0x01, 0x00, 0x00, 0x03, 0x01, 0xFF];
        let len = 5;
        let (count, flag) = run_clz(&buf, len, 4);
        assert_eq!(count, 19);
        assert_eq!(flag, 1);
        assert_eq!(reference_clz(&buf, len, 4), (19, true));
    }

    /// Two emulation sequences in one walk: the byte after a skipped
    /// `0x03` is data, never re-probed, so the `0x00` following the
    /// first `0x03` counts, and the second `00 00 03` still skips.
    #[test]
    fn clz_multiple_emulation_bytes_each_set_the_flag() {
        let buf = [0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x02, 0xFF];
        let len = 8;
        let (count, flag) = run_clz(&buf, len, 0);
        // 8 + 8 (two zero bytes) + skip + 8 + 8 (two more) + skip +
        // 6 zeros of 0x02 = 38.
        assert_eq!(count, 38);
        assert_eq!(flag, 1);
        assert_eq!(reference_clz(&buf, len, 0), (38, true));
    }

    /// The probe's only bounds check is `p + 1 < end`: a `00 00 03`
    /// whose `0x03` is the LAST readable byte is not skipped — the
    /// byte after it does not exist — and the `0x03` counts as data
    /// (6 leading zeros).
    #[test]
    fn clz_emulation_byte_at_end_of_buffer_is_data() {
        let buf = [0x00, 0x01, 0x00, 0x00, 0x03, 0xFF];
        let len = 3; // end = buf + 5: the 0x03 is the last readable byte
        let (count, flag) = run_clz(&buf, len, 0);
        assert_eq!(count, 8 + 8 + 6);
        assert_eq!(flag, 0);
        assert_eq!(reference_clz(&buf, len, 0), (22, false));
    }

    /// A `00 00 03` followed by a byte above `0x03` is not an
    /// emulation-prevention sequence: the `0x03` counts as data.
    #[test]
    fn clz_emulation_byte_followed_above_three_is_data() {
        let buf = [0x00, 0x01, 0x00, 0x00, 0x03, 0x04, 0xFF];
        let len = 5;
        let (count, flag) = run_clz(&buf, len, 0);
        assert_eq!(count, 8 + 8 + 6);
        assert_eq!(flag, 0);
        assert_eq!(reference_clz(&buf, len, 0), (22, false));
    }

    /// Byte READS are unchecked — only the probe bounds itself against
    /// `end`. With `end` after one zero byte, the walk reads the
    /// (allocated) byte at `end` and stops at its leading 1, exactly
    /// like the original running off the NAL into flat DRAM.
    #[test]
    fn clz_reads_past_end_are_unchecked() {
        let buf = [0x00, 0x01, 0x00, 0x80];
        let len = 1; // end = buf + 3: only buf[2] is readable
        let (count, flag) = run_clz(&buf, len, 0);
        assert_eq!(count, 8);
        assert_eq!(flag, 0);
        assert_eq!(reference_clz(&buf, len, 0), (8, false));
    }

    /// The flag is cleared at entry even when no probe ever fires, so
    /// one flag variable serves a whole parse function.
    #[test]
    fn clz_clears_the_flag_on_entry() {
        let buf = [0x00, 0x01, 0xC0, 0xFF];
        let mut r = clz_cursor(&buf, 2, 0);
        let mut flag = 1u8;
        let count = unsafe { h264_bitstream_count_leading_zeros(&mut r, &mut flag) };
        assert_eq!(count, 0);
        assert_eq!(flag, 0);
    }

    /// Rewound positions: `bit_pos asr 3` lands in the byte BEFORE
    /// `data` (the padding stands in for it) and the bit-in-byte index
    /// is the non-negative `pos - (pos & !7)`, so -1 counts from bit 7
    /// of that byte, not from a wrapped-around index.
    #[test]
    fn clz_negative_positions_use_the_arithmetic_shift() {
        let buf = [0x00, 0x02, 0xFF];
        let len = 1;
        let (count, flag) = run_clz(&buf, len, -1);
        // bit 7 of 0x02 is 0 (count 1), then 0xFF stops the walk.
        assert_eq!(count, 1);
        assert_eq!(flag, 0);
        assert_eq!(reference_clz(&buf, len, -1), (1, false));
    }

    /// Deterministic pseudo-random streams with emulation-prevention
    /// sequences spliced in, swept over every alignment of the first
    /// three bytes and compared against the bit-walking reference.
    #[test]
    fn clz_matches_reference_over_seeded_streams_with_emulation() {
        let mut state: u32 = 0x1234_5678;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        };
        for _case in 0..40 {
            let mut buf = std::vec![0x00, 0x01];
            for _ in 0..24 {
                buf.push(next());
            }
            // Splice `00 00 03 0x` sequences at three spots; the
            // trailing byte is drawn from 0..=7 so both the skip
            // (<= 3) and the data (> 3) outcomes occur.
            for offset in [4usize, 11, 18] {
                buf[offset] = 0x00;
                buf[offset + 1] = 0x00;
                buf[offset + 2] = 0x03;
                buf[offset + 3] = next() & 0x07;
            }
            buf.push(0xFF); // terminator
            let len = buf.len() - 2;
            for bit_pos in 0..24i32 {
                let (count, flag) = run_clz(&buf, len, bit_pos);
                let (want_count, want_flag) = reference_clz(&buf, len, bit_pos);
                assert_eq!(
                    (count, flag),
                    (want_count, want_flag as u8),
                    "buf {buf:02x?} pos {bit_pos}"
                );
            }
        }
    }
}
