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
}
