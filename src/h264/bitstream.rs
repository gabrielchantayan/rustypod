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
//! word: it fetches `bit_count` bits MSB-first through the
//! [`BITSTREAM_MSB_FETCH`] seam (`FUN_080efa38`, unported) and commits
//! them with a plain `bit_pos += bit_count`, bounds-check free.

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

/// MSB-first bit fetch `FUN_080efa38` (unported): 152 bytes @
/// 0x080efa38, all code — no literal pool, no calls; a
/// `str lr,[sp,#-0x4]!` prologue and three `ldr pc,[sp],#0x4` exits
/// (in-byte fast path, whole-byte loop tail, zero-remaining tail).
/// Returns the `bit_count` bits MSB-first from the +0x00 buffer at
/// the +0x04 bit position — bit `i` of the result is bit
/// `7 - ((pos + i) & 7)` of byte `(pos + i) >> 3` — WITHOUT moving
/// the position; [`bitstream_read_advance`] pays for the advance.
/// The byte index is an arithmetic shift (`asr #0x3`), so rewound
/// (negative) positions stay correct, and the `bit_count` compares
/// are signed (`cmp`/`movle` fast path, `movge` loop). The double
/// `rsb r12,r12,#0x8` is an ADS identity leaving `r12 = pos & 7`.
pub type BitstreamMsbFetch = unsafe extern "C" fn(stream: *mut u8, bit_count: u32) -> u32;

/// Spins forever: [`bitstream_read_advance`] must not run before
/// target integration installs the retailOS `FUN_080efa38`.
unsafe extern "C" fn missing_bitstream_msb_fetch(_stream: *mut u8, _bit_count: u32) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// RetailOS dependency of [`bitstream_read_advance`]. Target
/// integration must install the real `FUN_080efa38`; focused host
/// tests replace it with a scripted seam.
pub static mut BITSTREAM_MSB_FETCH: BitstreamMsbFetch = missing_bitstream_msb_fetch;

#[inline(always)]
unsafe fn bitstream_msb_fetch() -> BitstreamMsbFetch {
    core::ptr::read_volatile(addr_of!(BITSTREAM_MSB_FETCH))
}

/// bitstream_read_advance — original: `FUN_080ebbe0` @ 0x080ebbe0
/// (32 bytes, all code — no literal pool; 64 `bl` call sites, all in
/// the video header parser cluster 0x0807d7xx..0x080f1xxx around the
/// start-code matchers at 0x080ed0e8/0x080f0cec; source:
/// `ipod-decomp/decomp/c/008/080ebbe0_FUN_080ebbe0.c`).
///
/// The read-and-advance primitive of the MPEG-style video header
/// parser (32-bit start codes 0x000001B5/B3/B2): returns the
/// `bit_count` bits the [`BITSTREAM_MSB_FETCH`] fetch (`FUN_080efa38`)
/// reads MSB-first from the +0x00 buffer at the +0x04 bit position,
/// then advances +0x04 by `bit_count`. The complete retail body is
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
/// Deviations: the unported fetch rides the [`BITSTREAM_MSB_FETCH`]
/// seam (house pattern — see `OBJECT_FLAGS_FETCH_INCREMENT_LOCK` in
/// cxx/object_flags.rs) instead of a direct `bl`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bitstream_read_advance(stream: *mut u8, bit_count: u32) -> u32 {
    let bits = bitstream_msb_fetch()(stream, bit_count);
    let position = stream.add(4).cast::<i32>();
    position.write(position.read().wrapping_add(bit_count as i32));
    bits
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

    // --- bitstream_read_advance ---

    extern crate std;
    use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};

    /// Serializes the tests that swap the MSB-fetch seam and the
    /// scripted stream data.
    static READ_ADVANCE_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    /// Scripted payload the host fetch seams read. Byte index -1 maps
    /// to entry 0 (see [`fetch_data_base`]), so rewound (negative)
    /// bit positions are covered too.
    static mut READ_DATA: [u8; 12] = [0; 12];

    /// One recorded fetch call: the stream pointer and the requested
    /// bit count.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FetchCall {
        stream: usize,
        bit_count: u32,
    }

    const NO_FETCH: FetchCall = FetchCall { stream: 0, bit_count: 0 };

    static mut FETCH_CALLS: [FetchCall; 8] = [NO_FETCH; 8];
    static mut FETCH_COUNT: usize = 0;
    static mut FETCH_RESULT: u32 = 0;

    fn record_fetch(stream: *mut u8, bit_count: u32) {
        unsafe {
            let count = FETCH_COUNT;
            assert!(count < 8, "MSB-fetch seam called more than 8 times");
            FETCH_CALLS[count] = FetchCall { stream: stream as usize, bit_count };
            FETCH_COUNT = count + 1;
        }
    }

    /// A seam that only records the call and returns the scripted
    /// result: isolates the ported body's forwarding and advance.
    unsafe extern "C" fn recording_msb_fetch(stream: *mut u8, bit_count: u32) -> u32 {
        record_fetch(stream, bit_count);
        FETCH_RESULT
    }

    /// Byte-address base for the scripted payload: entry 1, so byte
    /// index -1 (a rewound position) lands on entry 0.
    unsafe fn fetch_data_base() -> *const u8 {
        addr_of!(READ_DATA).cast::<u8>().add(1)
    }

    /// A faithful host stand-in for `FUN_080efa38`, transcribed from
    /// the disassembly: signed count compares, arithmetic-shift byte
    /// index, the in-byte fast path, the whole-byte loop and the
    /// partial tail. Reads the scripted payload and records the call.
    /// Only bit counts 0..=32 are exercised: a larger signed count
    /// would take the fast path with an out-of-range shift, which the
    /// retail `lsr` by register survives but Rust does not.
    unsafe extern "C" fn real_bitstream_msb_fetch(stream: *mut u8, bit_count: u32) -> u32 {
        let n = bit_count as i32;
        let bit_pos = stream.add(4).cast::<i32>().read_volatile();
        let k = (bit_pos & 7) as u32;
        let avail = 8 - k as i32;
        let first = u32::from(fetch_data_base().offset((bit_pos >> 3) as isize).read_volatile());
        let value = if n <= avail {
            ((first << k) & 0xff) >> (8 - n)
        } else {
            let mut acc = ((first << k) & 0xff) >> k;
            let mut remaining = n - avail;
            let mut ptr = fetch_data_base().offset((bit_pos >> 3) as isize + 1);
            while remaining != 0 {
                if remaining >= 8 {
                    acc = (acc << 8) | u32::from(ptr.read_volatile());
                    ptr = ptr.add(1);
                    remaining -= 8;
                } else {
                    acc = (acc << remaining) | u32::from(ptr.read_volatile() >> (8 - remaining));
                    break;
                }
            }
            acc
        };
        record_fetch(stream, bit_count);
        value
    }

    /// An aligned stand-in for the two-word stream object: +0x00
    /// unused by the host seams (retail's fetch would read the data
    /// pointer here), +0x04 the bit position.
    #[repr(C, align(4))]
    struct ReadStream {
        words: [u32; 2],
    }

    /// Installs the fetch seam and seeds the scripted payload and
    /// result, returning the guard serializing the swap.
    fn install_fetch_seam(
        data: [u8; 12],
        fetch: BitstreamMsbFetch,
        result: u32,
    ) -> StdMutexGuard<'static, ()> {
        let guard = READ_ADVANCE_TEST_LOCK.lock().unwrap();
        unsafe {
            READ_DATA = data;
            FETCH_COUNT = 0;
            FETCH_RESULT = result;
            BITSTREAM_MSB_FETCH = fetch;
        }
        guard
    }

    fn uninstall_fetch_seam() {
        unsafe { BITSTREAM_MSB_FETCH = missing_bitstream_msb_fetch };
    }

    fn fetch_calls() -> (usize, [FetchCall; 8]) {
        unsafe { (FETCH_COUNT, FETCH_CALLS) }
    }

    /// Independent formulation of the fetch: bit `i` of the result is
    /// bit `7 - ((pos + i) & 7)` of byte `(pos + i) >> 3` of the
    /// scripted payload (byte -1 = entry 0).
    fn reference_fetch(bit_pos: i32, bit_count: u32) -> u32 {
        let mut value = 0u32;
        for i in 0..bit_count as i32 {
            let p = bit_pos + i;
            let byte = unsafe { READ_DATA[((p >> 3) + 1) as usize] };
            value = (value << 1) | u32::from(byte >> (7 - (p & 7)) & 1);
        }
        value
    }

    /// The fetch result is returned unchanged and the arguments are
    /// forwarded verbatim — the retail `bl 0x080efa38` passes r0/r1
    /// through untouched.
    #[test]
    fn forwards_stream_and_count_and_returns_the_fetch_result() {
        let _guard = install_fetch_seam([0; 12], recording_msb_fetch, 0xA5A5_005A);
        let mut stream = ReadStream { words: [0, 24] };
        let stream_ptr = stream.words.as_mut_ptr().cast::<u8>();
        let got = unsafe { bitstream_read_advance(stream_ptr, 0x20) };
        assert_eq!(got, 0xA5A5_005A);
        let (count, calls) = fetch_calls();
        assert_eq!(count, 1);
        assert_eq!(calls[0], FetchCall { stream: stream_ptr as usize, bit_count: 0x20 });
        uninstall_fetch_seam();
    }

    /// The position word advances by exactly `bit_count` — the retail
    /// `ldr r1,[r4,#0x4]; add r1,r1,r5; str r1,[r4,#0x4]`.
    #[test]
    fn advances_the_position_by_the_bit_count() {
        for (start, n) in [(0u32, 1u32), (3, 5), (7, 1), (8, 8), (24, 32), (100, 0)] {
            let _guard = install_fetch_seam([0; 12], recording_msb_fetch, 0);
            let mut stream = ReadStream { words: [0, start] };
            unsafe { bitstream_read_advance(stream.words.as_mut_ptr().cast(), n) };
            assert_eq!(stream.words[1], start.wrapping_add(n), "{start} + {n}");
            let (count, calls) = fetch_calls();
            assert_eq!(count, 1, "the fetch runs even for a zero count");
            assert_eq!(calls[0].bit_count, n);
            uninstall_fetch_seam();
        }
    }

    /// The position is read back AFTER the fetch returns — the retail
    /// `ldr r1,[r4,#0x4]` follows the `bl` — so a fetch that moved
    /// the position advances from the value it left behind.
    #[test]
    fn reads_the_position_back_after_the_fetch() {
        unsafe extern "C" fn position_shifting_fetch(stream: *mut u8, _n: u32) -> u32 {
            stream.add(4).cast::<u32>().write_volatile(100);
            7
        }
        let _guard = install_fetch_seam([0; 12], position_shifting_fetch, 0);
        let mut stream = ReadStream { words: [0, 3] };
        let got = unsafe { bitstream_read_advance(stream.words.as_mut_ptr().cast(), 5) };
        assert_eq!(got, 7);
        assert_eq!(stream.words[1], 105);
        uninstall_fetch_seam();
    }

    /// Overflow wraps like the original's `add`, and does not panic.
    #[test]
    fn position_add_wraps_like_the_original() {
        let _guard = install_fetch_seam([0; 12], recording_msb_fetch, 0);
        let mut stream = ReadStream { words: [0, (i32::MAX - 1) as u32] };
        unsafe { bitstream_read_advance(stream.words.as_mut_ptr().cast(), 4) };
        assert_eq!(stream.words[1] as i32, i32::MAX.wrapping_add(3));
        uninstall_fetch_seam();
    }

    /// End to end with the faithful `FUN_080efa38` transcription: the
    /// returned bits match an independent per-bit formulation over
    /// positions (including rewound negative ones), counts 0..=32 and
    /// every in-byte alignment, and each call advances the position
    /// by the count.
    #[test]
    fn matches_reference_over_positions_counts_and_alignments() {
        let data: [u8; 12] =
            [0b1011_0011, 0b0100_1101, 0xA5, 0xFF, 0x00, 0x5A, 0b1100_0011, 0x69, 0x96, 0x0F, 0xF0, 0b0101_1010];
        for start in [-8i32, -4, -1, 0, 1, 2, 3, 6, 7, 8, 9, 13, 16, 24] {
            for n in [0u32, 1, 2, 3, 4, 5, 7, 8, 9, 12, 16, 17, 24, 31, 32] {
                let _guard = install_fetch_seam(data, real_bitstream_msb_fetch, 0);
                let mut stream = ReadStream { words: [0, start as u32] };
                let got = unsafe { bitstream_read_advance(stream.words.as_mut_ptr().cast(), n) };
                assert_eq!(got, reference_fetch(start, n), "pos {start} n {n}");
                assert_eq!(stream.words[1] as i32, start.wrapping_add(n as i32), "pos {start} n {n}");
                let (count, _) = fetch_calls();
                assert_eq!(count, 1);
                uninstall_fetch_seam();
            }
        }
    }
}
