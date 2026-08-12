//! `cg_rbsp_read_bits` — original: `FUN_082d0630` @ 0x082d0630
//! (292 bytes, all code — no literal pool; **55 `bl` call sites**,
//! counted in osos.asm: the H.264 decoder's syntax parsers at
//! 0x0836xxxx plus the Exp-Golomb reader `cg_exp_golomb_ue_read`
//! @ 0x082c5df0, which is its in-module neighbour's seam slot).
//!
//! The H.264 `u(n)` fixed-width bit reader over the decoder's shared
//! RBSP cursor ([`RbspBitReader`]): returns the next `count` bits
//! (1..=32; anything else yields 0) MSB-first WITHOUT moving the
//! cursor — the caller commits the bits afterwards through
//! `h264_bitstream_advance` @ 0x082b3258 (that is the trailing
//! `FUN_082b3258(param_1, local_10, &local_1c)` at every Exp-Golomb
//! call site). It lives at 0x082d0630, inside the Vincent JIT's
//! address block, but it is pure decoder machinery — the three words
//! it touches are the `{data, bit_pos, end}` cursor documented in
//! `crate::h264::bitstream`. It is ported under the `cg_*` roof
//! because that is the cluster the address falls in.
//!
//! Algorithm, exactly as the 73-instruction body has it:
//!
//! ```text
//! *flag = 0                                   // strb r4,[r2] FIRST,
//! if count > 32 || count < 1: return 0        //   even on refusal
//! p = data + (bit_pos >> 3)                   // arithmetic shift
//! first = 8 - (bit_pos & 7)                   // bits left in *p
//! if first == 8 && probe(p, end):             // read starts on a
//!     p += 1; *flag = 1                       //   00 00 03 byte: skip
//! if count <= first:                          // whole read in *p
//!     return (*p << (8-first) & 0xff) >> (8-count)
//! value = low `first` bits of *p
//! remaining = count - first
//! pending = probe(p + 1, end)                 // next byte an EP 0x03?
//! if pending: *flag = 1
//! while remaining >= 8:                       // whole-byte loop
//!     if pending: p_next += 1; pending = false
//!     byte = *p_next; p_next += 1
//!     pending = probe(p_next, end)
//!     value = value << 8 | byte; remaining -= 8
//!     if pending: *flag = 1
//! if remaining > 0:                           // 1..7-bit tail
//!     if pending: p_next += 1
//!     return value << remaining | *p_next >> (8 - remaining)
//! return value
//! ```
//!
//! The emulation-prevention dance deserves a careful read because the
//! probe is ALWAYS called on the byte AFTER the one just consumed
//! (`ldrb r10,[r3],#0x1` post-increments, then `bl 0x082c319c`), and
//! its verdict is deferred in a "pending skip" register (r4): the
//! NEXT byte fetch skips one more byte first when it is set. Only the
//! byte-ALIGNED entry probes the very first byte (a mid-byte cursor
//! can never sit on an EP byte — the caller's advance already paid
//! for it). The probe itself @ 0x082c319c answers "is the byte at `p`
//! the `0x03` of a `00 00 03 xx` sequence with `xx <= 3` and at least
//! one byte left before `end`?" — reads `p[-2]`, `p[-1]`, `p[0]`,
//! `p[1]`, bounds-checked only by `p + 1 < end`.
//!
//! Every probe hit also stores 1 through `flag` (`strbne r9,[r8]`):
//! the read reports that it stepped over an EP byte, and whichever
//! advance runs next pays the 8-bit surcharge — see the
//! `cg_exp_golomb_ue_read` names.yaml entry for the flag protocol.
//! The flag write on entry means even a refused `count` clears it.
//!
//! Observable bounds behavior: the read itself is NOT bounds-checked
//! against `end` — only the probe is — so an over-long `count` reads
//! past the payload into whatever follows. The single-byte path in
//! the original issues a 32-bit `ldr` at `p` (ARMv5 unaligned: the
//! containing aligned word) whose high bytes are then masked off;
//! the value depends only on `*p`.
//!
//! Deviations:
//! - The single-byte path reads one byte instead of the original's
//!   unaligned word load. The three extra bytes are shifted/masked
//!   away (`lsl (8-first)`; `and #0xff`; `lsr (8-count)`), so the
//!   returned value is identical and the port never touches bytes the
//!   result does not use.
//! - The emulation-prevention probe @ 0x082c319c is unported and sits
//!   behind the [`CG_RBSP_READ_BITS_OPS`] `read_volatile` dispatch
//!   seam (the house pattern — see `super::heap::CG_HEAP_OPS`). The
//!   default is a `missing_*` spin-loop stub, matching
//!   `super::timer_wait::CG_TIMER_WAIT_OPS`; host tests install a
//!   faithful transcription of the original.
//! - Shift amounts here are all provably in 0..8 (counts are gated to
//!   1..=32 and `first` to 1..=8), so plain Rust shifts stand in for
//!   the ARM register forms; no wrapping operators are needed.

use crate::h264::bitstream::RbspBitReader;

/// Indirect dispatch for the one unported callee (see the module
/// header). Host tests replace the whole table.
#[derive(Clone, Copy)]
pub struct CgRbspReadBitsOps {
    /// Emulation-prevention probe @ 0x082c319c: nonzero iff the byte
    /// at `p` is the `0x03` of a `00 00 03 xx` sequence with
    /// `xx <= 3` and `p + 1 < end`.
    pub emulation_probe: unsafe extern "C" fn(p: *const u8, end: *const u8) -> u32,
}

unsafe extern "C" fn missing_emulation_probe(_p: *const u8, _end: *const u8) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// The active callee binding. Unwired `missing_*` stub until the
/// probe is ported (see the module header's deviation); host tests
/// replace the table.
pub static mut CG_RBSP_READ_BITS_OPS: CgRbspReadBitsOps = CgRbspReadBitsOps {
    emulation_probe: missing_emulation_probe,
};

/// Volatile read of the ops table — without it LLVM constant-folds the
/// indirect call back to the default.
#[inline(always)]
fn cg_rbsp_read_bits_ops() -> CgRbspReadBitsOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CG_RBSP_READ_BITS_OPS)) }
}

/// cg_rbsp_read_bits — original: `FUN_082d0630` @ 0x082d0630
/// (292 bytes, 55 `bl` call sites).
///
/// Returns the next `count` bits of the cursor MSB-first, refusing
/// `count` outside 1..=32 with a 0; the cursor is NEVER advanced (the
/// caller commits through `h264_bitstream_advance`). Clears
/// `*emulation_byte_pending` on entry — before the count gate — and
/// sets it to 1 each time the read steps over an H.264
/// emulation-prevention `00 00 03` byte. Reads are not bounds-checked
/// against `end`; only the EP probe is.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_rbsp_read_bits(
    reader: *mut RbspBitReader,
    count: i32,
    emulation_byte_pending: *mut u8,
) -> u32 {
    let ops = cg_rbsp_read_bits_ops();
    *emulation_byte_pending = 0;
    if count > 0x20 || count < 1 {
        return 0;
    }
    let pos = (*reader).bit_pos;
    let end = (*reader).end;
    // `pos >> 3` is the original's arithmetic `asr #3`; `pos & !7`
    // matches `bic` on two's complement, so a negative offset keeps
    // the ARM round-towards-minus-infinity residue in 0..8.
    let mut p = (*reader).data.wrapping_offset((pos >> 3) as isize);
    let first_bits: i32 = 8 - (pos - (pos & !7));
    if first_bits == 8 && (ops.emulation_probe)(p, end) != 0 {
        p = p.add(1);
        *emulation_byte_pending = 1;
    }
    if count <= first_bits {
        // The original's unaligned `ldr` + lsl/and/lsr: only `*p`
        // survives the mask (see the module header's deviation).
        let byte = *p as u32;
        return ((byte << (8 - first_bits)) & 0xff) >> (8 - count);
    }
    let byte = *p;
    let mut next = p.add(1);
    let probed = (ops.emulation_probe)(next, end) != 0;
    let mut pending_skip = probed;
    let low = 8 - first_bits;
    let mut value: u32 = ((byte as u32) << low & 0xff) >> low;
    let mut remaining: i32 = count - first_bits;
    if probed {
        *emulation_byte_pending = 1;
    }
    loop {
        if remaining == 0 {
            return value;
        }
        if remaining < 8 {
            break;
        }
        let mut cur = next;
        if pending_skip {
            cur = next.add(1);
            pending_skip = false;
        }
        next = cur.add(1);
        let byte = *cur;
        let probed = (ops.emulation_probe)(next, end) != 0;
        if probed {
            pending_skip = true;
        }
        value = value << 8 | byte as u32;
        remaining -= 8;
        if probed {
            *emulation_byte_pending = 1;
        }
    }
    if pending_skip {
        next = next.add(1);
    }
    value << remaining | (*next as u32) >> (8 - remaining)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the shared ops table across tests.
    static LOCK: Mutex<()> = Mutex::new(());

    /// Faithful transcription of the probe `FUN_082c319c` @
    /// 0x082c319c: is the byte at `p` the `0x03` of a `00 00 03 xx`
    /// sequence with `xx < 4`, with at least one byte after it before
    /// `end`? Reads `p[-2]`, so test payloads are padded (with 0xff,
    /// which can never match).
    unsafe extern "C" fn model_probe(p: *const u8, end: *const u8) -> u32 {
        if p.add(1) < end
            && p.offset(-2).read() == 0
            && p.offset(-1).read() == 0
            && p.read() == 3
            && p.add(1).read() < 4
        {
            return 1;
        }
        0
    }

    const MODEL_OPS: CgRbspReadBitsOps = CgRbspReadBitsOps {
        emulation_probe: model_probe,
    };

    fn setup() -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CG_RBSP_READ_BITS_OPS).write(MODEL_OPS);
        }
        guard
    }

    fn teardown() {
        unsafe {
            core::ptr::addr_of_mut!(CG_RBSP_READ_BITS_OPS).write(CgRbspReadBitsOps {
                emulation_probe: missing_emulation_probe,
            });
        }
    }

    /// Scratch payload with two 0xff guard bytes before `data` (the
    /// probe reads `p[-2]`) and 64 bytes of 0xff slack after, so
    /// out-of-payload reads never fault and never false-positive an
    /// EP sequence.
    struct Payload {
        buf: Vec<u8>,
    }

    impl Payload {
        fn new(bytes: &[u8]) -> Payload {
            let mut buf = std::vec![0xffu8; 2];
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&[0xffu8; 64]);
            Payload { buf }
        }

        fn reader(&self) -> RbspBitReader {
            let data = unsafe { self.buf.as_ptr().add(2) };
            RbspBitReader {
                data,
                bit_pos: 0,
                end: unsafe { data.add(self.buf.len() - 2 - 64) },
            }
        }
    }

    /// Naive MSB-first bit fetch over raw bytes — the independent
    /// reference. Reads through the same backing memory as the port,
    /// so over-`end` reads still compare meaningfully.
    fn reference_read(bytes: &[u8], bit_pos: usize, count: usize) -> u32 {
        let mut value = 0u32;
        for k in 0..count {
            let pos = bit_pos + k;
            let bit = (bytes[pos >> 3] >> (7 - (pos & 7))) & 1;
            value = value << 1 | bit as u32;
        }
        value
    }

    /// Standard H.264 emulation prevention: after two zero bytes,
    /// insert 0x03 before a byte in 0..=3.
    fn insert_emulation_prevention(rbsp: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut zeros = 0;
        for &b in rbsp {
            if zeros >= 2 && b <= 3 {
                out.push(0x03);
                zeros = 0;
            }
            out.push(b);
            zeros = if b == 0 { zeros + 1 } else { 0 };
        }
        out
    }

    /// Is raw byte `i` an inserted emulation-prevention byte (same
    /// predicate the probe uses, index-space)?
    fn is_ep_byte(raw: &[u8], i: usize) -> bool {
        i >= 2 && raw[i - 2] == 0 && raw[i - 1] == 0 && raw[i] == 3 && raw[i + 1] < 4
    }

    /// Strip emulation-prevention bytes: the RBSP the reference
    /// decoder works on.
    fn rbsp_of(raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..raw.len() {
            let last = i + 1 == raw.len();
            if !last && is_ep_byte(raw, i) {
                continue;
            }
            out.push(raw[i]);
        }
        out
    }

    /// Calls the port on `payload` at `bit_pos`; returns
    /// (value, flag, reader-unchanged).
    fn read(payload: &Payload, bit_pos: i32, count: i32, flag_init: u8) -> (u32, u8, bool) {
        let mut reader = payload.reader();
        reader.bit_pos = bit_pos;
        let (data, end) = (reader.data, reader.end);
        let mut flag = flag_init;
        let value = unsafe { cg_rbsp_read_bits(&mut reader, count, &mut flag) };
        (
            value,
            flag,
            reader.data == data && reader.bit_pos == bit_pos && reader.end == end,
        )
    }

    /// Deterministic byte stream (a xorshift) with every 0x00 byte
    /// forced to 0x5a: no two consecutive zeros, so NO emulation
    /// prevention applies and raw == rbsp.
    fn plain_stream(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let b = (state >> 24) as u8;
                if b == 0 {
                    0x5a
                } else {
                    b
                }
            })
            .collect()
    }

    #[test]
    fn width_and_alignment_sweep_matches_naive_msb_first_read() {
        let _g = setup();
        let payload = Payload::new(&plain_stream(40));
        let raw = &payload.buf[2..42];
        for count in 1..=32i32 {
            for align in 0..8i32 {
                // bit positions at this alignment with the whole read
                // inside the payload
                let mut bit = align;
                while bit + count <= (raw.len() as i32) * 8 {
                    let (value, flag, unmoved) = read(&payload, bit, count, 0xA5);
                    let expect = reference_read(raw, bit as usize, count as usize);
                    assert_eq!(
                        value, expect,
                        "count={count} bit_pos={bit} (alignment {align})"
                    );
                    assert_eq!(flag, 0, "no EP in a zero-free stream");
                    assert!(unmoved, "the cursor never moves");
                    bit += 8;
                }
            }
        }
        teardown();
    }

    #[test]
    fn refuses_out_of_range_counts_and_still_clears_the_flag() {
        let _g = setup();
        let payload = Payload::new(&plain_stream(16));
        for count in [-2i32, -1, 0, 33, 34, 100, i32::MIN, i32::MAX] {
            let (value, flag, unmoved) = read(&payload, 13, count, 1);
            assert_eq!(value, 0, "count={count} refused");
            assert_eq!(flag, 0, "entry store clears the flag even on refusal");
            assert!(unmoved);
        }
        teardown();
    }

    #[test]
    fn single_byte_path_uses_only_the_addressed_byte() {
        let _g = setup();
        // Neighbours that would poison the result if the port leaked
        // adjacent bytes the way the original's unaligned `ldr` reads
        // them: the mask must drop them.
        let payload = Payload::new(&[0xDE, 0b1011_0011, 0xAD]);
        for count in 1..=8i32 {
            let (value, _, unmoved) = read(&payload, 8, count, 0);
            let expect = 0b1011_0011u32 >> (8 - count);
            assert_eq!(value, expect, "count={count}");
            assert!(unmoved);
        }
        // Unaligned single-byte windows.
        for align in 1..8i32 {
            for count in 1..=(8 - align) {
                let (value, _, _) = read(&payload, 8 + align, count, 0);
                let expect =
                    reference_read(&payload.buf[2..5], (8 + align) as usize, count as usize);
                assert_eq!(value, expect, "align={align} count={count}");
            }
        }
        teardown();
    }

    #[test]
    fn aligned_read_starting_on_an_ep_byte_skips_it() {
        let _g = setup();
        // rbsp: 00 00 01 ff — encoder inserts 03 before the 01.
        let raw = insert_emulation_prevention(&[0x00, 0x00, 0x01, 0xff, 0x80]);
        assert_eq!(&raw[..4], &[0x00, 0x00, 0x03, 0x01]);
        let payload = Payload::new(&raw);
        // bit_pos 16: the aligned cursor sits exactly on the EP byte.
        let (value, flag, unmoved) = read(&payload, 16, 8, 0);
        assert_eq!(value, 0x01, "the 0x03 is skipped, not read");
        assert_eq!(flag, 1, "the skip is reported");
        assert!(unmoved);
        // A wider read from the same spot crosses the skip and keeps
        // pulling real bytes.
        let rbsp = rbsp_of(&raw);
        for count in 1..=24i32 {
            let (value, flag, _) = read(&payload, 16, count, 0);
            assert_eq!(
                value,
                reference_read(&rbsp, 16, count as usize),
                "count={count}"
            );
            assert_eq!(flag, 1, "count={count}");
        }
        teardown();
    }

    #[test]
    fn mid_read_ep_skip_matches_rbsp_reference_at_every_alignment() {
        let _g = setup();
        // An RBSP rich in EP triggers: 00 00 00/01/02/03 runs, framed
        // by nonzero bytes, long enough for 32-bit reads.
        let rbsp = [
            0xff, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x01, 0x55, 0x00, 0x00, 0x02, 0x33,
            0x00, 0x00, 0x03, 0xcc, 0x7e,
        ];
        let raw = insert_emulation_prevention(&rbsp);
        let payload = Payload::new(&raw);
        let stripped = rbsp_of(&raw);
        assert_eq!(stripped, rbsp, "the strip predicate inverts the inserter");
        // The cursor's bit_pos indexes the RAW stream — an EP byte
        // occupies eight bit positions, and a mid-byte start inside
        // one reads its bits as data. Valid start positions are the
        // non-EP raw bytes; each maps to its RBSP byte, and a read
        // from raw bit 8*i+off must return the RBSP bits at 8*j+off.
        let mut j = 0usize; // rbsp index of raw byte i
        for i in 0..raw.len() {
            if is_ep_byte(&raw, i) {
                continue;
            }
            for off in 0..8i32 {
                let raw_bit = (i * 8) as i32 + off;
                let rbsp_bit = j * 8 + off as usize;
                for count in 1..=32i32 {
                    if rbsp_bit + count as usize > stripped.len() * 8 {
                        break;
                    }
                    let (value, _, unmoved) = read(&payload, raw_bit, count, 0);
                    assert_eq!(
                        value,
                        reference_read(&stripped, rbsp_bit, count as usize),
                        "count={count} raw_bit={raw_bit} (rbsp bit {rbsp_bit})"
                    );
                    assert!(unmoved);
                }
            }
            j += 1;
        }
        teardown();
    }

    #[test]
    fn flag_reports_exactly_the_probes_that_fire() {
        let _g = setup();
        // rbsp: aa 00 00 01 bb → raw: aa 00 00 03 01 bb. The EP byte
        // is raw byte 3, between rbsp bytes 2 and 3.
        let rbsp = [0xaa, 0x00, 0x00, 0x01, 0xbb];
        let raw = insert_emulation_prevention(&rbsp);
        assert_eq!(&raw, &[0xaa, 0x00, 0x00, 0x03, 0x01, 0xbb]);
        let payload = Payload::new(&raw);
        let stripped = rbsp_of(&raw);
        // (bit_pos, count, expected flag)
        let cases: &[(i32, i32, u8)] = &[
            (0, 8, 0),   // byte 0 only: no probe can reach the EP byte
            (0, 16, 0),  // bytes 0..1: probes fire on bytes 1 and 2
            (8, 8, 0),   // byte 1 alone
            (16, 8, 0),  // byte 2 alone: the EP byte follows but the
                         // aligned-entry probe points at byte 2 itself
            (8, 16, 1),  // bytes 1..2: the whole-byte loop consumes
                         // byte 2 and probes byte 3 — the probe FIRES
                         // (and reports) even though the read ends
                         // there and the pending skip is never consumed
            (16, 16, 1), // bytes 2..3: mid-read skip is consumed
            (24, 8, 1),  // aligned entry exactly on the EP byte
            (24, 1, 1),  // even a 1-bit read from there skips first
            (0, 32, 1),  // bytes 0..3 across the seam
            (8, 32, 1),  // bytes 1..4 across the seam
            (4, 32, 1),  // unaligned window across the seam
        ];
        for &(bit, count, expect_flag) in cases {
            let (value, flag, unmoved) = read(&payload, bit, count, 0xA5);
            assert_eq!(
                value,
                reference_read(&stripped, bit as usize, count as usize),
                "bit_pos={bit} count={count}"
            );
            assert_eq!(flag, expect_flag, "bit_pos={bit} count={count}");
            assert!(unmoved);
        }
        teardown();
    }

    #[test]
    fn ep_byte_at_the_payload_end_is_not_a_sequence() {
        let _g = setup();
        // Probe needs p + 1 < end: a trailing 00 00 03 (the 0x03 is
        // the last byte) is NOT an EP sequence, so the aligned read
        // starting on it reads the 0x03 as data and reports nothing.
        let payload = Payload::new(&[0x11, 0x00, 0x00, 0x03]);
        let (value, flag, unmoved) = read(&payload, 24, 8, 0);
        assert_eq!(value, 0x03);
        assert_eq!(flag, 0);
        assert!(unmoved);
        // Same when the following byte is 4 or above: 00 00 03 04 is
        // not an EP sequence either.
        let payload = Payload::new(&[0x11, 0x00, 0x00, 0x03, 0x04]);
        let (value, flag, _) = read(&payload, 24, 8, 0);
        assert_eq!(value, 0x03);
        assert_eq!(flag, 0);
        let (value, flag, _) = read(&payload, 24, 16, 0);
        assert_eq!(value, 0x0304);
        assert_eq!(flag, 0);
        teardown();
    }

    #[test]
    fn reads_past_end_are_unchecked_but_stable() {
        let _g = setup();
        // The port must not bounds-check the byte fetches: a 32-bit
        // read starting in the last payload byte pulls the following
        // 0xff slack, exactly as the original reads whatever memory
        // follows. The reference sees the same backing bytes.
        let payload = Payload::new(&[0x11, 0x22, 0x33, 0x44]);
        let (value, flag, unmoved) = read(&payload, 24, 32, 0);
        assert_eq!(
            value,
            reference_read(&payload.buf[2..], 24, 32),
            "0x44 followed by three 0xff slack bytes"
        );
        assert_eq!(value, 0x44ff_ffff);
        assert_eq!(flag, 0);
        assert!(unmoved);
        teardown();
    }

    #[test]
    fn full_width_reads_at_every_alignment() {
        let _g = setup();
        let payload = Payload::new(&plain_stream(12));
        let raw = &payload.buf[2..14];
        for bit in 0..8i32 {
            let (value, flag, unmoved) = read(&payload, bit, 32, 0);
            assert_eq!(
                value,
                reference_read(raw, bit as usize, 32),
                "bit_pos={bit}: 32-bit window"
            );
            assert_eq!(flag, 0);
            assert!(unmoved);
        }
        // All-ones and all-zeros-extreme payloads.
        let ones = Payload::new(&[0xff; 12]);
        let (value, _, _) = read(&ones, 3, 32, 0);
        assert_eq!(value, 0xffff_ffff);
        let zeros = Payload::new(&[0x80, 0, 0, 0x40, 0, 0, 0x20, 0]);
        // 00 00 40: 0x40 >= 4 so no EP; value is the plain window.
        let (value, flag, _) = read(&zeros, 0, 32, 0);
        assert_eq!(value, 0x8000_0040);
        assert_eq!(flag, 0);
        teardown();
    }
}
