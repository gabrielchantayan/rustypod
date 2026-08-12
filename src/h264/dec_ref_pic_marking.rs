//! `dec_ref_pic_marking` — original: `FUN_08365640` @ 0x08365640
//! (464 bytes, all code — no literal pool; exactly one `bl` call
//! site, in the slice-header parser @ 0x08366b8c, which passes the
//! shared RBSP cursor, `slice_header + 0x2c` as the output struct,
//! `nal_unit_type` in r2 and a stale r3).
//!
//! The H.264 `dec_ref_pic_marking()` syntax parser (spec section
//! 7.3.3.3), verbatim:
//!
//! ```text
//! if nal_unit_type == 5:                    // IDR picture
//!     no_output_of_prior_pics_flag   u(1)   // -> marking + 0x00
//!     long_term_reference_flag       u(1)   // -> marking + 0x01
//! else:
//!     adaptive_ref_pic_marking_mode_flag u(1)   // -> marking + 0x02
//!     if adaptive_ref_pic_marking_mode_flag:
//!         do:
//!             memory_management_control_operation ue(v)  // -> +0x03
//!             if mmco == 1 || mmco == 3:
//!                 difference_of_pic_nums_minus1  ue(v)   // -> +0x04
//!             if mmco == 2:
//!                 long_term_pic_num              ue(v)   // -> +0x08
//!             if mmco == 3 || mmco == 6:
//!                 long_term_frame_idx            ue(v)   // -> +0x0c
//!             if mmco == 4:
//!                 max_long_term_frame_idx_plus1  ue(v)   // -> +0x10
//!         while mmco != 0
//! ```
//!
//! Every syntax element is a read primitive (u(1) via
//! [`cg_rbsp_read_bits`] @ 0x082d0630, ue(v) via
//! [`cg_exp_golomb_ue_read`] @ 0x082c5df0) immediately committed by
//! [`h264_bitstream_advance`] @ 0x082b3258; the parser returns `true`
//! only when every advance reports the cursor still inside the NAL
//! payload, `false` otherwise — including the operand reads, whose
//! stores have already happened when their advance fails (the
//! original's `strb`/`str` precede every `bl 0x082b3258`). A single
//! `u8` emulation-prevention flag local serves every read and advance
//! in the function (the `str r0,[sp]` at entry zeroes it once), and a
//! single `i32` stack slot carries each ue(v) element's bit count from
//! the reader to its advance.
//!
//! The MMCO loop condition reloads the stored byte each round: the
//! first iteration is gated on `adaptive_ref_pic_marking_mode_flag`,
//! subsequent ones on the just-stored
//! `memory_management_control_operation` (`ldrb r0,[r4,#0x2]` /
//! `ldrb r0,[r4,#0x3]` feeding the `cmp r0,#0x0; bne` at the loop
//! tail). The mmco store is a `strb` — a ue(v) value above 255 wraps
//! mod 256, so a corrupt stream can terminate the loop on a nonzero
//! code number; the port keeps the `as u8` truncation.
//!
//! Deviations:
//! - All three callees are ported ([`cg_rbsp_read_bits`],
//!   [`cg_exp_golomb_ue_read`], [`h264_bitstream_advance`]), so they
//!   take direct calls — no dispatch seams, retiring none.
//! - r3 (`bits_out_init`) seeds the bits-count stack slot exactly like
//!   the original's spilled argument, but it is dead:
//!   [`cg_exp_golomb_ue_read`] always stores the slot before this
//!   function reads it, and the one call site passes a stale register.
//! - Ghidra's `break`-then-`return 0` on the mmco advance failure is
//!   the same `mov r0,#0x0` exit every other failed advance branches
//!   to (0x08365808); the port returns `false` directly.

use crate::codegen::exp_golomb::cg_exp_golomb_ue_read;
use crate::codegen::rbsp_read_bits::cg_rbsp_read_bits;
use crate::h264::bitstream::{h264_bitstream_advance, RbspBitReader};

/// The parser's output record (original layout: three flag bytes, the
/// mmco byte, then four word operands; 20 bytes total, word-aligned
/// from +0x04). Every field is written only on the path that parses
/// it, and — like the original — an element's store happens even when
/// the advance that follows it fails.
#[repr(C)]
pub struct DecRefPicMarking {
    /// +0x00 — IDR only: the picture is not output before a later one.
    pub no_output_of_prior_pics_flag: u8,
    /// +0x01 — IDR only: mark this picture "long term".
    pub long_term_reference_flag: u8,
    /// +0x02 — non-IDR only: gates the MMCO loop.
    pub adaptive_ref_pic_marking_mode_flag: u8,
    /// +0x03 — the last MMCO read; the loop reloads it as its
    /// condition, so it is 0 on success and the last nonzero command
    /// on a mid-loop stream exhaustion.
    pub memory_management_control_operation: u8,
    /// +0x04 — MMCO 1/3 operand.
    pub difference_of_pic_nums_minus1: u32,
    /// +0x08 — MMCO 2 operand.
    pub long_term_pic_num: u32,
    /// +0x0c — MMCO 3/6 operand.
    pub long_term_frame_idx: u32,
    /// +0x10 — MMCO 4 operand.
    pub max_long_term_frame_idx_plus1: u32,
}

/// dec_ref_pic_marking — original: `FUN_08365640` @ 0x08365640
/// (464 bytes, one `bl` call site).
///
/// Parses the `dec_ref_pic_marking()` syntax of the slice header at
/// the cursor into `marking`; see the module header for the element
/// order. Returns `true` when every element's commit kept the cursor
/// inside the NAL payload, `false` on the first exhaustion — with the
/// element whose commit failed already stored, matching the original.
///
/// `bits_out_init` is the original's fourth (dead) argument: the
/// spilled r3 seeds the bits-count slot the ue(v) reader always
/// overwrites before this function loads it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dec_ref_pic_marking(
    reader: *mut RbspBitReader,
    marking: *mut DecRefPicMarking,
    nal_unit_type: i32,
    bits_out_init: i32,
) -> bool {
    let mut emulation_byte_pending: u8 = 0;
    let mut bits_out: i32 = bits_out_init;
    if nal_unit_type == 5 {
        (*marking).no_output_of_prior_pics_flag =
            cg_rbsp_read_bits(reader, 1, &mut emulation_byte_pending) as u8;
        if h264_bitstream_advance(reader, 1, &mut emulation_byte_pending) {
            (*marking).long_term_reference_flag =
                cg_rbsp_read_bits(reader, 1, &mut emulation_byte_pending) as u8;
            if h264_bitstream_advance(reader, 1, &mut emulation_byte_pending) {
                return true;
            }
        }
    } else {
        (*marking).adaptive_ref_pic_marking_mode_flag =
            cg_rbsp_read_bits(reader, 1, &mut emulation_byte_pending) as u8;
        if h264_bitstream_advance(reader, 1, &mut emulation_byte_pending) {
            let mut mmco = (*marking).adaptive_ref_pic_marking_mode_flag;
            loop {
                if mmco == 0 {
                    return true;
                }
                (*marking).memory_management_control_operation =
                    cg_exp_golomb_ue_read(reader, &mut bits_out, &mut emulation_byte_pending) as u8;
                if !h264_bitstream_advance(reader, bits_out, &mut emulation_byte_pending) {
                    return false;
                }
                let op = (*marking).memory_management_control_operation;
                if op == 1 || op == 3 {
                    (*marking).difference_of_pic_nums_minus1 =
                        cg_exp_golomb_ue_read(reader, &mut bits_out, &mut emulation_byte_pending);
                    if !h264_bitstream_advance(reader, bits_out, &mut emulation_byte_pending) {
                        return false;
                    }
                }
                if op == 2 {
                    (*marking).long_term_pic_num =
                        cg_exp_golomb_ue_read(reader, &mut bits_out, &mut emulation_byte_pending);
                    if !h264_bitstream_advance(reader, bits_out, &mut emulation_byte_pending) {
                        return false;
                    }
                }
                if op == 3 || op == 6 {
                    (*marking).long_term_frame_idx =
                        cg_exp_golomb_ue_read(reader, &mut bits_out, &mut emulation_byte_pending);
                    if !h264_bitstream_advance(reader, bits_out, &mut emulation_byte_pending) {
                        return false;
                    }
                }
                if op == 4 {
                    (*marking).max_long_term_frame_idx_plus1 =
                        cg_exp_golomb_ue_read(reader, &mut bits_out, &mut emulation_byte_pending);
                    if !h264_bitstream_advance(reader, bits_out, &mut emulation_byte_pending) {
                        return false;
                    }
                }
                mmco = (*marking).memory_management_control_operation;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::codegen::exp_golomb::{CgExpGolombOps, CG_EXP_GOLOMB_OPS};
    use crate::codegen::rbsp_read_bits::{CgRbspReadBitsOps, CG_RBSP_READ_BITS_OPS};
    use crate::h264::bitstream::h264_bitstream_count_leading_zeros;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the shared ops tables across tests (the crate also
    /// runs tests single-threaded via RUST_TEST_THREADS=1).
    static LOCK: Mutex<()> = Mutex::new(());

    /// Faithful transcription of the probe `FUN_082c319c` @
    /// 0x082c319c: is the byte at `p` the `0x03` of a `00 00 03 xx`
    /// sequence with `xx < 4`, with at least one byte after it before
    /// `end`? Reads `p[-2]`, so test payloads are padded (with 0xff,
    /// which can never match). Same transcription as the
    /// rbsp_read_bits.rs tests.
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

    /// Wires both seam tables to the REAL ported primitives, so the
    /// parser is exercised end to end: cg_exp_golomb_ue_read through
    /// the ported count_leading_zeros / cg_rbsp_read_bits, the EP
    /// probe through the faithful transcription. Not restored on
    /// teardown: every other consumer of these tables installs its own
    /// bindings before use, and the real ports are strictly more
    /// functional than the `missing_*` spin-loop defaults.
    fn setup() -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CG_EXP_GOLOMB_OPS).write(CgExpGolombOps {
                count_leading_zeros: h264_bitstream_count_leading_zeros,
                read_bits: cg_rbsp_read_bits,
            });
            core::ptr::addr_of_mut!(CG_RBSP_READ_BITS_OPS).write(CgRbspReadBitsOps {
                emulation_probe: model_probe,
            });
        }
        guard
    }

    /// Scratch payload with two 0xff guard bytes before `data` (the
    /// probe reads `p[-2]`) and 64 bytes of 0xff slack after, so
    /// out-of-payload reads never fault and never false-positive an
    /// EP sequence. `end` can be shortened independently of the
    /// backing bytes to stage stream exhaustion.
    struct Payload {
        buf: Vec<u8>,
        len: usize,
    }

    impl Payload {
        fn new(bytes: &[u8]) -> Payload {
            let mut buf = std::vec![0xffu8; 2];
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&[0xffu8; 64]);
            Payload {
                buf,
                len: bytes.len(),
            }
        }

        /// A payload whose `end` hides the tail: the bytes are still
        /// readable (slack), only the bounds verdict changes.
        fn truncated(mut self, len: usize) -> Payload {
            self.len = len;
            self
        }

        fn reader(&self) -> RbspBitReader {
            let data = unsafe { self.buf.as_ptr().add(2) };
            RbspBitReader {
                data,
                bit_pos: 0,
                end: unsafe { data.add(self.len) },
            }
        }
    }

    /// MSB-first RBSP builder: u(n) fields and ue(v) code words.
    struct BitWriter {
        bits: Vec<u8>,
    }

    impl BitWriter {
        fn new() -> BitWriter {
            BitWriter { bits: Vec::new() }
        }

        fn bit(&mut self, b: u32) {
            self.bits.push((b & 1) as u8);
        }

        fn ue(&mut self, value: u32) {
            let code_num = value + 1;
            let lz = 31 - code_num.leading_zeros();
            for _ in 0..lz {
                self.bit(0);
            }
            for k in (0..=lz).rev() {
                self.bit(code_num >> k);
            }
        }

        /// The packed bytes and the exact bit length (no trailing pad
        /// counted).
        fn finish(&self) -> (Vec<u8>, usize) {
            let total = self.bits.len();
            let mut bytes = std::vec![0u8; total.div_ceil(8)];
            for (i, &b) in self.bits.iter().enumerate() {
                bytes[i >> 3] |= b << (7 - (i & 7));
            }
            (bytes, total)
        }
    }

    /// Standard H.264 emulation prevention: after two zero bytes,
    /// insert 0x03 before a byte in 0..=3. Returns the EBSP and the
    /// number of inserted bytes.
    fn insert_emulation_prevention(rbsp: &[u8]) -> (Vec<u8>, usize) {
        let mut out = Vec::new();
        let mut inserted = 0;
        let mut zeros = 0;
        for &b in rbsp {
            if zeros >= 2 && b <= 3 {
                out.push(0x03);
                inserted += 1;
                zeros = 0;
            }
            out.push(b);
            zeros = if b == 0 { zeros + 1 } else { 0 };
        }
        (out, inserted)
    }

    /// Sentinel-filled output record: any field the parser leaves
    /// alone keeps its poison value.
    fn sentinel_marking() -> DecRefPicMarking {
        DecRefPicMarking {
            no_output_of_prior_pics_flag: 0xaa,
            long_term_reference_flag: 0xbb,
            adaptive_ref_pic_marking_mode_flag: 0xcc,
            memory_management_control_operation: 0xdd,
            difference_of_pic_nums_minus1: 0xdead_beef,
            long_term_pic_num: 0xcafe_babe,
            long_term_frame_idx: 0x8bad_f00d,
            max_long_term_frame_idx_plus1: 0x0bad_cafe,
        }
    }

    /// Runs the parser on `payload` at bit 0 with `nal_unit_type`.
    fn parse(
        payload: &Payload,
        nal_unit_type: i32,
    ) -> (bool, RbspBitReader, DecRefPicMarking) {
        let mut reader = payload.reader();
        let mut marking = sentinel_marking();
        let ok = unsafe { dec_ref_pic_marking(&mut reader, &mut marking, nal_unit_type, 0) };
        (ok, reader, marking)
    }

    #[test]
    fn idr_reads_both_flags() {
        let _guard = setup();
        // Bits: no_output=1, long_term=0 -> 0x80; no_output=0,
        // long_term=1 -> 0x40; both set -> 0xc0; both clear -> 0x00.
        for (byte, no_output, long_term) in [
            (0x80u8, 1u8, 0u8),
            (0x40, 0, 1),
            (0xc0, 1, 1),
            (0x00, 0, 0),
        ] {
            let payload = Payload::new(&[byte]);
            let (ok, reader, marking) = parse(&payload, 5);
            assert!(ok, "byte {byte:#04x}");
            assert_eq!(marking.no_output_of_prior_pics_flag, no_output);
            assert_eq!(marking.long_term_reference_flag, long_term);
            assert_eq!(reader.bit_pos, 2);
            // The non-IDR fields are untouched.
            assert_eq!(marking.adaptive_ref_pic_marking_mode_flag, 0xcc);
            assert_eq!(marking.memory_management_control_operation, 0xdd);
        }
    }

    #[test]
    fn idr_second_flag_advance_failure_still_stores_it() {
        let _guard = setup();
        // One readable byte, cursor started at bit 6: flag 1 commits
        // to bit 7 (byte 0, in bounds), flag 2 commits to bit 8 (byte
        // 1 == end, exhausted). The failed element is still stored.
        let payload = Payload::new(&[0x03]);
        let mut reader = payload.reader();
        reader.bit_pos = 6;
        let mut marking = sentinel_marking();
        let ok = unsafe { dec_ref_pic_marking(&mut reader, &mut marking, 5, 0) };
        assert!(!ok);
        assert_eq!(marking.no_output_of_prior_pics_flag, 1);
        assert_eq!(marking.long_term_reference_flag, 1);
        assert_eq!(reader.bit_pos, 8);
    }

    #[test]
    fn idr_first_flag_advance_failure_leaves_second_untouched() {
        let _guard = setup();
        // Cursor at bit 7 of a one-byte payload: the first flag reads
        // fine but its commit lands on byte 1 == end.
        let payload = Payload::new(&[0x01]);
        let mut reader = payload.reader();
        reader.bit_pos = 7;
        let mut marking = sentinel_marking();
        let ok = unsafe { dec_ref_pic_marking(&mut reader, &mut marking, 5, 0) };
        assert!(!ok);
        assert_eq!(marking.no_output_of_prior_pics_flag, 1);
        assert_eq!(marking.long_term_reference_flag, 0xbb, "untouched");
        assert_eq!(reader.bit_pos, 8);
    }

    #[test]
    fn non_idr_adaptive_flag_clear_skips_the_mmco_loop() {
        let _guard = setup();
        let payload = Payload::new(&[0x00]);
        let (ok, reader, marking) = parse(&payload, 1);
        assert!(ok);
        assert_eq!(marking.adaptive_ref_pic_marking_mode_flag, 0);
        assert_eq!(reader.bit_pos, 1);
        // No MMCO was read; IDR fields untouched too.
        assert_eq!(marking.memory_management_control_operation, 0xdd);
        assert_eq!(marking.no_output_of_prior_pics_flag, 0xaa);
    }

    #[test]
    fn non_idr_adaptive_flag_set_with_immediate_end_mmco() {
        let _guard = setup();
        // u(1) flag = 1, then ue(0) = "1": loop reads mmco 0 and
        // returns success on the second iteration's condition.
        let payload = Payload::new(&[0xc0]);
        let (ok, reader, marking) = parse(&payload, 1);
        assert!(ok);
        assert_eq!(marking.adaptive_ref_pic_marking_mode_flag, 1);
        assert_eq!(marking.memory_management_control_operation, 0);
        assert_eq!(reader.bit_pos, 2);
        // mmco 0 takes no operands.
        assert_eq!(marking.difference_of_pic_nums_minus1, 0xdead_beef);
    }

    #[test]
    fn mmco_loop_reads_every_command_and_operand() {
        let _guard = setup();
        let mut w = BitWriter::new();
        w.bit(1); // adaptive_ref_pic_marking_mode_flag
        w.ue(1); // mmco 1: mark short-term unused
        w.ue(5); //   difference_of_pic_nums_minus1
        w.ue(2); // mmco 2: mark long-term unused
        w.ue(3); //   long_term_pic_num
        w.ue(3); // mmco 3: assign long-term frame idx
        w.ue(2); //   difference_of_pic_nums_minus1
        w.ue(7); //   long_term_frame_idx
        w.ue(6); // mmco 6: mark current long-term
        w.ue(1); //   long_term_frame_idx
        w.ue(4); // mmco 4: cap long-term frame idx
        w.ue(9); //   max_long_term_frame_idx_plus1
        w.ue(0); // mmco 0: end
        let (rbsp, total_bits) = w.finish();
        let (raw, inserted) = insert_emulation_prevention(&rbsp);
        let payload = Payload::new(&raw);
        let (ok, reader, marking) = parse(&payload, 1);
        assert!(ok);
        assert_eq!(marking.adaptive_ref_pic_marking_mode_flag, 1);
        assert_eq!(marking.memory_management_control_operation, 0);
        assert_eq!(marking.difference_of_pic_nums_minus1, 2, "mmco 3 wins");
        assert_eq!(marking.long_term_pic_num, 3);
        assert_eq!(marking.long_term_frame_idx, 1, "mmco 6 wins");
        assert_eq!(marking.max_long_term_frame_idx_plus1, 9);
        // The cursor indexes the RAW (EBSP) stream: every inserted EP
        // byte costs an extra 8 committed bits.
        assert_eq!(
            reader.bit_pos as usize,
            total_bits + 8 * inserted,
            "raw cursor end state"
        );
    }

    #[test]
    fn mmco_operands_decode_across_emulation_prevention_bytes() {
        let _guard = setup();
        // diff = 2^26 - 1: its ue(v) code is 26 zeros, a 1, then 26
        // zeros. The operand starts at bit 4, so the 1 lands at byte
        // bit index 6 (byte 0x02) after two zero bytes, and the
        // all-zero suffix closes with another 00 00 00 triple: two
        // emulation-prevention bytes, three bytes apart, crossed by
        // the prefix scan and the suffix read respectively.
        let mut w = BitWriter::new();
        w.bit(1);
        w.ue(1); // mmco 1
        w.ue((1 << 26) - 1); //   difference_of_pic_nums_minus1
        w.ue(0); // end
        let (rbsp, total_bits) = w.finish();
        let (raw, inserted) = insert_emulation_prevention(&rbsp);
        assert_eq!(inserted, 2, "stream must contain EP bytes: {raw:02x?}");
        let payload = Payload::new(&raw);
        let (ok, reader, marking) = parse(&payload, 1);
        assert!(ok);
        assert_eq!(marking.difference_of_pic_nums_minus1, (1 << 26) - 1);
        assert_eq!(marking.memory_management_control_operation, 0);
        assert_eq!(reader.bit_pos as usize, total_bits + 8 * inserted);
    }

    #[test]
    fn exhausted_stream_mid_mmco_code_returns_false() {
        let _guard = setup();
        // u(1) flag = 1 and then only zeros in the one readable byte:
        // the mmco ue(v) read walks into the 0xff slack (reads are
        // not bounds-checked) and its commit lands past end.
        let payload = Payload::new(&[0x80]).truncated(1);
        let (ok, reader, marking) = parse(&payload, 1);
        assert!(!ok);
        assert_eq!(marking.adaptive_ref_pic_marking_mode_flag, 1);
        // lz = 7 zeros to the slack's first 1 bit: 7 committed for
        // the prefix, 8 for the element.
        assert_eq!(reader.bit_pos, 1 + 7 + 8);
    }

    #[test]
    fn exhausted_stream_mid_operand_returns_false_with_mmco_stored() {
        let _guard = setup();
        // flag = 1, mmco 1 ("010"), then the operand's ue(v) prefix
        // runs off the one readable byte. The mmco store and its
        // commit succeeded; only the operand's commit fails.
        let payload = Payload::new(&[0b1010_0000]).truncated(1);
        let (ok, reader, marking) = parse(&payload, 1);
        assert!(!ok);
        assert_eq!(marking.memory_management_control_operation, 1);
        // 1 (flag) + 3 (mmco) committed, then the operand: 4 zeros to
        // the slack's first 1 bit, 5 committed for the element.
        assert_eq!(reader.bit_pos, 1 + 3 + 4 + 5);
    }

    #[test]
    fn exhausted_stream_at_adaptive_flag_returns_false() {
        let _guard = setup();
        // Zero readable bytes: the flag reads slack but its commit
        // lands on byte 0 == end.
        let payload = Payload::new(&[0xff]).truncated(0);
        let (ok, _, marking) = parse(&payload, 1);
        assert!(!ok);
        // The failed element is still stored (read from 0xff slack).
        assert_eq!(marking.adaptive_ref_pic_marking_mode_flag, 1);
    }
}
