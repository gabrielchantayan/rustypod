//! Packed-record field classification — how SQLite decides which serial
//! type one `Mem` becomes when OP_MakeRecord packs a record, the
//! classifier twin of [`vdbe_serial_put`](super::vdbe_serial_put)'s
//! writer and [`vdbe_serial_get`](super::vdbe_serial_get)'s reader.
//!
//! - `vdbe_serial_type` — original: `FUN_0838cec0` @ 0x0838cec0 (288
//!   bytes, 0x0838cec0..0x0838cfe0 plus the two 4-byte literal-pool
//!   words at 0x0838cfe0/0x0838cfe4; **3 `bl` call sites**, all
//!   unconditional, binary-scanned from osos.dec by decoding every
//!   branch word: 0x08388680 and 0x083887d8 — inside the 16 KB VDBE
//!   engine routine FUN_08386ef8, upstream vdbe.c's `sqlite3VdbeExec`
//!   OP_MakeRecord loop, which sizes each field before it packs it —
//!   and 0x0838ce1c inside
//!   [`vdbe_serial_put`](super::vdbe_serial_put); no tail `b`).
//!   Upstream SQLite 3.5.9's `sqlite3VdbeSerialType` (vdbeaux.c): `u32
//!   sqlite3VdbeSerialType(Mem *pMem, int file_format)`. functions.csv's
//!   288 bytes is exact: 72 instructions through the `ldmia` return at
//!   0x0838cfdc, then the two literal-pool words, then the next
//!   function's prologue (`cmp r0,#0xc`) at 0x0838cfe8 — the ported
//!   [`vdbe_serial_type_len`](super::vdbe_serial_type_len).
//!
//! ### Listing
//!
//! ```text
//! 0838cec0  stmdb sp!, {r4,r5,r6,lr}
//! 0838cec4  ldrh r4,[r0,#0x1c]     @ flags = Mem.flags
//! 0838cec8  tst  r4,#0x1           @ MEM_Null?
//! 0838cecc  movne r0,#0x0          @   -> serial type 0
//! 0838ced0  ldmiane sp!, {r4,r5,r6,pc}
//! 0838ced4  tst  r4,#0x4           @ MEM_Int?
//! 0838ced8  beq  0x0838cfa4
//! 0838cedc  ldr  r4,[r0,#0x4]      @ v = Mem.u.i (high word)
//! 0838cee0  ldr  r5,[r0,#0x0]      @               (low word)
//! 0838cee4  ldr  r6,[0x838cfe0]    @ pool: 0x00007fff
//! 0838cee8  cmp  r1,#0x4           @ file_format >= 4?  (SIGNED blt)
//! 0838ceec  blt  0x0838cf10
//! 0838cef0  cmp  r4,#0x0
//! 0838cef4  bic  r0,r5,#0x1
//! 0838cef8  mov  r2,#0x0
//! 0838cefc  cmpeq r0,r2            @ v == 0 || v == 1?
//! 0838cf00  bne  0x0838cf10
//! 0838cf04  adds r0,r5,#0x8        @   -> v + 8 (the constants 0/1:
//! 0838cf08  adc  r1,r4,#0x0        @      types 8/9; high half dead)
//! 0838cf0c  ldmia sp!, {r4,r5,r6,pc}
//! 0838cf10  subs r0,r5,#0x0
//! 0838cf14  mov  r3,#0x0
//! 0838cf18  sbcs r1,r4,r3          @ 64-bit sign test of v
//! 0838cf1c  bge  0x0838cf28
//! 0838cf20  rsbs r5,r5,#0x0
//! 0838cf24  rsc  r4,r4,#0x0        @ v = -v (two's complement)
//! 0838cf28  cmp  r4,#0x0
//! 0838cf2c  mov  r2,#0x7f
//! 0838cf30  mov  r0,r5
//! 0838cf34  cmpeq r0,r2
//! 0838cf38  movls r0,#0x1          @ v <= 0x7f (UNSIGNED) -> 1
//! 0838cf3c  ldmials sp!, {r4,r5,r6,pc}
//! 0838cf40  cmp  r4,#0x0
//! 0838cf44  mov  r2,r6             @ 0x7fff
//! 0838cf48  mov  r0,r5
//! 0838cf4c  cmpeq r0,r2
//! 0838cf50  movls r0,#0x2          @ v <= 0x7fff -> 2
//! 0838cf54  ldmials sp!, {r4,r5,r6,pc}
//! 0838cf58  cmp  r4,#0x0
//! 0838cf5c  ldr  r2,[0x838cfe4]    @ pool: 0x007fffff
//! 0838cf60  mov  r0,r5
//! 0838cf64  cmpeq r0,r2
//! 0838cf68  movls r0,#0x3          @ v <= 0x7fffff -> 3
//! 0838cf6c  ldmials sp!, {r4,r5,r6,pc}
//! 0838cf70  cmp  r4,#0x0
//! 0838cf74  mvn  r2,#0x80000000    @ 0x7fffffff
//! 0838cf78  mov  r0,r5
//! 0838cf7c  cmpeq r0,r2
//! 0838cf80  movls r0,#0x4          @ v <= 0x7fffffff -> 4
//! 0838cf84  ldmials sp!, {r4,r5,r6,pc}
//! 0838cf88  cmp  r4,r6             @ high word vs 0x7fff
//! 0838cf8c  mvn  r2,#0x0           @ 0xffffffff
//! 0838cf90  mov  r0,r5
//! 0838cf94  cmpeq r0,r2
//! 0838cf98  movls r0,#0x5          @ v <= MAX_6BYTE -> 5
//! 0838cf9c  movhi r0,#0x6          @ else -> 6
//! 0838cfa0  ldmia sp!, {r4,r5,r6,pc}
//! 0838cfa4  tst  r4,#0x8           @ MEM_Real?
//! 0838cfa8  movne r0,#0x7          @   -> serial type 7
//! 0838cfac  ldmiane sp!, {r4,r5,r6,pc}
//! 0838cfb0  ldr  r2,[r0,#0x18]     @ n = Mem.n
//! 0838cfb4  tst  r4,#0x800         @ MEM_Zero?
//! 0838cfb8  beq  0x0838cfcc
//! 0838cfbc  ldrd r0,r1,[r0,#0x0]   @ Mem.u.nZero
//! 0838cfc0  adds r0,r0,r2
//! 0838cfc4  adc  r1,r1,r2, asr #0x1f  @ n += nZero (high half dead)
//! 0838cfc8  mov  r2,r0
//! 0838cfcc  mov  r0,r2, lsl #0x1   @ n * 2
//! 0838cfd0  and  r1,r4,#0x2        @ MEM_Str bit
//! 0838cfd4  add  r0,r0,r1, lsr #0x1   @ + 1 when text
//! 0838cfd8  add  r0,r0,#0xc        @ + 12
//! 0838cfdc  ldmia sp!, {r4,r5,r6,pc}
//! ```
//!
//! ### Algorithm
//!
//! The flag cascade runs in `Mem.flags` (+0x1c) precedence order.
//! `MEM_Null` (0x1) is serial type 0. `MEM_Int` (0x4) reads the 64-bit
//! `Mem.u.i` union word at +0x00: under file format 4 or newer
//! (SIGNED `blt` skips) the exact constants 0 and 1 short-circuit to
//! the payload-less types 8 and 9 (`v + 8`, the `adc` high half
//! feeding nothing). Otherwise the value is negated to its magnitude
//! when negative and walked through the UNSIGNED width ladder —
//! 0x7f, 0x7fff (the first literal-pool word), 0x7fffff (the second),
//! 0x7fffffff, and finally the 48-bit pair `cmp high,#0x7fff; cmpeq
//! low,#0xffffffff` that encodes upstream's `MAX_6BYTE`
//! (`(0x8000 << 32) - 1` = 0x7fffffffffffffff) — answering serial
//! types 1 through 6. `MEM_Real` (0x8) is type 7. Everything left is
//! the string/blob tail: `Mem.n` (+0x18), grown by the low word of
//! `Mem.u.nZero` (+0x00) when `MEM_Zero` (0x800) is set, becomes
//! `n * 2 + 12 + ((flags & MEM_Str) >> 1)` — even types are blobs,
//! odd types text.
//!
//! ### Deviations
//!
//! - `p_mem` is the raw original-layout 0x28-byte `Mem`, exactly as
//!   in [`vdbe_serial_get`](super::vdbe_serial_get) and
//!   [`vdbe_serial_put`](super::vdbe_serial_put): the classifier
//!   never dereferences a pointer field, so no host fixture mapping
//!   is needed.
//! - The original returns through r0:r1 (Ghidra types the function
//!   `ulonglong`): the `file_format >= 4` arm's `adc` and the
//!   `MEM_Zero` arm's `adc` produce high halves no caller reads (all
//!   three call sites consume r0 alone), so the port returns the low
//!   word as `u32` — the same narrowing
//!   [`vdbe_serial_put`](super::vdbe_serial_put) documents for its
//!   own 64-bit sums.
//! - Upstream guards the negation with `if( i<(-MAX_6BYTE) ) return
//!   6;` so `-i` cannot overflow on `INT64_MIN`; the firmware omits
//!   the guard and lets the two's-complement `rsbs`/`rsc` wrap. The
//!   behaviors coincide — for `i < -MAX_6BYTE` the wrapped magnitude
//!   exceeds `MAX_6BYTE` and falls through to type 6 anyway — and
//!   the port keeps the firmware's unconditional-wrap shape, which
//!   the host tests prove equivalent across the whole `i64` domain.

use super::value_new::{MEM_FLAGS_OFFSET, MEM_NULL};
use super::value_text::MEM_STR;
use super::value_text::MEM_ZERO;
use super::vdbe_serial_get::{MEM_INT, MEM_N_OFFSET, MEM_REAL, MEM_U_OFFSET};

/// Upstream's `MAX_6BYTE`: the largest magnitude a 6-byte big-endian
/// serial integer holds, `(((i64)0x00008000)<<32)-1`. The original
/// encodes it as the `cmp r4,r6` / `cmpeq r0,#0xffffffff` word pair
/// with the 0x7fff literal already in r6 from the type-2 rung.
const MAX_6BYTE: u64 = 0x7fff_ffff_ffff_ffff;

/// vdbe_serial_type — original: `FUN_0838cec0` @ 0x0838cec0 (288
/// bytes; 3 `bl` call sites, binary-scanned from osos.dec:
/// 0x08388680, 0x083887d8 and 0x0838ce1c).
///
/// `sqlite3VdbeSerialType`: classify the raw 0x28-byte `Mem` at
/// `p_mem` into its record serial type — 0 for NULL, 1..=6 the
/// fixed-width integers by magnitude, 7 the binary64 real, 8/9 the
/// file-format-4 constants 0/1, and the `n * 2 + 12 + is_text` tail
/// for strings and blobs. See the module header for the listing, the
/// flag precedence, and the 64-bit return narrowing.
///
/// Register usage: r0 = p_mem → return, r1 = file_format, r2 =
/// threshold scratch, r3 = zero, r4 = flags → value high word, r5 =
/// value low word, r6 = the 0x7fff literal.
///
/// # Safety
/// `p_mem` must point to a readable, 8-aligned target-layout `Mem`
/// (the `Mem.u` word is loaded 64-bit wide); no pointer field is
/// dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_serial_type(p_mem: *const u8, file_format: i32) -> u32 {
    let flags = (p_mem.add(MEM_FLAGS_OFFSET) as *const u16).read();
    if flags & MEM_NULL != 0 {
        return 0;
    }
    if flags & MEM_INT != 0 {
        let value = (p_mem.add(MEM_U_OFFSET) as *const u64).read();
        if file_format >= 4 && value < 2 {
            return value.wrapping_add(8) as u32;
        }
        let magnitude = if (value as i64) < 0 {
            value.wrapping_neg()
        } else {
            value
        };
        if magnitude <= 0x7f {
            return 1;
        }
        if magnitude <= 0x7fff {
            return 2;
        }
        if magnitude <= 0x7f_ffff {
            return 3;
        }
        if magnitude <= 0x7fff_ffff {
            return 4;
        }
        if magnitude <= MAX_6BYTE {
            return 5;
        }
        return 6;
    }
    if flags & MEM_REAL != 0 {
        return 7;
    }
    let mut len = (p_mem.add(MEM_N_OFFSET) as *const u32).read();
    if flags & MEM_ZERO != 0 {
        let zero_tail = (p_mem.add(MEM_U_OFFSET) as *const u32).read();
        len = zero_tail.wrapping_add(len);
    }
    (len << 1)
        .wrapping_add(((flags & MEM_STR) >> 1) as u32)
        .wrapping_add(12)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::value_new::MEM_SIZE;
    use super::super::value_text::MEM_BLOB;
    use super::*;
    use std::vec::Vec;

    /// A raw original-layout Mem, 8-aligned for the `ldrd` value load.
    #[repr(align(8))]
    struct MemBlock([u8; MEM_SIZE as usize]);

    impl MemBlock {
        fn zeroed() -> MemBlock {
            MemBlock([0; MEM_SIZE as usize])
        }

        fn ptr(&self) -> *const u8 {
            self.0.as_ptr()
        }

        fn put_u16(&mut self, offset: usize, value: u16) {
            self.0[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
        }

        fn put_u32(&mut self, offset: usize, value: u32) {
            self.0[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }

        fn put_u64(&mut self, offset: usize, value: u64) {
            self.0[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
    }

    /// Upstream SQLite 3.5.9 `sqlite3VdbeSerialType` (vdbeaux.c),
    /// transcribed independently of the port — including the
    /// `i < -MAX_6BYTE` guard the firmware replaced with a wrapping
    /// negate — so the sweep below double-checks the equivalence.
    fn reference_serial_type(flags: u16, value: i64, n: u32, file_format: i32) -> u32 {
        if flags & MEM_NULL != 0 {
            return 0;
        }
        if flags & MEM_INT != 0 {
            if file_format >= 4 {
                if value == 0 {
                    return 8;
                }
                if value == 1 {
                    return 9;
                }
            }
            let magnitude = if value < 0 {
                if value < -(MAX_6BYTE as i64) {
                    return 6;
                }
                // The guard keeps `value` off i64::MIN here.
                (-(value as i128)) as u64
            } else {
                value as u64
            };
            if magnitude <= 127 {
                return 1;
            }
            if magnitude <= 32767 {
                return 2;
            }
            if magnitude <= 8388607 {
                return 3;
            }
            if magnitude <= 2147483647 {
                return 4;
            }
            if magnitude <= MAX_6BYTE {
                return 5;
            }
            return 6;
        }
        if flags & MEM_REAL != 0 {
            return 7;
        }
        let mut len = n;
        if flags & MEM_ZERO != 0 {
            len = len.wrapping_add(value as u32);
        }
        (len << 1)
            .wrapping_add(if flags & MEM_STR != 0 { 1 } else { 0 })
            .wrapping_add(12)
    }

    fn classify(flags: u16, value: i64, n: u32, file_format: i32) -> u32 {
        let mut block = MemBlock::zeroed();
        block.put_u16(MEM_FLAGS_OFFSET, flags);
        block.put_u64(MEM_U_OFFSET, value as u64);
        block.put_u32(MEM_N_OFFSET, n);
        unsafe { vdbe_serial_type(block.ptr(), file_format) }
    }

    /// The classifying flags the fixture never sets stay zero; only
    /// flags/value/n vary, everything else in the Mem is dead to the
    /// classifier.
    fn agree(flags: u16, value: i64, n: u32, file_format: i32) {
        let got = classify(flags, value, n, file_format);
        let want = reference_serial_type(flags, value, n, file_format);
        assert_eq!(
            got, want,
            "flags {flags:#06x} value {value:#x} n {n:#x} file_format {file_format}",
        );
    }

    #[test]
    fn null_dominates_every_other_flag() {
        for file_format in [-1, 0, 3, 4, 100] {
            for extra in [0, MEM_STR, MEM_INT, MEM_REAL, MEM_BLOB, MEM_ZERO, 0xffff] {
                agree(MEM_NULL | extra, -5, 9, file_format);
            }
        }
    }

    #[test]
    fn integer_width_ladder_boundaries() {
        let rungs: [u64; 5] = [0x7f, 0x7fff, 0x7f_ffff, 0x7fff_ffff, MAX_6BYTE];
        let mut values: Vec<i64> = Vec::new();
        for rung in rungs {
            for delta in -2i64..=2 {
                let edge = (rung as i64).wrapping_add(delta);
                values.push(edge);
                values.push(edge.wrapping_neg());
            }
        }
        values.extend_from_slice(&[0, 1, 2, -1, i64::MIN, i64::MIN + 1, i64::MAX]);
        for file_format in [-1, 0, 1, 3, 4, 5, 100] {
            for &value in &values {
                agree(MEM_INT, value, 0, file_format);
            }
        }
    }

    #[test]
    fn integer_width_ladder_bit_sweep() {
        // A deterministic xorshift walk over the whole i64 domain,
        // dense near the sign boundary where the wrapping negate and
        // upstream's guard must agree.
        let mut state = 0x9e3779b97f4a7c15u64;
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value = state as i64;
            for file_format in [3, 4] {
                agree(MEM_INT, value, 0, file_format);
            }
        }
    }

    #[test]
    fn file_format_four_constants_only() {
        // Types 8/9 exist only for exactly 0/1 under file_format >= 4;
        // the original tests the value as (high == 0) && (low & !1) ==
        // 0, so 2 and every negative fall through to the ladder.
        assert_eq!(classify(MEM_INT, 0, 0, 4), 8);
        assert_eq!(classify(MEM_INT, 1, 0, 4), 9);
        assert_eq!(classify(MEM_INT, 0, 0, 3), 1);
        assert_eq!(classify(MEM_INT, 1, 0, 3), 1);
        assert_eq!(classify(MEM_INT, 2, 0, 4), 1);
    }

    #[test]
    fn real_beats_the_string_blob_tail() {
        for file_format in [-1, 0, 3, 4] {
            for extra in [0, MEM_STR, MEM_BLOB, MEM_ZERO] {
                agree(MEM_REAL | extra, 0, 7, file_format);
            }
        }
    }

    #[test]
    fn string_blob_tail_formula() {
        let flag_sets = [MEM_STR, MEM_BLOB, MEM_STR | MEM_ZERO, MEM_BLOB | MEM_ZERO];
        let lengths = [0u32, 1, 2, 5, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff];
        let zero_tails = [0u32, 1, 4, 0xffff_fffe, 0xffff_ffff];
        for file_format in [-1, 4] {
            for flags in flag_sets {
                for &n in &lengths {
                    for &zero_tail in &zero_tails {
                        agree(flags, zero_tail as i64, n, file_format);
                    }
                }
            }
        }
    }

    #[test]
    fn int_dominates_real_and_string_bits() {
        // The original's tst order is NULL, INT, REAL, tail: an Int
        // flag decides the type no matter what else is set.
        for extra in [MEM_REAL, MEM_STR, MEM_BLOB | MEM_ZERO] {
            agree(MEM_INT | extra, 300, 11, 4);
        }
    }
}
