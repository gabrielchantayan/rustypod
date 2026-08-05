//! The 64-bit b-tree varint decoder — SQLite 3.5.x's full-width
//! `sqlite3GetVarint`, the routine behind every rowid (table b-tree
//! nKey) read and the tail of the truncating u32 getter.
//!
//! `get_varint64` — original: `FUN_0837aab0` @ 0x0837aab0 (380 bytes;
//! 3 `bl` call sites: 0x08372008 [FUN_08371e54, which reads the result
//! back with `ldrd r0,r1,[sp,#0x8]` — a full u64], 0x08372858 [the
//! ported `btree_parse_cell_ptr`'s rowid read, out-pointer =
//! CellInfo+0x08 so the high word lands at +0x0c], 0x0837ace0 [the
//! tail call from the ported `get_varint` @ 0x0837ac30, which keeps
//! only the low word]).
//!
//! ```c
//! u8 sqlite3GetVarint(const u8 *p, u64 *v);  // out-param per the asm stores
//! ```
//!
//! Naming caveat (inversion vs upstream): the repo's established names
//! attach upstream's `sqlite3GetVarint` to 0x0837ac30, whose original
//! out-param is a u32 (single `str` per case — upstream's
//! `sqlite3GetVarint32` role), while THIS function writes a u64
//! (paired lo/hi stores at [r1,#0]/[r1,#4] in every exit — upstream's
//! `sqlite3GetVarint` role). Consistent with the sibling
//! `sqlite/get_varint.rs`, this port is therefore `get_varint64`; the
//! [`BTREE_CELL_OPS`] seam slot it ships as the default of keeps its
//! established (upstream-inverted) name `get_varint32`. The
//! slot-to-address mapping is correct either way.
//!
//! Algorithm (verified instruction-by-instruction against osos.asm;
//! the sibling's [`crate::sqlite::get_varint`] header documents the
//! same cascade from its tail's perspective): SQLite's big-endian
//! base-128 varint, cases unrolled shortest-first with the length
//! returned. Unlike 0x0837ac30 there IS a one-byte case (p[0]'s high
//! bit clear: v = p[0], length 1) — the parse_cell rowid read has no
//! inline fast path and calls here for every rowid. Each case k reads
//! exactly p[0..k], testing p[k-1]'s continuation bit:
//!
//! 1. Cases 1..=8 accumulate 7-bit groups most-significant first:
//!    `v = (v << 7) | (p[i] & 0x7f)`. The original computes this in a
//!    u32 lo/hi register pair (literal pool @ 0x0837ac2c = 0x001FC07F,
//!    the same PAIR_MASK as the sibling's pool @ 0x0837acf0; `bic`
//!    pairs 0x0FE00000/0x3F80 strip continuation bits out of shifted
//!    accumulators); its paired stores equal
//!    `(v as u32, (v >> 32) as u32)` of the plain u64 accumulation
//!    here for every case — the masks drop exactly the bits the group
//!    accumulation never sets, and the bits a 7-bit group would place
//!    above bit 31 fall off the 32-bit store identically (checked for
//!    the 5/7/8-byte cases, where the sibling's decode_tail shares
//!    this function's shifts).
//! 2. The 9th byte (p[0..=7] all carry the continuation bit)
//!    contributes all 8 bits: `v = (v << 8) | p[8]`. The original
//!    re-reads p[4] (`ldrb r2,[r2,#-0x4]`) to rebuild the high word's
//!    top group; same value.
//!
//! So unlike the u32 sibling (5-byte varints truncate to the low
//! word), this function returns the FULL value at every length: hi =
//! v >> 32 from the 5-byte case up.
//!
//! Deviations: none in behavior. The unrolled cascade is written as
//! plain u64 group accumulation (see case 1 above) rather than the
//! original's paired-u32 shift/mask machinery; the two are bit-exact.

/// get_varint64 — original: `FUN_0837aab0` @ 0x0837aab0 (380 bytes;
/// 3 `bl` call sites).
///
/// SQLite's full-width `sqlite3GetVarint`: decode the varint at `p`
/// into `out`, returning the number of bytes consumed (1..=9). Handles
/// the one-byte case itself (the rowid call site has no inline fast
/// path); the 9th byte contributes all 8 bits.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn get_varint64(p: *const u8, out: *mut u64) -> u32 {
    let b0 = *p;
    if b0 & 0x80 == 0 {
        *out = b0 as u64;
        return 1;
    }
    let mut v = (b0 & 0x7f) as u64;
    let b1 = *p.add(1);
    if b1 & 0x80 == 0 {
        *out = v << 7 | b1 as u64;
        return 2;
    }
    v = v << 7 | (b1 & 0x7f) as u64;
    let b2 = *p.add(2);
    if b2 & 0x80 == 0 {
        *out = v << 7 | b2 as u64;
        return 3;
    }
    v = v << 7 | (b2 & 0x7f) as u64;
    let b3 = *p.add(3);
    if b3 & 0x80 == 0 {
        *out = v << 7 | b3 as u64;
        return 4;
    }
    v = v << 7 | (b3 & 0x7f) as u64;
    let b4 = *p.add(4);
    if b4 & 0x80 == 0 {
        *out = v << 7 | b4 as u64;
        return 5;
    }
    v = v << 7 | (b4 & 0x7f) as u64;
    let b5 = *p.add(5);
    if b5 & 0x80 == 0 {
        *out = v << 7 | b5 as u64;
        return 6;
    }
    v = v << 7 | (b5 & 0x7f) as u64;
    let b6 = *p.add(6);
    if b6 & 0x80 == 0 {
        *out = v << 7 | b6 as u64;
        return 7;
    }
    v = v << 7 | (b6 & 0x7f) as u64;
    let b7 = *p.add(7);
    if b7 & 0x80 == 0 {
        *out = v << 7 | b7 as u64;
        return 8;
    }
    v = v << 7 | (b7 & 0x7f) as u64;
    // The 9th byte contributes all 8 bits, high bit included.
    *out = v << 8 | *p.add(8) as u64;
    9
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::cell_size::{get_varint32_op, BTREE_CELL_OPS};
    use crate::testing::BTREE_CELL_TEST_LOCK;
    use std::vec::Vec;

    /// Reference encoder: SQLite's canonical `sqlite3PutVarint` —
    /// 7-bit groups, most significant first, continuation bit on all
    /// but the last; values >= 2^56 take 9 bytes with the 9th byte
    /// contributing all 8 bits.
    fn put_varint(v: u64) -> ([u8; 9], usize) {
        let mut buf = [0u8; 9];
        if v >= (1 << 56) {
            let mut x = v >> 8;
            for i in (0..8).rev() {
                buf[i] = (x as u8 & 0x7f) | 0x80;
                x >>= 7;
            }
            buf[8] = v as u8;
            (buf, 9)
        } else {
            let mut tmp = [0u8; 8];
            let mut n = 0;
            let mut x = v;
            loop {
                tmp[n] = (x & 0x7f) as u8;
                x >>= 7;
                n += 1;
                if x == 0 {
                    break;
                }
            }
            for i in 0..n {
                buf[i] = tmp[n - 1 - i] | if i + 1 < n { 0x80 } else { 0 };
            }
            (buf, n)
        }
    }

    /// Smallest and largest values encoding to each length.
    fn length_bounds(len: usize) -> (u64, u64) {
        let min = if len == 1 { 0 } else { 1u64 << (7 * (len - 1)) };
        let max = if len == 9 { u64::MAX } else { (1u64 << (7 * len)) - 1 };
        (min, max)
    }

    /// Deterministic xorshift64* for the sweep.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    /// Values that must encode to `len`: the bounds, the boundary
    /// list, and a pseudo-random sweep inside the range.
    fn values_for_length(len: usize) -> Vec<u64> {
        let (min, max) = length_bounds(len);
        let mut vs = std::vec![min, max];
        for &b in [0u64, 0x7f, 0x80, 0x3fff, 0x4000, u32::MAX as u64, u64::MAX].iter() {
            if b >= min && b <= max {
                vs.push(b);
            }
        }
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ len as u64);
        for _ in 0..64 {
            vs.push(min | (rng.next() & (max - min)));
        }
        vs
    }

    #[test]
    fn round_trips_every_encoded_length_against_the_reference_encoder() {
        for len in 1..=9usize {
            for v in values_for_length(len) {
                let (enc, n) = put_varint(v);
                assert_eq!(n, len, "encoder length for {v:#x}");
                // Unlike the u32 sibling, the export decodes every
                // length itself (one-byte case included) and never
                // truncates: the full u64 round-trips.
                let mut out = u64::MAX;
                let got = unsafe { get_varint64(enc.as_ptr(), &mut out) };
                assert_eq!((out, got), (v, len as u32), "decode of {v:#x}");
            }
        }
    }

    #[test]
    fn one_byte_varints_decode_in_the_export() {
        // The rowid call site has no inline fast path: 0 and 0x7f —
        // the boundary values the u32 sibling's callers keep inline —
        // reach this export directly.
        for v in 0u64..0x80 {
            let (enc, n) = put_varint(v);
            assert_eq!(n, 1);
            assert_eq!(enc[0], v as u8);
            let mut out = u64::MAX;
            assert_eq!(unsafe { get_varint64(enc.as_ptr(), &mut out) }, 1);
            assert_eq!(out, v);
        }
    }

    #[test]
    fn boundary_values() {
        let cases: &[(u64, u32)] = &[
            (0, 1),
            (0x7f, 1),
            (0x80, 2),
            (0x3fff, 2),
            (0x4000, 3),
            (u32::MAX as u64, 5),
            (u32::MAX as u64 + 1, 5),
            (u64::MAX, 9),
        ];
        for &(v, len) in cases {
            let (enc, n) = put_varint(v);
            assert_eq!(n as u32, len, "encoder length for {v:#x}");
            let mut out = u64::MAX;
            let got = unsafe { get_varint64(enc.as_ptr(), &mut out) };
            assert_eq!((out, got), (v, len), "decode of {v:#x}");
        }
    }

    #[test]
    fn five_byte_varints_keep_the_full_value_unlike_the_u32_sibling() {
        // 35-bit maximum 5-byte value: the u32 sibling truncates this
        // to its low word; the original's paired stores keep hi =
        // v >> 32 = 0x7.
        let v = (1u64 << 35) - 1;
        let (enc, n) = put_varint(v);
        assert_eq!(n, 5);
        let mut out = 0;
        assert_eq!(unsafe { get_varint64(enc.as_ptr(), &mut out) }, 5);
        assert_eq!(out, v, "hi word 0x7 survives");
        // 2^32 encodes to 5 bytes and must NOT truncate to 0.
        let (enc, n) = put_varint(1u64 << 32);
        assert_eq!(n, 5);
        let mut out = 0;
        assert_eq!(unsafe { get_varint64(enc.as_ptr(), &mut out) }, 5);
        assert_eq!(out, 1u64 << 32);
    }

    #[test]
    fn ninth_byte_contributes_all_eight_bits() {
        // u64::MAX: all eight 7-bit groups plus a 0xFF ninth byte.
        let (enc, n) = put_varint(u64::MAX);
        assert_eq!(n, 9);
        assert_eq!(enc, [0xff; 9], "max encoding sets the 9th byte's high bit");
        let mut out = 0;
        assert_eq!(unsafe { get_varint64(enc.as_ptr(), &mut out) }, 9);
        assert_eq!(out, u64::MAX);
        // A ninth byte of exactly 0x80 (high bit set, low bits clear).
        let v = 0x0100_0000_0000_0080u64;
        let (enc, n) = put_varint(v);
        assert_eq!(n, 9);
        assert_eq!(enc[8], 0x80);
        let mut out = 0;
        assert_eq!(unsafe { get_varint64(enc.as_ptr(), &mut out) }, 9);
        assert_eq!(out, v);
    }

    #[test]
    fn bytes_consumed_stops_at_the_first_clean_high_bit() {
        // Trailing continuation-bit garbage past the varint must not
        // be consumed.
        for len in 1..=9usize {
            let (min, _) = length_bounds(len);
            let (enc, n) = put_varint(min);
            assert_eq!(n, len);
            let mut buf = [0x80u8; 16];
            buf[..len].copy_from_slice(&enc[..len]);
            // For a 9-byte varint the 9th byte is 0x80 — which the
            // decoder takes whole, so the run of 0x80s is unambiguous.
            let mut out = 0;
            let got = unsafe { get_varint64(buf.as_ptr(), &mut out) };
            assert_eq!(got, len as u32, "length with trailing garbage");
            assert_eq!(out, min, "value with trailing garbage");
        }
    }

    #[test]
    fn reads_no_byte_past_the_varint_end() {
        extern "C" {
            fn mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, offset: i64)
                -> usize;
            fn mprotect(addr: usize, len: usize, prot: i32) -> i32;
        }
        #[cfg(target_os = "macos")]
        const MAP_PRIVATE_ANON: i32 = 0x1002;
        #[cfg(target_os = "linux")]
        const MAP_PRIVATE_ANON: i32 = 0x22;
        const PROT_READ_WRITE: i32 = 3;
        const PROT_NONE: i32 = 0;
        const PAGE: usize = 0x1000;

        unsafe {
            let base = mmap(0, 2 * PAGE, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0);
            assert_ne!(base, usize::MAX, "mmap failed");
            assert_eq!(mprotect(base + PAGE, PAGE, PROT_NONE), 0, "mprotect failed");
            for len in 1..=9usize {
                let (min, max) = length_bounds(len);
                for v in [min, max] {
                    let (enc, n) = put_varint(v);
                    assert_eq!(n, len);
                    // End the encoding exactly at the guard page: any
                    // read past the varint faults.
                    let start = (base + PAGE - n) as *mut u8;
                    core::ptr::copy_nonoverlapping(enc.as_ptr(), start, n);
                    let mut out = 0;
                    let got = get_varint64(start as *const u8, &mut out);
                    assert_eq!((out, got), (v, len as u32), "guarded decode of {v:#x}");
                }
            }
        }
    }

    #[test]
    fn shipped_seam_default_is_this_port() {
        let _guard = BTREE_CELL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            assert_eq!(
                get_varint32_op() as usize,
                get_varint64 as *const () as usize,
                "the shipped get_varint32 slot is this port"
            );
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CELL_OPS.get_varint32))
                    as usize,
                get_varint64 as *const () as usize
            );
        }
    }
}
