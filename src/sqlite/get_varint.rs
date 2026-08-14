//! The b-tree varint decoder — SQLite 3.5.x's `sqlite3GetVarint`, the
//! reader every payload-size and key-length decode in the b-tree and
//! VDBE record layers funnels into.
//!
//! `get_varint` — original: `FUN_0837ac30` @ 0x0837ac30 (192 bytes;
//! 13 `bl` call sites: 0x08371ff8 [FUN_08371e54], 0x08372834 and
//! 0x08372880 [the ported `btree_parse_cell_ptr`], 0x083882e0 and
//! 0x083883a4 [FUN_08386ef8], 0x0838b504/0x0838b52c [FUN_0838b478],
//! 0x0838b590/0x0838b5b4 [FUN_0838b570], 0x0838c8d0/0x0838c900
//! [FUN_0838c87c], 0x0838ca78/0x0838caa8 [FUN_0838c9f0]).
//!
//! ```c
//! u8 sqlite3GetVarint(const u8 *p, u32 *v);  // out-param per the asm stores
//! ```
//!
//! Algorithm (verified instruction-by-instruction against osos.asm —
//! Ghidra's decompile invents `param_3`/`param_4` from the untouched
//! stack slots the tail call reuses): SQLite's big-endian base-128
//! varint, cases unrolled shortest-first with the length returned:
//!
//! 1. There is NO one-byte case. The function reads p[0] and p[1]
//!    unconditionally and tests p[1]'s high bit; a first byte below
//!    0x80 would be misdecoded. Every one of the 13 call sites guards
//!    the call with `cmp r0,#0x80; bcc` and keeps the single byte
//!    inline (value = byte, length 1), so the export's contract —
//!    like the original's — is "p[0] has the continuation bit set".
//! 2. Two bytes: `v = p[1] | (p[0]&0x7f)<<7`.
//! 3. Three bytes: with `a = p[2] | p[0]<<14`,
//!    `v = (a & 0x1FC07F) | (p[1]&0x7f)<<7`. The mask is the literal
//!    pool entry @ 0x0837acf0 — `(0x7f<<14)|0x7f`, confirmed against
//!    osos.dec (0x001fc07f).
//! 4. Four bytes: with `b = p[3] | p[1]<<14`,
//!    `v = (b & 0x1FC07F) | ((a & 0x1FC07F) << 7)`.
//! 5. Five bytes: with `c = p[4] | a<<14`,
//!    `v = (c & ~0x0FE00000 & ~0x3F80) | ((b & ~0x0FE00000 & ~0x3F80) << 7)`
//!    — the two `bic` pairs strip each raw byte's continuation bit out
//!    of the shifted accumulators. The top group's bits above the low
//!    32 are shifted out: the original's out-param is a u32, so a
//!    5-byte varint (35 bits) keeps only its low word.
//! 6. Six or more (p[4]'s high bit set): the original rewinds to p
//!    (`sub r0,r1,#0x4`) and tail-calls the 64-bit decoder @
//!    0x0837aab0 (identified — the u64 counterpart of this routine,
//!    with the 1..=9-byte cascade including the one-byte fast path),
//!    then copies only the LOW word of the callee's stack u64 into the
//!    out-param and returns the callee's byte count. 0x0837aab0 is now
//!    ported (`sqlite/get_varint64.rs`); [`decode_tail`] still inlines
//!    the equivalent decode rather than calling it, verified
//!    group-by-group against its disassembly (the 7-bit
//!    accumulation is exact; the 9th byte contributes all 8 bits,
//!    `v = (v<<8) | p[8]` — the path Ghidra's decompile of that
//!    function mangles).
//!
//! Deviations:
//!
//! - The original's out-param is a u32; the [`BTREE_CELL_OPS`] seam
//!   slot this export ships as the default of is `*mut u64` (house
//!   model from `sqlite/parse_cell.rs`, whose caller truncates the
//!   slot's result with `as u32` exactly like the original's u32
//!   store). The port therefore writes hi = 0 for the 2..=5-byte
//!   cases (bit-identical to the original's zero-extended u32 store,
//!   including the 5-byte truncation) and the FULL u64 for the 6..=9
//!   tail — the value the original computed in its callee and then
//!   discarded the high word of. The low word is bit-identical to the
//!   original in every case.
//! - 0x0837aab0's tail semantics are inlined in [`decode_tail`] rather
//!   than called; that function has since been ported
//!   (`sqlite/get_varint64.rs`) and both bodies decode identically.

/// Literal pool entry @ 0x0837acf0 (and @ 0x0837ac2c in the u64
/// counterpart): keeps the low 7 bits of the first and third byte of a
/// shifted pair — `(0x7f << 14) | 0x7f`.
const PAIR_MASK: u32 = 0x001F_C07F;

/// Continuation-bit strippers of the 5-byte case (`bic` immediates in
/// the original): bit 7 of each raw byte lands at bit 7/21 of the
/// shifted accumulators, so 0x0FE0_0000 (bits 21..=27) and 0x3F80
/// (bits 7..=13) clear exactly those.
const STRIP_HI: u32 = 0x0FE0_0000;
const STRIP_LO: u32 = 0x3F80;

/// The original's tail: 6..=9-byte varints, decoded as the 64-bit
/// reader @ 0x0837aab0 decodes them. Entered only when p[0..=4] all
/// carry the continuation bit, so the cascade starts at the sixth
/// byte. 7-bit groups accumulate big-endian; the 9th byte contributes
/// all 8 bits. Hand-verified against 0x0837aab0's u32-pair shifts: its
/// lo/hi stores equal `(v as u32, (v >> 32) as u32)` of this value for
/// every length (the `and`/`bic` masks there drop exactly the bits the
/// group accumulation here never sets).
#[inline(always)]
unsafe fn decode_tail(p: *const u8) -> (u64, u32) {
    let g = |i: usize| (*p.add(i) & 0x7f) as u64;
    let mut v = g(0) << 28 | g(1) << 21 | g(2) << 14 | g(3) << 7 | g(4);
    let b5 = *p.add(5);
    if b5 & 0x80 == 0 {
        return (v << 7 | b5 as u64, 6);
    }
    v = v << 7 | (b5 & 0x7f) as u64;
    let b6 = *p.add(6);
    if b6 & 0x80 == 0 {
        return (v << 7 | b6 as u64, 7);
    }
    v = v << 7 | (b6 & 0x7f) as u64;
    let b7 = *p.add(7);
    if b7 & 0x80 == 0 {
        return (v << 7 | b7 as u64, 8);
    }
    v = v << 7 | (b7 & 0x7f) as u64;
    (v << 8 | *p.add(8) as u64, 9)
}

/// get_varint — original: `FUN_0837ac30` @ 0x0837ac30 (192 bytes;
/// 13 `bl` call sites).
///
/// SQLite's `sqlite3GetVarint`: decode the multi-byte varint at `p`
/// (the caller has already seen p[0]'s continuation bit set — see the
/// module header) into `out`, returning the number of bytes consumed
/// (2..=9). The seam-slot out-param is u64; see the module header for
/// what the high word holds per case.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn get_varint(p: *const u8, out: *mut u64) -> u32 {
    let b0 = *p as u32;
    let b1 = *p.add(1) as u32;
    if b1 & 0x80 == 0 {
        *out = (b1 | (b0 & 0x7f) << 7) as u64;
        return 2;
    }
    let a = *p.add(2) as u32 | b0 << 14;
    if a & 0x80 == 0 {
        *out = ((a & PAIR_MASK) | (b1 & 0x7f) << 7) as u64;
        return 3;
    }
    let b = *p.add(3) as u32 | b1 << 14;
    if b & 0x80 == 0 {
        *out = ((b & PAIR_MASK) | (a & PAIR_MASK) << 7) as u64;
        return 4;
    }
    let c = *p.add(4) as u32 | a << 14;
    if c & 0x80 == 0 {
        let lo = c & !STRIP_HI & !STRIP_LO;
        let hi = b & !STRIP_HI & !STRIP_LO;
        *out = (lo | hi << 7) as u64;
        return 5;
    }
    let (v, n) = decode_tail(p);
    *out = v;
    n
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::cell_size::{get_varint_op, BTREE_CELL_OPS};
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

    /// The firmware's caller pattern (all 13 call sites, mirrored by
    /// `sqlite/parse_cell.rs`'s `read_varint_fast`): a first byte below
    /// 0x80 is the whole varint; only multi-byte varints reach the
    /// export. Returns the value exactly as the caller sees it — the
    /// low word of the seam slot's u64.
    unsafe fn caller_decode(p: *const u8) -> (u64, u32) {
        let first = *p;
        if first < 0x80 {
            (first as u64, 1)
        } else {
            let mut value = 0u64;
            let len = get_varint(p, &mut value);
            ((value as u32) as u64, len)
        }
    }

    /// What the export must produce for an encoded value of length
    /// `len`: exact for every length except 5-byte varints, whose top
    /// group's bits above the low 32 are shifted out by the original's
    /// u32 out-param (module header, case 5).
    fn expected_direct(v: u64, len: usize) -> u64 {
        if len == 5 { (v as u32) as u64 } else { v }
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
                // Through the firmware's caller pattern (the only way
                // the original is ever invoked), every length
                // round-trips, u32-truncated from 5 bytes up exactly
                // like the original's out-param.
                let (value, got) = unsafe { caller_decode(enc.as_ptr()) };
                let want = if len >= 5 { (v as u32) as u64 } else { v };
                assert_eq!((value, got), (want, len as u32), "caller decode of {v:#x}");
            }
        }
    }

    #[test]
    fn decodes_two_through_nine_byte_varints_directly() {
        for len in 2..=9usize {
            for v in values_for_length(len) {
                let (enc, n) = put_varint(v);
                assert_eq!(n, len);
                let mut out = u64::MAX;
                let got = unsafe { get_varint(enc.as_ptr(), &mut out) };
                assert_eq!(got, len as u32, "length of {v:#x}");
                assert_eq!(out, expected_direct(v, len), "value of {v:#x}");
            }
        }
    }

    #[test]
    fn one_byte_varints_are_the_callers_inline_fast_path() {
        // 0 and 0x7f are the boundary values whose encoding never
        // reaches the export: the caller keeps them inline.
        for v in 0u64..0x80 {
            let (enc, n) = put_varint(v);
            assert_eq!(n, 1);
            assert_eq!(enc[0], v as u8);
            assert_eq!(unsafe { caller_decode(enc.as_ptr()) }, (v, 1));
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
            (u64::MAX, 9),
        ];
        for &(v, len) in cases {
            let (enc, n) = put_varint(v);
            assert_eq!(n as u32, len, "encoder length for {v:#x}");
            let (value, got) = unsafe { caller_decode(enc.as_ptr()) };
            assert_eq!(got, len, "length for {v:#x}");
            let want = if len >= 5 { (v as u32) as u64 } else { v };
            assert_eq!(value, want, "value for {v:#x}");
        }
    }

    #[test]
    fn ninth_byte_contributes_all_eight_bits() {
        // u64::MAX: all eight 7-bit groups plus a 0xFF ninth byte.
        let (enc, n) = put_varint(u64::MAX);
        assert_eq!(n, 9);
        assert_eq!(enc, [0xff; 9], "max encoding sets the 9th byte's high bit");
        let mut out = 0;
        assert_eq!(unsafe { get_varint(enc.as_ptr(), &mut out) }, 9);
        assert_eq!(out, u64::MAX);
        // A ninth byte of exactly 0x80 (high bit set, low bits clear).
        let v = 0x0100_0000_0000_0080u64;
        let (enc, n) = put_varint(v);
        assert_eq!(n, 9);
        assert_eq!(enc[8], 0x80);
        let mut out = 0;
        assert_eq!(unsafe { get_varint(enc.as_ptr(), &mut out) }, 9);
        assert_eq!(out, v);
    }

    #[test]
    fn five_byte_varints_keep_only_the_low_word_like_the_original() {
        // 35-bit maximum 5-byte value: the original's u32 out-param
        // shifts the top group's high bits out.
        let v = (1u64 << 35) - 1;
        let (enc, n) = put_varint(v);
        assert_eq!(n, 5);
        let mut out = u64::MAX;
        assert_eq!(unsafe { get_varint(enc.as_ptr(), &mut out) }, 5);
        assert_eq!(out, u32::MAX as u64, "hi word is 0, low word truncated");
        // 2^32 encodes to 5 bytes and truncates to 0.
        let (enc, n) = put_varint(1u64 << 32);
        assert_eq!(n, 5);
        let mut out = u64::MAX;
        assert_eq!(unsafe { get_varint(enc.as_ptr(), &mut out) }, 5);
        assert_eq!(out, 0);
    }

    #[test]
    fn bytes_consumed_stops_at_the_first_clean_high_bit() {
        // Trailing continuation-bit garbage past the varint must not
        // be consumed.
        for len in 2..=9usize {
            let (min, _) = length_bounds(len);
            let (enc, n) = put_varint(min);
            assert_eq!(n, len);
            let mut buf = [0x80u8; 16];
            buf[..len].copy_from_slice(&enc[..len]);
            // For a 9-byte varint the 9th byte is 0x80 — which the
            // decoder takes whole, so the run of 0x80s is unambiguous.
            let mut out = 0;
            let got = unsafe { get_varint(buf.as_ptr(), &mut out) };
            assert_eq!(got, len as u32, "length with trailing garbage");
            let (full, _) = unsafe { caller_decode(buf.as_ptr()) };
            assert_eq!(full, (out as u32) as u64);
        }
    }

    #[test]
    fn reads_no_byte_past_the_varint_end() {
        extern "C" {
            fn mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, offset: i64)
                -> usize;
            fn mprotect(addr: usize, len: usize, prot: i32) -> i32;
            // arm64 macOS uses 16 KiB pages, x86_64 Linux 4 KiB. mprotect
            // rejects an unaligned base, so a hardcoded 0x1000 silently
            // fails everywhere the page is larger.
            fn getpagesize() -> i32;
        }
        #[cfg(target_os = "macos")]
        const MAP_PRIVATE_ANON: i32 = 0x1002;
        #[cfg(target_os = "linux")]
        const MAP_PRIVATE_ANON: i32 = 0x22;
        const PROT_READ_WRITE: i32 = 3;
        const PROT_NONE: i32 = 0;

        unsafe {
            let page = getpagesize() as usize;
            let base = mmap(0, 2 * page, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0);
            assert_ne!(base, usize::MAX, "mmap failed");
            assert_eq!(mprotect(base + page, page, PROT_NONE), 0, "mprotect failed");
            for len in 1..=9usize {
                let (min, max) = length_bounds(len);
                for v in [min, max] {
                    let (enc, n) = put_varint(v);
                    assert_eq!(n, len);
                    // End the encoding exactly at the guard page: any
                    // read past the varint faults.
                    let start = (base + page - n) as *mut u8;
                    core::ptr::copy_nonoverlapping(enc.as_ptr(), start, n);
                    let (value, got) = caller_decode(start as *const u8);
                    let want = if len >= 5 { (v as u32) as u64 } else { v };
                    assert_eq!((value, got), (want, len as u32), "guarded decode of {v:#x}");
                }
            }
        }
    }

    #[test]
    fn shipped_seam_default_is_this_port() {
        let _guard = BTREE_CELL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            assert_eq!(
                get_varint_op() as usize,
                get_varint as *const () as usize,
                "the shipped get_varint slot is this port"
            );
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CELL_OPS.get_varint))
                    as usize,
                get_varint as *const () as usize
            );
        }
    }
}
