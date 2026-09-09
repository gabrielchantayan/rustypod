//! OpenSSL's `BN_ucmp` — the unsigned magnitude comparison of two
//! `BIGNUM`s in the OpenSSL copy Apple vendored into retailOS (the
//! bignum cluster 0x0803d800..0x08041000 documented in
//! [`crate::crypto::bn_num_bits`]).
//!
//! Port: `bn_ucmp` — `FUN_08040ddc` @ 0x08040ddc (88 bytes,
//! 0x08040ddc..0x08040e34; **15 call sites**, binary-verified by
//! decoding every ARM B/BL word in osos.dec: all 15 are unconditional
//! `bl` (cond 0xe) — no predicated forms, so no caller NULL-guards or
//! flag-gates this entry point. No DATA word in the image holds the
//! address, so it is never dispatched virtually).
//!
//! # Decoded from the raw ARM at 0x08040ddc
//!
//! ```text
//! ldr   r2, [r0, #4]        ; r2 = a->top
//! ldr   r3, [r1, #4]        ; r3 = b->top
//! subs  r3, r2, r3
//! movne r0, r3              ; tops differ -> return the RAW difference
//! bxne  lr
//! ldr   r3, [r0]            ; r3 = a->d
//! ldr   ip, [r1]            ; ip = b->d
//! sub   r0, r2, #1          ; i = top - 1
//! b     check
//! loop:
//! ldr   r1, [r3, r0, lsl #2]  ; wa = a->d[i]
//! ldr   r2, [ip, r0, lsl #2]  ; wb = b->d[i]
//! cmp   r1, r2
//! beq   next
//! cmp   r1, r2
//! mvnls r0, #0              ; wa < wb (unsigned ls) -> -1
//! movhi r0, #1              ; wa > wb (unsigned hi) -> +1
//! bx    lr
//! next:
//! sub   r0, r0, #1
//! check:
//! cmp   r0, #0
//! bge   loop                ; while i >= 0
//! mov   r0, #0              ; all limbs equal -> 0
//! bx    lr
//! ```
//!
//! Twenty-two words, no literal pool; the next entry @ 0x08040e34 is
//! a separately linked function with its own `push {r3-r9, lr}`
//! prologue and callers, so Ghidra's 88-byte extent is exactly right.
//! Upstream crypto/bn/bn_lib.c: `int BN_ucmp(const BIGNUM *a,
//! const BIGNUM *b) { i = a->top - b->top; if (i != 0) return i;
//! for (i = a->top - 1; i >= 0; i--) { t1 = ap[i]; t2 = bp[i];
//! if (t1 != t2) return (t1 > t2) ? 1 : -1; } return 0; }` — the
//! `bn_check_top` asserts are compiled out.
//!
//! # Semantics worth pinning
//!
//! - The length mismatch return is the RAW signed difference
//!   `a->top - b->top` (e.g. 5 or -3), not a normalized sign. Callers
//!   in the cluster test it with `< 0` / `>= 0` (e.g. the caller @
//!   0x0803f5c4 requires `>= 0`), so the magnitude is dead weight —
//!   but the port keeps it bit-exact anyway.
//! - Limb comparison is UNSIGNED (`ls`/`hi`), magnitude only; the
//!   `neg` word @ +0x0c is never read (that is what the `u` in
//!   `BN_ucmp` means — `BN_cmp` @ 0x08040d68 handles signs first).
//! - Limbs are scanned most-significant first (`i = top - 1` down to
//!   0), so the FIRST difference found decides; lower differing limbs
//!   are never read.
//! - `top == 0` on both sides (or any equal `top <= 0`) returns 0
//!   without dereferencing `d` — the loop guard rejects `i = -1`.
//!
//! # Deviations
//!
//! None. Index arithmetic is `wrapping_*` so a bogus negative `top`
//! cannot trip host overflow checks; on target the wrapping ops are
//! the same single `sub` the original emits.

use super::bn_num_bits::BigNum;

/// bn_ucmp — original: `FUN_08040ddc` @ 0x08040ddc (88 bytes; 15 call
/// sites, all unconditional `bl` — binary-verified).
///
/// OpenSSL `BN_ucmp`: if the limb counts differ, return the raw
/// signed difference `a->top - b->top`; otherwise compare limb arrays
/// most-significant first as unsigned words, returning 1 / -1 at the
/// first difference, 0 when equal. Nothing is validated: a NULL `a`
/// or `b` faults exactly as in the original, and no caller gates the
/// call (all 15 sites are unconditional).
///
/// # Safety
///
/// `a` and `b` must name live [`BigNum`]s whose `d` buffers each hold
/// at least `top` readable limbs (never dereferenced when the tops
/// differ or are both <= 0).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_ucmp(a: *const BigNum, b: *const BigNum) -> i32 {
    let top = (*a).top;
    let top_diff = top.wrapping_sub((*b).top);
    if top_diff != 0 {
        return top_diff;
    }
    let ap = (*a).d;
    let bp = (*b).d;
    let mut i = top.wrapping_sub(1);
    while i >= 0 {
        let wa = ap.wrapping_add(i as usize).read();
        let wb = bp.wrapping_add(i as usize).read();
        if wa != wb {
            return if wa > wb { 1 } else { -1 };
        }
        i = i.wrapping_sub(1);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    fn bignum(d: *const u32, top: i32) -> BigNum {
        BigNum { d, top, dmax: top, neg: 0, flags: 0 }
    }

    /// Textbook `BN_ucmp` (bn_lib.c) on plain slices, the reference
    /// the port is compared against.
    fn reference_ucmp(a: &[u32], b: &[u32]) -> i32 {
        let diff = a.len() as i32 - b.len() as i32;
        if diff != 0 {
            return diff;
        }
        for i in (0..a.len()).rev() {
            if a[i] != b[i] {
                return if a[i] > b[i] { 1 } else { -1 };
            }
        }
        0
    }

    #[test]
    fn differing_tops_return_the_raw_signed_difference() {
        // Not a normalized sign: the original's `subs/movne/bxne`
        // hands back `top_a - top_b` verbatim.
        let la = [1u32, 2, 3, 4, 5];
        let lb = [9u32, 9];
        let a = bignum(la.as_ptr(), 5);
        let b = bignum(lb.as_ptr(), 2);
        assert_eq!(unsafe { bn_ucmp(&a, &b) }, 3);
        assert_eq!(unsafe { bn_ucmp(&b, &a) }, -3);

        // One limb vs none.
        let a = bignum(la.as_ptr(), 1);
        let b = bignum(core::ptr::null(), 0);
        assert_eq!(unsafe { bn_ucmp(&a, &b) }, 1);
        assert_eq!(unsafe { bn_ucmp(&b, &a) }, -1);
    }

    #[test]
    fn both_zero_top_are_equal_without_dereferencing_limbs() {
        // i = top - 1 = -1 fails the `bge` guard before any limb
        // load, so NULL limb buffers are fine.
        let a = bignum(core::ptr::null(), 0);
        let b = bignum(core::ptr::null(), 0);
        assert_eq!(unsafe { bn_ucmp(&a, &b) }, 0);

        // Any equal top <= 0 short-circuits the same way.
        let a = bignum(core::ptr::null(), -2);
        let b = bignum(core::ptr::null(), -2);
        assert_eq!(unsafe { bn_ucmp(&a, &b) }, 0);
    }

    #[test]
    fn the_most_significant_difference_decides() {
        // Scan runs top-1 ..= 0: the highest differing limb wins even
        // when a lower limb disagrees the other way.
        let la = [0xffff_ffffu32, 0, 1]; // low limb says "greater"
        let lb = [0u32, 0, 2]; //         top limb says "less"
        let a = bignum(la.as_ptr(), 3);
        let b = bignum(lb.as_ptr(), 3);
        assert_eq!(unsafe { bn_ucmp(&a, &b) }, -1);
        assert_eq!(unsafe { bn_ucmp(&b, &a) }, 1);
    }

    #[test]
    fn a_difference_in_the_least_significant_limb_is_found() {
        // The scan must walk all the way to index 0.
        let la = [1u32, 7, 7, 7];
        let lb = [2u32, 7, 7, 7];
        let a = bignum(la.as_ptr(), 4);
        let b = bignum(lb.as_ptr(), 4);
        assert_eq!(unsafe { bn_ucmp(&a, &b) }, -1);
        assert_eq!(unsafe { bn_ucmp(&b, &a) }, 1);
    }

    #[test]
    fn limb_comparison_is_unsigned() {
        // `mvnls/movhi` are the unsigned condition codes: 0x80000000
        // is GREATER than 0x7fffffff, sign bits are magnitude.
        let la = [0x8000_0000u32];
        let lb = [0x7fff_ffffu32];
        let a = bignum(la.as_ptr(), 1);
        let b = bignum(lb.as_ptr(), 1);
        assert_eq!(unsafe { bn_ucmp(&a, &b) }, 1);
        assert_eq!(unsafe { bn_ucmp(&b, &a) }, -1);

        let la = [0xffff_ffffu32];
        let lb = [0u32];
        let a = bignum(la.as_ptr(), 1);
        let b = bignum(lb.as_ptr(), 1);
        assert_eq!(unsafe { bn_ucmp(&a, &b) }, 1);
    }

    #[test]
    fn identical_bignums_compare_equal() {
        let limbs = [0xdead_beefu32, 0x1234_5678, 0x0000_0001];
        let a = bignum(limbs.as_ptr(), 3);
        let b = bignum(limbs.as_ptr(), 3);
        assert_eq!(unsafe { bn_ucmp(&a, &b) }, 0);
    }

    #[test]
    fn matches_the_reference_on_exhaustive_small_cases() {
        // Deterministic xorshift; every length pairing 0..=4 and a
        // spread of limb patterns, compared against textbook BN_ucmp.
        let mut state = 0x1234_5678u32;
        let mut rand = move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        for _ in 0..500 {
            let la: Vec<u32> = (0..(rand() % 5)).map(|_| rand()).collect();
            let mut lb = la.clone();
            match rand() % 3 {
                0 => {
                    // Same length, maybe tweak one limb.
                    if !lb.is_empty() {
                        let i = (rand() as usize) % lb.len();
                        lb[i] = lb[i].wrapping_add(rand() | 1);
                    }
                }
                1 => {
                    // Different length.
                    lb.push(rand());
                }
                _ => {}
            }
            let a = bignum(la.as_ptr(), la.len() as i32);
            let b = bignum(lb.as_ptr(), lb.len() as i32);
            assert_eq!(
                unsafe { bn_ucmp(&a, &b) },
                reference_ucmp(&la, &lb),
                "a={la:?} b={lb:?}"
            );
        }
    }
}
