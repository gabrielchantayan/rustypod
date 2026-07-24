//! Ports of the ARM ADS 1.0.1 64-bit division runtime routines.
//!
//! - `__aeabi_uldivmod` — original: `FUN_0802eefc` @ 0x0802eefc (712 bytes).
//!   Unsigned 64/64 divide+remainder: clz-normalizes the divisor, then runs
//!   a shifting restoring division loop (the original unrolls it 8x/4x with
//!   a `add pc, pc, rX` jump table into the unrolled body). Returns the
//!   quotient in r0:r1 and the remainder in r2:r3.
//! - `__aeabi_ldivmod` — original: `FUN_0802ee34` @ 0x0802ee34 (80 bytes).
//!   Signed wrapper: computes quotient sign = sign(num) XOR sign(den) and
//!   remainder sign = sign(num) into r4 (via `asr r4, r1, #1; eor r4, r4,
//!   r3, lsr #1`), negates both operands if negative (rsbs/rsc 64-bit
//!   negates), tail-calls the unsigned core, then conditionally negates the
//!   results.
//!
//! Simplifications vs the original:
//! - The core is written as a plain normalize (`leading_zeros`) + restoring
//!   bit loop over the u64 value instead of the original's word-split,
//!   unrolled jump-table loop. Same algorithm, same results.
//! - IMPORTANT: this module must never use Rust's own `u64`/`i64` `/` or `%`
//!   operators — on ARMv5TE those lower to calls to `__aeabi_uldivmod`,
//!   i.e. straight back into this file (infinite recursion). The loop below
//!   uses only compare/subtract/shift.
//! - Divide by zero: the original branches to the ADS divide-by-zero
//!   handler (__rt_div0 path via 0x080320c4 -> 0x0803421c, which raises
//!   signal 2 through `raise`). That machinery is not ported; this port
//!   returns quotient 0, remainder 0 for `den == 0`.
//!
//! ABI note: the originals return both quotient (r0:r1) and remainder
//! (r2:r3). A Rust `extern "C" fn(...) -> u64` can only fill r0:r1, so the
//! `#[no_mangle]` entry points return the quotient only; `uldivmod_full` /
//! `ldivmod_full` expose the remainder for Rust callers.

/// Unsigned divide+remainder core: clz-normalized shifting restoring
/// division. Returns (quotient, remainder). `den == 0` yields (0, 0) —
/// see module docs for how the original handles this.
fn uldivmod_core(mut num: u64, den: u64) -> (u64, u64) {
    if den == 0 {
        return (0, 0);
    }
    if num < den {
        return (0, num);
    }
    // Normalize: shift the divisor up so its top set bit aligns with the
    // dividend's, then restore one bit per iteration.
    let shift = den.leading_zeros() - num.leading_zeros();
    let mut divisor = den << shift;
    let mut quot = 0u64;
    for _ in 0..=shift {
        quot <<= 1;
        if num >= divisor {
            num -= divisor;
            quot |= 1;
        }
        divisor >>= 1;
    }
    (quot, num)
}

/// Quotient and remainder of `num / den` (unsigned). Rust-side helper for
/// callers that need the remainder the ABI can't return.
pub fn uldivmod_full(num: u64, den: u64) -> (u64, u64) {
    uldivmod_core(num, den)
}

/// __aeabi_uldivmod — original @ 0x0802eefc.
///
/// Unsigned 64/64 division. The original returns quotient in r0:r1 and
/// remainder in r2:r3; the Rust ABI can only return one u64 (r0:r1), so
/// this returns the quotient. Use `uldivmod_full` for the remainder.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_uldivmod(num: u64, den: u64) -> u64 {
    uldivmod_core(num, den).0
}

/// Remainder-only entry point over the same core (the stock firmware has no
/// separate __aeabi_ulmod; the compiler just ignores r2:r3 when it only
/// needs the quotient). Provided for Rust callers / parity testing.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_ulmod(num: u64, den: u64) -> u64 {
    uldivmod_core(num, den).1
}

/// Quotient and remainder of `num / den` (signed, truncation toward zero,
/// remainder takes the dividend's sign — same semantics as the original
/// and as C).
pub fn ldivmod_full(num: i64, den: i64) -> (i64, i64) {
    // Mirror of the original wrapper: quotient is negative iff the operand
    // signs differ; the remainder keeps the dividend's sign.
    let quot_negative = (num < 0) != (den < 0);
    let rem_negative = num < 0;
    let (uquot, urem) = uldivmod_core(num.unsigned_abs(), den.unsigned_abs());
    let quot = if quot_negative {
        (uquot as i64).wrapping_neg()
    } else {
        uquot as i64
    };
    let rem = if rem_negative {
        (urem as i64).wrapping_neg()
    } else {
        urem as i64
    };
    (quot, rem)
}

/// __aeabi_ldivmod — original @ 0x0802ee34.
///
/// Signed 64/64 division. The original returns quotient in r0:r1 and
/// remainder in r2:r3; the Rust ABI can only return one i64 (r0:r1), so
/// this returns the quotient and the remainder is discarded. Use
/// `ldivmod_full` when both are needed.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_ldivmod(num: i64, den: i64) -> i64 {
    ldivmod_full(num, den).0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Simple reference: host 64-bit / and %. `den == 0` mirrors this
    /// module's documented (0, 0) result.
    fn ref_udivmod(num: u64, den: u64) -> (u64, u64) {
        if den == 0 {
            (0, 0)
        } else {
            (num / den, num % den)
        }
    }

    fn ref_ldivmod(num: i64, den: i64) -> (i64, i64) {
        if den == 0 {
            (0, 0)
        } else {
            (num.wrapping_div(den), num.wrapping_rem(den))
        }
    }

    fn uedge_cases() -> Vec<(u64, u64)> {
        let vals: [u64; 20] = [
            0,
            1,
            2,
            3,
            7,
            8,
            9,
            0xffff_ffff,
            0x1_0000_0000,
            0x1_0000_0001,
            1 << 31,
            1 << 32,
            1 << 63,
            u64::MAX,
            u64::MAX - 1,
            0x8000_0000_0000_0001,
            0xdead_beef_cafe_f00d,
            0x0123_4567_89ab_cdef,
            1_000_000_000_007,
            0xffff_ffff_0000_0000,
        ];
        let mut cases = Vec::new();
        for &num in &vals {
            for &den in &vals {
                cases.push((num, den));
            }
        }
        // Powers of two crossed with awkward neighbours.
        for e in 0..64 {
            let p = 1u64 << e;
            for &num in &[p, p.wrapping_sub(1), p + 1, u64::MAX] {
                for &den in &[p, p.wrapping_sub(1), p + 1] {
                    cases.push((num, den));
                }
            }
        }
        cases
    }

    #[test]
    fn uldivmod_edge_cases() {
        for (num, den) in uedge_cases() {
            let (q, r) = uldivmod_full(num, den);
            let (rq, rr) = ref_udivmod(num, den);
            assert_eq!((q, r), (rq, rr), "udivmod({num:#x}, {den:#x})");
            unsafe {
                assert_eq!(__aeabi_uldivmod(num, den), rq, "uldiv q({num:#x}, {den:#x})");
                assert_eq!(__aeabi_ulmod(num, den), rr, "ulmod r({num:#x}, {den:#x})");
            }
        }
    }

    #[test]
    fn ldivmod_edge_cases() {
        let mut cases = Vec::new();
        for &(num, den) in &uedge_cases() {
            // Reinterpret the unsigned grid as signed, and add negations.
            let (sn, sd) = (num as i64, den as i64);
            cases.push((sn, sd));
            cases.push((sn.wrapping_neg(), sd));
            cases.push((sn, sd.wrapping_neg()));
            cases.push((sn.wrapping_neg(), sd.wrapping_neg()));
        }
        cases.push((i64::MIN, -1)); // overflow case: C UB, original wraps
        cases.push((i64::MIN, 1));
        cases.push((i64::MIN, i64::MIN));
        cases.push((i64::MAX, i64::MIN));
        for (num, den) in cases {
            let (q, r) = ldivmod_full(num, den);
            let (rq, rr) = ref_ldivmod(num, den);
            assert_eq!((q, r), (rq, rr), "ldivmod({num}, {den})");
            unsafe {
                assert_eq!(__aeabi_ldivmod(num, den), rq, "ldiv q({num}, {den})");
            }
        }
    }

    /// xorshift sweep across the full 64-bit range, including small
    /// divisors and near-equal operands.
    #[test]
    fn randomized_sweep() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for i in 0..20_000 {
            let (num, den) = match i % 4 {
                0 => (next(), next()),
                1 => (next(), next() & 0xffff),           // small divisor
                2 => (next(), next() | 1 << 63),          // huge divisor
                _ => {
                    let n = next();
                    (n, n.wrapping_sub(next() % 97))      // near-equal
                }
            };
            assert_eq!(
                uldivmod_full(num, den),
                ref_udivmod(num, den),
                "u64 sweep ({num:#x}, {den:#x})"
            );
            let (sn, sd) = (num as i64, den as i64);
            assert_eq!(
                ldivmod_full(sn, sd),
                ref_ldivmod(sn, sd),
                "i64 sweep ({sn}, {sd})"
            );
        }
    }

    #[test]
    fn div_by_zero_documented_behavior() {
        // The original branches to the ADS __rt_div0 handler (raise sig 2);
        // this port returns (0, 0) instead. Lock that in.
        assert_eq!(uldivmod_full(123, 0), (0, 0));
        assert_eq!(uldivmod_full(u64::MAX, 0), (0, 0));
        assert_eq!(ldivmod_full(-42, 0), (0, 0));
        unsafe {
            assert_eq!(__aeabi_uldivmod(5, 0), 0);
            assert_eq!(__aeabi_ulmod(5, 0), 0);
            assert_eq!(__aeabi_ldivmod(5, 0), 0);
        }
    }
}
