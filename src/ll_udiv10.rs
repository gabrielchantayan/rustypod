//! `_ll_udiv10` — original: `FUN_080320d0` @ 0x080320d0 (152 bytes).
//!
//! Unsigned 64-bit divide-by-10 without a divider, from the ARM ADS 1.0.1
//! long-long runtime. Used by retailOS printf/dtoa (`%lld`, `%llu`) and
//! `strtoull` to peel decimal digits. The original returns the quotient in
//! r0:r1 and the remainder (0..9) in r2; since the plain C ABI cannot hand
//! back r2, [`_ll_udiv10`] returns only the quotient and [`ll_udiv10_full`]
//! exposes the (quotient, remainder) pair to Rust callers.
//!
//! Algorithm (mirrored from the original instruction sequence):
//!
//! 1. Approximate `num * 0.8` with a shift-add chain. Starting from
//!    `x = num - (num >> 2)` (i.e. `num * (1 - 2^-2)`), each step adds
//!    `x >> k` for k = 4, 8, 16, 32, multiplying by `(1 + 2^-k)`. The
//!    factors telescope exactly:
//!    `(1-2^-2)(1+2^-4)(1+2^-8)(1+2^-16)(1+2^-32) = 0x3333333333333333 / 2^62`,
//!    so `x = floor(num * 0.8)` up to truncation error, and
//!    `quot = x >> 3` is `num / 10` rounded down, at most one too small
//!    (the error analysis guarantees `num - 10*quot < 20`).
//! 2. Fix-up: compute `rem = (num - 10) - quot * 10` as a 64-bit value.
//!    If its sign bit is set, `quot` was exact and the true remainder is
//!    `rem + 10`; otherwise `quot` was one low, so bump it and `rem`
//!    (now in 0..9) is the remainder. Seeding from `num - 10` is what
//!    lets a single comparison decide both cases.
//!
//! The port keeps the original's shift-add sequence verbatim (wrapping
//! arithmetic standing in for the ARM carry chains) rather than using
//! `u128` or `/ 10` — on armv5te this lowers to plain shifts/adds/umull
//! with no `__aeabi_uldivmod` libcall.

/// Quotient-only entry point matching the original's r0:r1 return.
#[no_mangle]
pub unsafe extern "C" fn _ll_udiv10(num: u64) -> u64 {
    ll_udiv10_full(num).0
}

/// Full divide: returns `(num / 10, num % 10)`.
pub fn ll_udiv10_full(num: u64) -> (u64, u8) {
    // Shift-add magic multiply: x ~= num * 0.8 (see module doc).
    let mut x = num - (num >> 2);
    x = x.wrapping_add(x >> 4);
    x = x.wrapping_add(x >> 8);
    x = x.wrapping_add(x >> 16);
    x = x.wrapping_add(x >> 32);
    let mut quot = x >> 3;

    // Fix-up: rem = (num - 10) - quot*10; negative means quot was exact.
    let mut rem = num.wrapping_sub(10).wrapping_sub(quot.wrapping_mul(10));
    if (rem as i64) < 0 {
        rem = rem.wrapping_add(10);
    } else {
        quot += 1;
    }
    (quot, rem as u8)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;
    use std::vec::Vec;

    /// Dead-simple reference: hardware divide.
    fn reference(num: u64) -> (u64, u8) {
        (num / 10, (num % 10) as u8)
    }

    fn check(num: u64) {
        let expected = reference(num);
        assert_eq!(
            ll_udiv10_full(num),
            expected,
            "ll_udiv10_full({num}) = {:?}, want {:?}",
            ll_udiv10_full(num),
            expected
        );
        assert_eq!(unsafe { _ll_udiv10(num) }, expected.0, "_ll_udiv10({num})");
    }

    #[test]
    fn small_values() {
        for num in 0..=20u64 {
            check(num);
        }
        // Exhaustive sweep across every digit-transition boundary region.
        for num in 0..1000u64 {
            check(num);
        }
    }

    #[test]
    fn powers_of_ten() {
        for k in 0..=19u32 {
            let p = 10u64.pow(k);
            for num in [p - 1, p, p + 1] {
                check(num);
            }
        }
    }

    #[test]
    fn extremes() {
        for num in [
            u64::MAX,
            u64::MAX - 1,
            u64::MAX - 9,
            u64::MAX - 10,
            u64::MAX / 2,
            u64::MAX / 10,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            1 << 63,
            (1 << 63) - 1,
        ] {
            check(num);
        }
    }

    /// Deterministic pseudo-random large values (xorshift64*).
    #[test]
    fn random_large_values() {
        let mut state = 0x9E3779B97F4A7C15u64;
        for _ in 0..100_000 {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let num = state.wrapping_mul(0x2545F4914F6CDD1D);
            check(num);
        }
    }

    /// Round-trip through the full pair: 10*q + r must rebuild the input.
    #[test]
    fn quotient_remainder_identity() {
        let mut values: Vec<u64> = (0..100).collect();
        values.extend([u64::MAX, u64::MAX - 7, 1 << 63, 999_999_999_999_999_999]);
        let mut state = 0xDEADBEEFCAFEF00Du64;
        for _ in 0..10_000 {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            values.push(state.wrapping_mul(0x2545F4914F6CDD1D));
        }
        for num in values {
            let (q, r) = ll_udiv10_full(num);
            assert!(r < 10, "remainder {r} out of range for {num}");
            assert_eq!(
                q.wrapping_mul(10).wrapping_add(r as u64),
                num,
                "10*q+r != num for {}",
                format!("{num}")
            );
        }
    }
}
