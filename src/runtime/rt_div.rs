//! Port of the ARM ADS 1.0.1 32-bit division core — the hottest runtime
//! routine in osos (2299 call sites combined).
//!
//! Originals:
//! - `__rt_sdiv` @ 0x08031568 (356 bytes): signed divide+remainder. Sign-fix
//!   prologue (negates num/den into unsigned, records quotient sign in r3
//!   and remainder sign in the shifter carry), then a restoring-division
//!   core fully unrolled in 8-bit octets (`rsbs ip,r1,r0,lsr#N /
//!   subcs r0,r0,r1,lsl#N / adc r2,r2,r2`), with a scaling path that
//!   left-shifts small divisors by 6 bits at a time. Epilogue negates
//!   quotient when signs differ, remainder when num was negative — i.e.
//!   exactly C truncation semantics. Returns quotient in r0 AND remainder
//!   in r1 (pre-EABI: callers use one or both).
//! - `__rt_udiv` @ 0x08036f14 (28 bytes): unsigned variant that joins the
//!   sdiv core mid-stream at the lsr#4 stage, skipping sign handling.
//! - `__rt_div0` @ 0x0803421c (12 bytes): `mov r0,#2; mov r1,#2;
//!   b __rt_raise` — raises signal 2 (SIGFPE) via `__rt_raise` @ 0x080320a8.
//!   Both cores funnel den==0 here (the `rsbs ip,r1,#0 / bcs` check at
//!   0x0803164c, after the scaling path forced r1 to 0).
//!
//! Simplification: the algorithm is identical restoring division, but the
//! unrolled-octet structure (and the divisor pre-scaling with quotient
//! marker bits) is collapsed into a plain 32-iteration bit loop with a
//! 33-bit remainder tracked in u64. Output values are bit-identical to the
//! original for every input; only the instruction-level shape differs
//! (exact match against ADS machine code was never achievable anyway).
//!
//! Division by zero: both cores funnel den==0 into `__rt_div0`, ported
//! below on top of the ported `__rt_raise` (raise.rs). With the stock
//! all-default handler table the raise never returns (default handler ->
//! OS terminate); if a registered handler deals with the SIGFPE, the
//! original returns to the divide's *caller* with r0 = 0 (`__rt_raise`'s
//! result) and r1 clobbered by the raise machinery — modeled here as a
//! 0 quotient and 0 remainder.

use crate::raise::{SIGFPE, __rt_raise};

/// __rt_div0 — original @ 0x0803421c (12 bytes): `mov r0, #2;
/// mov r1, #2; b __rt_raise` — raises SIGFPE (2) with the Divide By Zero
/// reason code (2, the `0x8000_0002` mask group in the default handler)
/// via `__rt_raise` @ 0x080320a8. The original is entered with a plain
/// `b` from the divide cores, so when a registered handler survives the
/// raise, `__rt_raise`'s return value (0) lands directly in the divide
/// caller's r0; the tail call is mirrored here by returning it.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_div0() -> i32 {
    __rt_raise(SIGFPE, 2)
}

/// den == 0 funnel shared by both cores: raise through `__rt_div0`. On
/// the survived-raise path the divide returns 0 (see module header).
fn div0_result() -> (u32, u32) {
    unsafe { __rt_div0() };
    (0, 0)
}

/// Restoring long division, one quotient bit per iteration, MSB first.
/// The u64 remainder makes the 33rd bit explicit so left shifts cannot
/// lose a bit when `den > 0x8000_0000`.
fn udiv_core(num: u32, den: u32) -> (u32, u32) {
    let den = den as u64;
    let mut rem: u64 = 0;
    let mut quot: u32 = 0;
    for bit in (0..32).rev() {
        rem = (rem << 1) | ((num >> bit) & 1) as u64;
        if rem >= den {
            rem -= den;
            quot |= 1 << bit;
        }
    }
    (quot, rem as u32)
}

/// Shared signed divide+remainder: C truncation semantics (quotient rounds
/// toward zero, remainder takes the sign of `num`). Mirrors the original's
/// prologue/epilogue: divide magnitudes, negate quotient when signs
/// differ, negate remainder when `num` was negative.
fn sdiv_core(num: i32, den: i32) -> (i32, i32) {
    if den == 0 {
        let (quot, rem) = div0_result();
        return (quot as i32, rem as i32);
    }
    let (mut quot, mut rem) = udiv_core(num.unsigned_abs(), den.unsigned_abs());
    if (num < 0) != (den < 0) {
        quot = quot.wrapping_neg();
    }
    if num < 0 {
        rem = rem.wrapping_neg();
    }
    (quot as i32, rem as i32)
}

/// `__rt_sdiv` @ 0x08031568 — signed 32-bit divide, quotient only.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_sdiv(num: i32, den: i32) -> i32 {
    sdiv_core(num, den).0
}

/// `__rt_sdiv` @ 0x08031568 — signed divide, quotient returned and
/// remainder stored through `rem` (the original returns both in r0/r1;
/// pre-EABI C callers that want both go through this wrapper).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_sdivmod(num: i32, den: i32, rem: *mut i32) -> i32 {
    let (quot, r) = sdiv_core(num, den);
    *rem = r;
    quot
}

/// `__rt_udiv` @ 0x08036f14 — unsigned 32-bit divide, quotient only.
// `#[inline(never)]`: intra-crate callers (block_deque_fill's block-count
// division) keep the original's `bl` call boundary for match.py review
// (free_path.rs precedent).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __rt_udiv(num: u32, den: u32) -> u32 {
    udiv_entry(num, den).0
}

/// `__rt_udiv` @ 0x08036f14 — unsigned divide, quotient returned and
/// remainder stored through `rem`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_udivmod(num: u32, den: u32, rem: *mut u32) -> u32 {
    let (quot, r) = udiv_entry(num, den);
    *rem = r;
    quot
}

/// Unsigned entry with the div0 funnel of the original core.
fn udiv_entry(num: u32, den: u32) -> (u32, u32) {
    if den == 0 {
        return div0_result();
    }
    udiv_core(num, den)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Reference: plain host `/` / `%` (hardware C semantics), with the one
    /// overflowing case (i32::MIN / -1) computed via wrapping ops to match
    /// the ARM original's wraparound.
    fn ref_sdiv(num: i32, den: i32) -> (i32, i32) {
        assert_ne!(den, 0);
        if num == i32::MIN && den == -1 {
            (i32::MIN, 0)
        } else {
            (num / den, num % den)
        }
    }

    fn ref_udiv(num: u32, den: u32) -> (u32, u32) {
        assert_ne!(den, 0);
        (num / den, num % den)
    }

    fn sdivmod(num: i32, den: i32) -> (i32, i32) {
        let mut rem = 0i32;
        let quot = unsafe { __rt_sdivmod(num, den, &mut rem) };
        (quot, rem)
    }

    fn udivmod(num: u32, den: u32) -> (u32, u32) {
        let mut rem = 0u32;
        let quot = unsafe { __rt_udivmod(num, den, &mut rem) };
        (quot, rem)
    }

    fn signed_cases() -> Vec<(i32, i32)> {
        let vals = [
            0,
            1,
            -1,
            2,
            -2,
            3,
            -3,
            7,
            -7,
            100,
            -100,
            255,
            256,
            4096,
            65535,
            65536,
            1 << 20,
            -(1 << 20),
            i32::MAX,
            i32::MAX - 1,
            i32::MIN,
            i32::MIN + 1,
            0x0fff_ffff,
            -0x0fff_ffff,
        ];
        let mut cases = Vec::new();
        for &num in &vals {
            for &den in &vals {
                if den != 0 {
                    cases.push((num, den));
                }
            }
        }
        // Divisors larger than the dividend, both signs.
        for &(num, den) in &[
            (5, 10),
            (-5, 10),
            (5, -10),
            (-5, -10),
            (0, i32::MAX),
            (1, i32::MIN),
            (i32::MAX - 1, i32::MAX),
            (i32::MIN + 1, i32::MIN),
        ] {
            cases.push((num, den));
        }
        cases
    }

    #[test]
    fn signed_matches_reference() {
        for (num, den) in signed_cases() {
            let (want_q, want_r) = ref_sdiv(num, den);
            assert_eq!(unsafe { __rt_sdiv(num, den) }, want_q, "sdiv({num}, {den})");
            assert_eq!(sdivmod(num, den), (want_q, want_r), "sdivmod({num}, {den})");
        }
    }

    #[test]
    fn unsigned_matches_reference() {
        let vals = [
            0u32,
            1,
            2,
            3,
            7,
            100,
            255,
            256,
            4096,
            65535,
            65536,
            1 << 20,
            0x0fff_ffff,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_0000,
            u32::MAX - 1,
            u32::MAX,
        ];
        for &num in &vals {
            for &den in &vals {
                if den == 0 {
                    continue;
                }
                let (want_q, want_r) = ref_udiv(num, den);
                assert_eq!(unsafe { __rt_udiv(num, den) }, want_q, "udiv({num}, {den})");
                assert_eq!(udivmod(num, den), (want_q, want_r), "udivmod({num}, {den})");
            }
        }
        // Divisor larger than dividend.
        for (num, den) in [(5u32, 10u32), (0, u32::MAX), (u32::MAX - 1, u32::MAX)] {
            assert_eq!(udivmod(num, den), ref_udiv(num, den));
        }
    }

    /// Powers of two as divisors and ±1 quotients around them.
    #[test]
    fn bit_boundary_sweep() {
        for shift in 0..32 {
            let base = 1u32 << shift;
            for num in [base.wrapping_sub(1), base, base.wrapping_add(1), u32::MAX] {
                for den in [base, base | 1] {
                    if den == 0 {
                        continue;
                    }
                    assert_eq!(udivmod(num, den), ref_udiv(num, den), "udiv({num}, {den})");
                    let (snum, sden) = (num as i32, den as i32);
                    if sden != 0 && !(snum == i32::MIN && sden == -1) {
                        assert_eq!(sdivmod(snum, sden), ref_sdiv(snum, sden), "sdiv({snum}, {sden})");
                        assert_eq!(
                            sdivmod(snum.wrapping_neg(), sden),
                            ref_sdiv(snum.wrapping_neg(), sden)
                        );
                    }
                }
            }
        }
    }

    /// Division by zero funnels into `__rt_div0` -> `__rt_raise(2, 2)`.
    /// With a handler registered for SIGFPE the raise is survived: the
    /// handler observes (sig=2, code=2) and the divide returns quotient 0
    /// (the original returns `__rt_raise`'s r0 = 0 to the divide's
    /// caller). The unhandled path (default handler -> OS terminate) is
    /// not host-testable — see raise.rs's test module. Serialized with
    /// raise.rs's tests through the shared signal-table lock.
    #[test]
    fn div_by_zero_raises_sigfpe() {
        use crate::raise::{signal, SIGFPE, TEST_SIGNAL_LOCK};

        static mut FPE_CALLS: Vec<(i32, i32)> = Vec::new();
        unsafe extern "C" fn fpe_recorder(sig: i32, code: i32) {
            unsafe { (*core::ptr::addr_of_mut!(FPE_CALLS)).push((sig, code)) };
        }

        let _guard = TEST_SIGNAL_LOCK.lock().unwrap();
        unsafe {
            let previous = signal(SIGFPE, fpe_recorder as *const () as isize);
            (*core::ptr::addr_of_mut!(FPE_CALLS)).clear();

            assert_eq!(__rt_div0(), 0);
            assert_eq!(__rt_sdiv(5, 0), 0);
            assert_eq!(__rt_udiv(7, 0), 0);
            let mut srem = 123i32;
            assert_eq!(__rt_sdivmod(-9, 0, &mut srem), 0);
            assert_eq!(srem, 0);
            let mut urem = 123u32;
            assert_eq!(__rt_udivmod(u32::MAX, 0, &mut urem), 0);
            assert_eq!(urem, 0);

            let calls = &*core::ptr::addr_of!(FPE_CALLS);
            assert_eq!(calls.as_slice(), &[(SIGFPE, 2); 5]);
            signal(SIGFPE, previous);
        }
    }

    /// Pseudorandom sweep (LCG, deterministic) over the full 32-bit space.
    #[test]
    fn random_sweep() {
        let mut state = 0x1234_5678u32;
        let mut next = move || {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            state
        };
        for _ in 0..20_000 {
            let (unum, uden) = (next(), next() | 1);
            assert_eq!(udivmod(unum, uden), ref_udiv(unum, uden));
            let (snum, sden) = (unum as i32, uden as i32);
            if !(snum == i32::MIN && sden == -1) {
                assert_eq!(sdivmod(snum, sden), ref_sdiv(snum, sden));
            }
        }
    }
}
