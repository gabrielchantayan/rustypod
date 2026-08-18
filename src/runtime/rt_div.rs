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
//! - `FUN_08037a84` @ 0x08037a84 (540 bytes; Ghidra's 344 truncates at the
//!   computed jump): the Q16.16 fixed-point signed division core, NOT an
//!   ADS integer div. Computes `(dividend << 16) / divisor`, truncated
//!   toward zero. Sign-fix prologue (magnitudes in r2/r1, quotient sign
//!   track in r3), then `shift = clz(den) - clz(num)` dispatches via
//!   `add pc,pc,r4` into an unrolled cascade: sixteen 3-instruction
//!   blocks (`subs r4,r2,r1,lsl#s / orrcs r0,#bit / movcs r2,r4`,
//!   12-byte stride) produce quotient bits 31..16 against the pre-shifted
//!   divisor, then sixteen 4-instruction blocks (`add r2,r2,r2 / subs /
//!   orrcs / movcs`) shift the remainder left and produce fractional bits
//!   15..0. Quotient negated when the signs differed; ONLY r0 is
//!   returned (the remainder left in r2 is call-clobbered — the sibling
//!   remainder core ending @ 0x08037a80 shares the layout but keeps r2).
//!   No div0 funnel: den==0 never traps, every compare succeeds and the
//!   cascade sets all visited bits (see fixed16_div_core's doc header).
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
// `#[inline(never)]`: intra-crate callers (cxx::templates'
// vector_capacity) keep the original's `b` tail-branch boundary for
// match.py review (the __rt_udiv precedent below).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
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
// `#[inline(never)]` like the quotient-only variant above: intra-crate
// callers (btree_parse_cell_ptr's overflow split) keep the original's
// `bl` call boundary for match.py review.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
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

/// fixed16_div_core — original: `FUN_08037a84` @ 0x08037a84 (344 bytes in
/// Ghidra's functions.csv, but that truncates the body at the computed
/// jump; real extent 0x08037a84-0x08037c9f = 540 bytes). 6 direct bl call
/// sites — 0x080ea678/0x080ea820/0x080eae7c (FUN_080ea5a0), 0x080eb024
/// (FUN_080eade0), 0x080f78ac (FUN_080f780c), 0x080f7a90 (FUN_080f79d8) —
/// plus the `b` tail call from fixed16_div_indirect @ 0x082a182c.
///
/// Q16.16 fixed-point signed division, quotient only: returns
/// `(dividend << 16) / divisor` truncated toward zero. All callers pass
/// Q16.16 values (e.g. FUN_080f780c divides by `0xf0000` = 15.0 and uses
/// `(result >> 16) + 1`). The original reduces both operands to magnitude
/// with a quotient-sign track (`sign(dividend) ^ sign(divisor)`), computes
/// `shift = clz(den) - clz(num)`, and dispatches with `add pc,pc,r4` into
/// an unrolled shift-subtract cascade: the entered block compares the
/// remainder against `den << shift` and emits quotient bit `16 + shift`,
/// each following block decrements the shift until bit 16, then sixteen
/// blocks shift the remainder left one bit at a time to emit fractional
/// bits 15..0. When `num < den` in magnitude (shift < 0) the original's
/// `bmi` skips the high blocks entirely — only fractional bits are
/// produced. The port keeps the identical two-phase structure as loops,
/// which reproduces every output bit-exactly, including the edge cases:
///
/// - Truncation toward zero via the sign track, e.g. -1/3 -> -0x5555
///   (not floor's -0x5556).
/// - Divide by zero does NOT trap (no `__rt_div0` funnel here): den == 0
///   makes every compare succeed, so the cascade sets all visited bits —
///   the result is `(1 << (17 + shift)) - 1` with `shift =
///   32 - clz(|dividend|)`, negated when dividend < 0. E.g. 5/0 ->
///   0x000f_ffff, 1/0 -> 0x0003_ffff, 0/0 -> 0x0001_ffff, -5/0 ->
///   -0x000f_ffff. The port reproduces this exactly for |dividend| <
///   32768 (shift <= 15).
/// - Overflow (shift > 15, i.e. the Q16.16 quotient does not fit in 32
///   bits): the original's computed jump lands BEFORE its unrolled table
///   and walks into its own prologue — wild, effectively undefined. The
///   port clamps the high phase at shift 15 instead; no caller can
///   observe a difference without the original first hanging.
///
/// `|dividend| = |divisor| = 0x8000_0000` (INT_MIN/INT_MIN) is handled:
/// both magnitudes are 0x8000_0000, shift = 0, quotient 0x1_0000 (1.0).
// `#[inline(never)]`: fixed16_div_indirect (fp_misc.rs) tail-calls this
// core in the original; keep the call boundary for match.py review of
// that port (the __rt_sdiv precedent above).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed16_div_core(dividend: i32, divisor: i32) -> i32 {
    let mut rem = dividend.unsigned_abs();
    let den = divisor.unsigned_abs();
    let negate_quotient = (dividend < 0) != (divisor < 0);

    let mut quotient: u32 = 0;
    // shift = clz(den) - clz(num): the Q16.16 quotient needs shift + 17
    // bits; shift > 15 means 32-bit overflow (wild jump in the original,
    // clamped here — see doc header). shift < 0 (num < den) skips the
    // high phase, matching the original's `bmi` into the low blocks.
    let shift = den.leading_zeros() as i32 - rem.leading_zeros() as i32;
    if shift >= 0 {
        // High phase: quotient bits 31..16 against the pre-shifted
        // divisor (`subs r4,r2,r1,lsl#s / orrcs / movcs`). bit_length
        // (den) + shift <= bit_length(num) <= 32, so `den << s` never
        // loses a bit on the reachable path.
        for s in (0..=shift.min(15) as u32).rev() {
            let scaled = den << s;
            if rem >= scaled {
                rem -= scaled;
                quotient |= 1 << (16 + s);
            }
        }
    }
    // Low phase: sixteen `add r2,r2,r2 / subs / orrcs / movcs` blocks
    // shifting the remainder left, producing fractional bits 15..0. The
    // shift wraps mod 2^32 exactly like the ARM add (observable only on
    // the den == 0 path, where rem is never reduced).
    for bit in (0..16u32).rev() {
        rem <<= 1;
        if rem >= den {
            rem -= den;
            quotient |= 1 << bit;
        }
    }

    if negate_quotient {
        quotient = quotient.wrapping_neg();
    }
    quotient as i32
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

    // ---- fixed16_div_core @ 0x08037a84 (Q16.16 division) ----

    fn fixed16_div(dividend: i32, divisor: i32) -> i32 {
        unsafe { fixed16_div_core(dividend, divisor) }
    }

    /// Q16.16 reference: `(dividend << 16) / divisor` in i64, truncated
    /// toward zero (host `/` on i64). Only called where the quotient
    /// magnitude fits in 32 bits — outside that the ORIGINAL is undefined
    /// (computed jump walks off its unrolled table), so there is nothing
    /// to match. `as u32 as i32` wraps bit-31 results (e.g. 0x8000/1 ->
    /// 0x8000_0000 == INT_MIN) exactly like the original's r0.
    fn ref_fixed16_div(dividend: i32, divisor: i32) -> (i32, bool) {
        if divisor == 0 {
            return (0, false);
        }
        let quotient = ((dividend as i64) << 16) / (divisor as i64);
        if quotient.unsigned_abs() > u32::MAX as u64 {
            return (0, false); // original: wild jump, undefined
        }
        (quotient as u32 as i32, true)
    }

    /// Reference for the den == 0 path: no trap in the original; every
    /// cascade block visited sets its bit, so the quotient magnitude is
    /// `(1 << (17 + shift)) - 1` with `shift = bit_length(|dividend|)`,
    /// negated when the dividend is negative. The original defines this
    /// only for shift <= 15 (|dividend| < 32768); beyond that its
    /// computed jump is wild (the port clamps, see the doc header).
    fn ref_fixed16_div0(dividend: i32) -> i32 {
        let shift = 32 - dividend.unsigned_abs().leading_zeros();
        assert!(shift <= 15, "original undefined for |dividend| >= 32768");
        let bits = 17 + shift;
        let magnitude = if bits == 32 { u32::MAX } else { (1u32 << bits) - 1 };
        if dividend < 0 { magnitude.wrapping_neg() as i32 } else { magnitude as i32 }
    }

    /// All four sign quadrants, with truncation-toward-zero checked
    /// against exact bit patterns (1/3 = 0x5555.55... -> 0x5555, and the
    /// negative quadrants truncate toward zero rather than floor).
    #[test]
    fn fixed16_sign_quadrants() {
        // (1 << 16) / 3 = 21845.33.. -> 0x5555 in every quadrant.
        assert_eq!(fixed16_div(1, 3), 0x5555);
        assert_eq!(fixed16_div(-1, 3), -0x5555);
        assert_eq!(fixed16_div(1, -3), -0x5555);
        assert_eq!(fixed16_div(-1, -3), 0x5555);
        // Exact Q16.16 identities: 1.0/1.0, 15.0 divisor (FUN_080f780c's
        // 0xf0000), negative one, halves.
        assert_eq!(fixed16_div(0x1_0000, 0x1_0000), 0x1_0000);
        assert_eq!(fixed16_div(0xf_0000, 0xf_0000), 0x1_0000);
        assert_eq!(fixed16_div(-0x1_0000, 0x1_0000), -0x1_0000);
        assert_eq!(fixed16_div(1, 2), 0x8000);
        assert_eq!(fixed16_div(3, 2), 0x1_8000);
        assert_eq!(fixed16_div(-3, 2), -0x1_8000);
        // Dividend smaller than divisor: pure fraction (the original's
        // `bmi` path skipping the high blocks).
        assert_eq!(fixed16_div(2, 3), 0xaaaa); // 0.666.. truncated
        assert_eq!(fixed16_div(-2, 3), -0xaaaa);
        assert_eq!(fixed16_div(0, 7), 0);
        assert_eq!(fixed16_div(0, -7), 0);
    }

    /// INT_MIN and 32-bit boundary edges. The original returns only r0
    /// (quotient); the remainder it leaves in r2 is call-clobbered and
    /// unobservable, so behavioral parity is exactly "r0 matches".
    #[test]
    fn fixed16_int_min_and_boundaries() {
        let cases = [
            (i32::MIN, i32::MIN),       // 1.0
            (i32::MIN, 0x1_0000),       // -32768.0 -> 0x8000_0000 wraps
            (i32::MIN, -0x1_0000),      // +32768.0 -> 0x8000_0000 wraps
            (i32::MIN, i32::MAX),
            (0x8000, 1),                // 32768.0 -> 0x8000_0000 (shift 15)
            (0x8000, -1),
            (-0x8000, 1),
            (0xffff, 1),                // shift 15 boundary from below
            (0xffff, -1),
            (i32::MIN, 0x2_0000),
            (i32::MAX, i32::MIN),
            (1, i32::MIN),              // tiny fraction
            (-1, i32::MIN),
            (0x1_0000, 3),
            (123_456, -789),
        ];
        for (num, den) in cases {
            let (want, defined) = ref_fixed16_div(num, den);
            assert!(defined, "test case outside the original's defined range");
            assert_eq!(fixed16_div(num, den), want, "fixed16_div({num}, {den})");
        }
    }

    /// Divide by zero: the fixed16 core has NO __rt_div0 funnel (unlike
    /// the ADS integer cores above) — it never traps. Every compare
    /// against den == 0 succeeds, so the visited cascade bits all set.
    #[test]
    fn fixed16_div_by_zero_does_not_trap() {
        assert_eq!(fixed16_div(0, 0), 0x0001_ffff);
        assert_eq!(fixed16_div(1, 0), 0x0003_ffff);
        assert_eq!(fixed16_div(5, 0), 0x000f_ffff);
        assert_eq!(fixed16_div(-5, 0), -0x000f_ffff);
        assert_eq!(fixed16_div(32767, 0), -1); // all 32 bits set
        assert_eq!(fixed16_div(-32767, 0), 1); // negated all-ones
        // |dividend| >= 32768 with den == 0 is the original's wild-jump
        // territory (shift > 15); the port clamps instead — deliberately
        // not asserted here (see the fixed16_div_core doc header).
    }

    /// Bit-boundary sweep: Q16.16 dividends/divisors straddling powers of
    /// two, all sign combinations.
    #[test]
    fn fixed16_bit_boundary_sweep() {
        for shift in 0..16u32 {
            let base = 1i32 << shift;
            for num in [base - 1, base, base + 1] {
                for den in [base, base | 1, -(base), -(base | 1)] {
                    for num in [num, -num] {
                        let (want, defined) = ref_fixed16_div(num, den);
                        if defined {
                            assert_eq!(fixed16_div(num, den), want, "fixed16_div({num}, {den})");
                        }
                    }
                }
            }
        }
    }

    /// Pseudorandom sweep (LCG, deterministic) over the full 32-bit
    /// space, restricted to the original's defined range (quotient fits
    /// 32 bits), plus a div0 sweep over the defined |dividend| < 32768.
    #[test]
    fn fixed16_random_sweep() {
        let mut state = 0xdead_beefu32;
        let mut next = move || {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            state
        };
        let mut compared = 0u32;
        for _ in 0..200_000 {
            let (num, den) = (next() as i32, next() as i32);
            let (want, defined) = ref_fixed16_div(num, den);
            if defined {
                assert_eq!(fixed16_div(num, den), want, "fixed16_div({num}, {den})");
                compared += 1;
            }
        }
        assert!(compared > 1000, "sweep barely covered the defined range");
        // den == 0 sweep across every defined dividend magnitude class.
        for _ in 0..20_000 {
            let num = (next() % 32768) as i32;
            for num in [num, -num] {
                assert_eq!(fixed16_div(num, 0), ref_fixed16_div0(num), "fixed16_div({num}, 0)");
            }
        }
    }
}
