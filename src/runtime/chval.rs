//! Small ARM ADS 1.0.1 stdlib helpers: ASCII digit valuation and signed
//! long division.
//!
//! Behavioral verification: host-side `cargo test` compares against simple
//! reference implementations; `tools/match.py` (ipod-decomp) reports the
//! mnemonic-level diff against the original machine code.

/// _chval — original: `_chval` @ 0x08032fec (32 bytes).
///
/// Converts an ASCII character to its digit value in `base` (2..36),
/// returning -1 when the character is not a digit valid for that base.
/// Handles `0-9`, `a-z` and `A-Z`.
///
/// The port mirrors the original's branchless idiom exactly:
/// `cmp #0x3a; subcc #0x30; bic #0x20; cmp #0x41; subcs #0x37; cmp base;
/// mvncs #-1`. Characters below `'0'` wrap to huge unsigned values after
/// the subtract and are rejected by the final base compare, as in the
/// original. (Bases above 36 inherit the original's raw unsigned compare,
/// so e.g. `':'` is not special-cased away — callers pass sane bases.)
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _chval(c: u8, base: u32) -> i32 {
    let mut value = c as u32;
    if value < 0x3a {
        // '0'..'9' -> 0..9; anything below '0' wraps huge and is
        // rejected by the final compare, matching the original.
        value = value.wrapping_sub(0x30);
    }
    let upper = value & !0x20; // fold lowercase to uppercase
    if upper >= 0x41 {
        // 'A'..'Z' (and wrapped-huge values) -> letter value or still-huge.
        value = upper.wrapping_sub(0x37);
    }
    if value >= base { -1 } else { value as i32 }
}

/// ldiv return value, matching the C `ldiv_t` layout (`{quot, rem}`).
///
/// An 8-byte struct is returned through a hidden pointer in r0 under the
/// AAPCS, exactly like the original's `stm r4, {r0, r1}`.
#[repr(C)]
pub struct LdivResult {
    pub quot: i32,
    pub rem: i32,
}

/// ldiv — original: `ldiv` @ 0x08030e60 (28 bytes).
///
/// Signed long division returning quotient and remainder. The original
/// tail-calls `__rt_sdiv` (ported separately in rt_div.rs — not imported
/// here) and stores `{quot, rem}` through the hidden struct pointer.
///
/// Division is implemented locally as bitwise long division on the
/// unsigned magnitudes so this module stays self-contained (LLVM would
/// otherwise emit `__aeabi_idiv` helper calls on ARMv5). Semantics match
/// `__rt_sdiv`: quotient truncates toward zero, remainder takes the sign
/// of the dividend. Divergence: divide-by-zero returns `{0, 0}` where the
/// original's `__rt_sdiv` raises SIGFPE via `__rt_raise`; `i32::MIN / -1`
/// wraps to `i32::MIN` instead of overflowing.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ldiv(num: i32, den: i32) -> LdivResult {
    if den == 0 {
        return LdivResult { quot: 0, rem: 0 };
    }
    let (q, r) = udiv_mod(num.unsigned_abs(), den.unsigned_abs());
    let quot = if (num < 0) != (den < 0) {
        (q as i32).wrapping_neg()
    } else {
        q as i32
    };
    // Remainder takes the sign of the dividend (truncating division).
    let rem = if num < 0 {
        (r as i32).wrapping_neg()
    } else {
        r as i32
    };
    LdivResult { quot, rem }
}

/// Bitwise long division: returns (n / d, n % d) for d != 0.
fn udiv_mod(n: u32, d: u32) -> (u32, u32) {
    let mut quot = 0u32;
    let mut rem = 0u32;
    for bit in (0..32).rev() {
        rem = (rem << 1) | ((n >> bit) & 1);
        if rem >= d {
            rem -= d;
            quot |= 1 << bit;
        }
    }
    (quot, rem)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// Obvious-table reference: only defined for the sane base range.
    fn ref_chval(c: u8, base: u32) -> i32 {
        let v = match c {
            b'0'..=b'9' => (c - b'0') as i32,
            b'a'..=b'z' => (c - b'a') as i32 + 10,
            b'A'..=b'Z' => (c - b'A') as i32 + 10,
            _ => -1,
        };
        if v < 0 || v as u32 >= base {
            -1
        } else {
            v
        }
    }

    /// Every byte value against every base 2..=36.
    #[test]
    fn chval_all_bytes_all_bases() {
        for c in 0u16..=255 {
            for base in 2u32..=36 {
                assert_eq!(
                    unsafe { _chval(c as u8, base) },
                    ref_chval(c as u8, base),
                    "mismatch: c={c:#04x} base={base}"
                );
            }
        }
    }

    /// Spot-check the documented digit sets explicitly.
    #[test]
    fn chval_digit_classes() {
        unsafe {
            assert_eq!(_chval(b'0', 2), 0);
            assert_eq!(_chval(b'1', 2), 1);
            assert_eq!(_chval(b'2', 2), -1);
            assert_eq!(_chval(b'9', 10), 9);
            assert_eq!(_chval(b'a', 16), 10);
            assert_eq!(_chval(b'F', 16), 15);
            assert_eq!(_chval(b'z', 36), 35);
            assert_eq!(_chval(b'Z', 36), 35);
            assert_eq!(_chval(b'z', 35), -1);
            assert_eq!(_chval(b'/', 36), -1); // just below '0'
            assert_eq!(_chval(b':', 36), -1); // just above '9'
            assert_eq!(_chval(b'@', 36), -1); // just below 'A'
            assert_eq!(_chval(b'`', 36), -1); // just below 'a'
            assert_eq!(_chval(0, 36), -1);
        }
    }

    fn ref_ldiv(num: i32, den: i32) -> (i32, i32) {
        // Host wrapping ops give the truncating semantics we target.
        (num.wrapping_div(den), num.wrapping_rem(den))
    }

    #[test]
    fn ldiv_edge_cases() {
        let cases = [
            (7, 2),
            (-7, 2),
            (7, -2),
            (-7, -2),
            (6, 3),
            (-6, 3),
            (0, 5),
            (1, 1),
            (-1, 1),
            (i32::MAX, 1),
            (i32::MIN, 1),
            (i32::MIN, -1), // wraps, matches ARM behavior
            (i32::MIN, 2),
            (i32::MAX, -1),
            (1, i32::MIN),
            (123_456_789, -1000),
        ];
        for (num, den) in cases {
            let r = unsafe { ldiv(num, den) };
            let (q, m) = ref_ldiv(num, den);
            assert_eq!((r.quot, r.rem), (q, m), "mismatch: {num} / {den}");
            // C invariant: quot * den + rem == num (wrapping).
            assert_eq!(
                r.quot.wrapping_mul(den).wrapping_add(r.rem),
                num,
                "identity failed: {num} / {den}"
            );
        }
    }

    /// Pseudo-random sweep (xorshift) against the host reference.
    #[test]
    fn ldiv_random_sweep() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..10_000 {
            let num = next() as u32 as i32;
            let mut den = (next() >> 16) as u32 as i32;
            if den == 0 {
                den = 1;
            }
            let r = unsafe { ldiv(num, den) };
            let (q, m) = ref_ldiv(num, den);
            assert_eq!((r.quot, r.rem), (q, m), "mismatch: {num} / {den}");
        }
    }

    #[test]
    fn ldiv_divide_by_zero_is_defined() {
        // Divergence from the original (which raises SIGFPE): {0, 0}.
        let r = unsafe { ldiv(42, 0) };
        assert_eq!((r.quot, r.rem), (0, 0));
    }
}
