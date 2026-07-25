//! Ports of the ARM ADS 1.0.1 64-bit shift runtime routines (AEABI).
//!
//! Each function works on the u32 halves explicitly — using Rust's native
//! 64-bit shift operators on armv5te would lower to a call to these very
//! symbols, recursing forever.
//!
//! Original algorithm (all three): compare the shift against 32
//! (`subs r3, r2, #32`). Below 32, funnel the crossing bits between the
//! halves with an `orr` (the `rsb r3, r2, #32` distance is 32 when
//! shift == 0, and an ARM register shift by 32 yields 0, so shift 0 falls
//! out naturally). At or above 32, the result is one half shifted by
//! `shift - 32` into the other word; ARM register shifts >= 32 produce 0
//! (or pure sign for `asr`), so shift >= 64 collapses to 0 / sign-fill.
//! The Rust port spells those two ARM register-shift edge cases out as
//! explicit `shift == 0` and `shift >= 64` branches instead of relying on
//! hardware shift masking.
//!
//! Behavioral verification: host-side `cargo test` compares against a
//! u128-based reference over all shift amounts 0..70; `tools/match.py`
//! (ipod-decomp) reports the mnemonic-level diff against the original
//! machine code.

/// __aeabi_llsl — original: `FUN_0802ee84` @ 0x0802ee84 (40 bytes).
///
/// 64-bit left shift, unsigned/signed identical. Shift 0..31 funnels the
/// top bits of the low word into the high word; shift 32..63 moves the low
/// word into the high word; shift >= 64 yields 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __aeabi_llsl(value: u64, shift: u32) -> u64 {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    let (lo, hi) = if shift == 0 {
        (lo, hi)
    } else if shift < 32 {
        // hi = (hi << shift) | (lo >> (32 - shift)); lo <<= shift
        (lo << shift, (hi << shift) | (lo >> (32 - shift)))
    } else if shift < 64 {
        (0, lo << (shift - 32))
    } else {
        (0, 0)
    };
    ((hi as u64) << 32) | (lo as u64)
}

/// __aeabi_llsr — original: `FUN_0802eeac` @ 0x0802eeac (40 bytes).
///
/// 64-bit logical (unsigned) right shift. Mirror image of `__aeabi_llsl`:
/// shift 0..31 funnels the bottom bits of the high word into the low word;
/// shift 32..63 moves the high word into the low word; shift >= 64
/// yields 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __aeabi_llsr(value: u64, shift: u32) -> u64 {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    let (lo, hi) = if shift == 0 {
        (lo, hi)
    } else if shift < 32 {
        // lo = (lo >> shift) | (hi << (32 - shift)); hi >>= shift
        ((lo >> shift) | (hi << (32 - shift)), hi >> shift)
    } else if shift < 64 {
        (hi >> (shift - 32), 0)
    } else {
        (0, 0)
    };
    ((hi as u64) << 32) | (lo as u64)
}

/// __aeabi_lasr — original: `FUN_0802eed4` @ 0x0802eed4 (40 bytes).
///
/// 64-bit arithmetic (signed) right shift. Same funnel as
/// `__aeabi_llsr`, but the high word shifts arithmetically; at shift >= 32
/// the high word becomes pure sign fill (`asr r1, r1, #31`), and at
/// shift >= 64 both words do.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __aeabi_lasr(value: i64, shift: u32) -> i64 {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    let sign = ((hi as i32) >> 31) as u32; // 0 or 0xffffffff
    let (lo, hi) = if shift == 0 {
        (lo, hi)
    } else if shift < 32 {
        (
            (lo >> shift) | (hi << (32 - shift)),
            ((hi as i32) >> shift) as u32,
        )
    } else if shift < 64 {
        (((hi as i32) >> (shift - 32)) as u32, sign)
    } else {
        (sign, sign)
    };
    (((hi as u64) << 32) | (lo as u64)) as i64
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    // Simple references computed in 128 bits, matching the ARM semantics
    // (shift >= 64 -> 0, or pure sign fill for the arithmetic shift).
    fn ref_llsl(value: u64, shift: u32) -> u64 {
        if shift >= 64 {
            0
        } else {
            ((value as u128) << shift) as u64
        }
    }

    fn ref_llsr(value: u64, shift: u32) -> u64 {
        if shift >= 64 {
            0
        } else {
            ((value as u128) >> shift) as u64
        }
    }

    fn ref_lasr(value: i64, shift: u32) -> i64 {
        if shift >= 64 {
            if value < 0 {
                -1
            } else {
                0
            }
        } else {
            ((value as i128) >> shift) as i64
        }
    }

    const VALUES: [u64; 6] = [
        0,
        1,
        u64::MAX,
        0x8000_0000_0000_0000,
        0x0123_4567_89ab_cdef,
        i64::MIN as u64,
    ];

    #[test]
    fn llsl_matches_reference() {
        for &value in &VALUES {
            for shift in 0..70u32 {
                let got = unsafe { __aeabi_llsl(value, shift) };
                assert_eq!(got, ref_llsl(value, shift), "llsl({value:#x}, {shift})");
            }
        }
    }

    #[test]
    fn llsr_matches_reference() {
        for &value in &VALUES {
            for shift in 0..70u32 {
                let got = unsafe { __aeabi_llsr(value, shift) };
                assert_eq!(got, ref_llsr(value, shift), "llsr({value:#x}, {shift})");
            }
        }
    }

    #[test]
    fn lasr_matches_reference() {
        for &value in &VALUES {
            for shift in 0..70u32 {
                let got = unsafe { __aeabi_lasr(value as i64, shift) };
                assert_eq!(
                    got,
                    ref_lasr(value as i64, shift),
                    "lasr({:#x}, {shift})",
                    value as i64
                );
            }
        }
    }
}
