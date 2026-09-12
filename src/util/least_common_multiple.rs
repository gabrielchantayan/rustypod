use crate::runtime::rt_div::{__rt_udiv, __rt_udivmod};

/// least_common_multiple — original: `FUN_082d3c5c` @ 0x082d3c5c (72 bytes;
/// 8 direct `bl` call sites, all unconditional: 0x08043608, 0x08043618,
/// 0x08043630, 0x08043640, 0x08043658, 0x08043668, 0x08043680, 0x08043690).
///
/// Raw extent is 18 ARM words from 0x082d3c5c through the tail `b __rt_udiv`
/// at 0x082d3ca0; the next separately linked function begins at 0x082d3ca4.
/// The only caller loads both inputs as bytes. The routine returns 1 when the
/// signed low-half product is zero; otherwise, it finds the unsigned GCD of
/// the full-width inputs with Euclid's division algorithm, then returns the
/// unsigned quotient of the signed-low-half product by that GCD.
///
/// Deliberate ABI deviation: ARM's `__rt_udiv` exposes a remainder in r1, but
/// every verified caller consumes only r0. Rust receives each Euclidean
/// remainder through the existing `__rt_udivmod` output pointer instead.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn least_common_multiple(left: u32, right: u32) -> u32 {
    let product = (i32::from(left as u16 as i16) * i32::from(right as u16 as i16)) as u32;
    if product == 0 {
        return 1;
    }

    let mut dividend = left;
    let mut divisor = right;
    loop {
        if dividend < divisor {
            core::mem::swap(&mut dividend, &mut divisor);
        }

        let mut remainder = 0;
        __rt_udivmod(dividend, divisor, &mut remainder);
        if remainder == 0 {
            return __rt_udiv(product, divisor);
        }
        dividend = remainder;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(left: u32, right: u32) -> u32 {
        let product = (i32::from(left as u16 as i16) * i32::from(right as u16 as i16)) as u32;
        if product == 0 {
            return 1;
        }

        let mut dividend = left;
        let mut divisor = right;
        loop {
            if dividend < divisor {
                core::mem::swap(&mut dividend, &mut divisor);
            }
            let remainder = dividend % divisor;
            if remainder == 0 {
                return product / divisor;
            }
            dividend = remainder;
        }
    }

    #[test]
    fn zero_low_half_product_returns_one() {
        for &(left, right) in &[(0, 0), (0, 255), (255, 0), (0x0001_0000, 3)] {
            assert_eq!(unsafe { least_common_multiple(left, right) }, 1);
        }
    }

    #[test]
    fn returns_the_byte_domain_least_common_multiple() {
        assert_eq!(unsafe { least_common_multiple(6, 8) }, 24);
        assert_eq!(unsafe { least_common_multiple(8, 6) }, 24);
        assert_eq!(unsafe { least_common_multiple(255, 254) }, 64_770);
    }

    #[test]
    fn matches_raw_semantics_for_every_verified_caller_input() {
        for left in 0..=u8::MAX as u32 {
            for right in 0..=u8::MAX as u32 {
                assert_eq!(
                    unsafe { least_common_multiple(left, right) },
                    reference(left, right),
                    "left={left:#x}, right={right:#x}",
                );
            }
        }
    }

    #[test]
    fn preserves_full_width_euclid_and_signed_low_half_product() {
        for &(left, right) in &[
            (0xffff_ffff, 1),
            (0x0001_0001, 3),
            (0x8000_8000, 0x7fff_7fff),
            (0xffff_8000, 0x0000_8000),
        ] {
            assert_eq!(
                unsafe { least_common_multiple(left, right) },
                reference(left, right),
                "left={left:#x}, right={right:#x}",
            );
        }
    }
}
