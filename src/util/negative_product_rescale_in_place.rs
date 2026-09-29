//! Rescales a negative intermediate product in place.
//!
//! `negative_product_rescale_in_place` — retailOS `FUN_08340f04` at load
//! address **0x08340f04**. Raw `osos.dec` establishes the 40-byte extent:
//! instruction bytes at `0x08340f04..0x08340f2c`, followed by literals
//! `0x7f377e0a` and `0x7f8899ed`; the next real function starts at
//! `0x08340f34`. Decoding the full ARM image finds two direct callers, both
//! unconditional `bl` (`0x0830a468` and `0x0830a488`); there are no predicated
//! direct calls.
//!
//! The function computes the wrapping product by `0x7f377e0a`. If that
//! intermediate product has its sign bit set, it negates it with wrapping
//! arithmetic, rescales it by `0x7f8899ed`, and stores that result; otherwise
//! it leaves the pointed-to word untouched. It always returns zero. Deliberate
//! deviation: Rust exposes the word as `u32` so wrapping and sign-bit behavior
//! are explicit; the retailOS ABI treats the same storage as `int`.

use core::ptr;

const INITIAL_SCALE: u32 = 0x7f37_7e0a;
const NEGATIVE_PRODUCT_SCALE: u32 = 0x7f88_99ed;

/// Applies retailOS's conditional wrapped-product rescaling to `value`.
///
/// Like retailOS, this function has no null-pointer guard and always returns
/// zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.negative_product_rescale_in_place")]
#[inline(never)]
pub unsafe extern "C" fn negative_product_rescale_in_place(value: *mut u32) -> u32 {
    let product = unsafe { ptr::read(value) }.wrapping_mul(INITIAL_SCALE);
    if (product as i32) < 0 {
        unsafe { ptr::write(value, product.wrapping_neg().wrapping_mul(NEGATIVE_PRODUCT_SCALE)) };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(value: u32) -> u32 {
        let product = value.wrapping_mul(INITIAL_SCALE);
        if (product as i32) < 0 {
            product.wrapping_neg().wrapping_mul(NEGATIVE_PRODUCT_SCALE)
        } else {
            value
        }
    }
    #[test]
    fn leaves_words_with_nonnegative_initial_products_unchanged() {
        for value in [0, 1] {
            let mut actual = value;
            assert_eq!(unsafe { negative_product_rescale_in_place(&mut actual) }, 0);
            assert_eq!(actual, reference(value));
        }
    }

    #[test]
    fn rescales_negative_products_with_wrapping_negation() {
        for value in [0x0000_0002, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let mut actual = value;
            assert_eq!(unsafe { negative_product_rescale_in_place(&mut actual) }, 0);
            assert_eq!(actual, reference(value));
        }
    }
}
