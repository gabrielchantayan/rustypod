//! `encoded_field_prefix_size` — original: `FUN_08164e9c` @ `0x08164e9c`
//! (40 bytes).
//!
//! Raw `osos.dec` establishes the true body as `0x08164e9c..0x08164ec4`:
//! `ldrb r1,[r0]; mov r0,#0; tst r1,#3; bxeq lr; and r0,r1,#12; mov
//! r1,#1; add r0,r1,r0,lsr#2; cmp r0,#4; bxls lr; bl heap_panic`. The
//! following `ldrb r0,[r0]` starts a separately linked function. Complete-image
//! ARM B/BL decoding finds four inbound plain `bl` calls and no predicated
//! calls: `0x08164a68`, `0x08164af0`, `0x08164e38`, and `0x08164eec`.
//! The low two bits select no prefix or a prefix whose encoded size is bits
//! 2..3 plus one. The raw `cmp`/`bl` fatal path is unreachable: masking to two
//! bits bounds that size to one through four. Deliberate deviation: LLVM
//! removes this dead fatal branch; structured Rust conditionals replace the
//! original predicated returns while preserving the volatile byte read and
//! observable result.

use core::ptr;

const PREFIX_PRESENT_MASK: u8 = 3;
const PREFIX_SIZE_MASK: u8 = 0x0c;

/// Returns the encoded field's prefix size selected by its first byte.
///
/// # Safety
///
/// `encoded_field` must point to a readable byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn encoded_field_prefix_size(encoded_field: *const u8) -> u32 {
    let first_byte = ptr::read_volatile(encoded_field);
    if (first_byte & PREFIX_PRESENT_MASK) == 0 {
        0
    } else {
        ((first_byte & PREFIX_SIZE_MASK) >> 2) as u32 + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_prefix_encodings_return_zero() {
        for first_byte in [0x00, 0x04, 0x08, 0x0c, 0xfc] {
            assert_eq!(unsafe { encoded_field_prefix_size(&first_byte) }, 0, "{first_byte:#04x}");
        }
    }

    #[test]
    fn prefix_encodings_return_the_two_bit_size_plus_one() {
        for (first_byte, expected) in [(0x01, 1), (0x05, 2), (0x09, 3), (0x0d, 4), (0xed, 4)] {
            assert_eq!(unsafe { encoded_field_prefix_size(&first_byte) }, expected, "{first_byte:#04x}");
        }
    }

    #[test]
    fn every_byte_matches_the_bounded_prefix_reference() {
        for first_byte in u8::MIN..=u8::MAX {
            let expected = if (first_byte & PREFIX_PRESENT_MASK) == 0 {
                0
            } else {
                ((first_byte & PREFIX_SIZE_MASK) >> 2) as u32 + 1
            };
            assert_eq!(unsafe { encoded_field_prefix_size(&first_byte) }, expected, "{first_byte:#04x}");
        }
    }
}
