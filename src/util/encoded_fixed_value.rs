//! `encoded_fixed_value` — original: `FUN_080d4020` @ **0x080d4020**
//! (56 bytes, `0x080d4020..0x080d4054`; the next sibling begins at
//! `0x080d4058`). Full-image ARM decoding finds **seven** direct inbound
//! `bl` call sites, all unconditional and none predicated:
//! `0x08087ed8`, `0x080bfdac`, `0x080bfdbc`, `0x080bfdcc`, `0x080bfddc`,
//! `0x080bfdec`, and `0x080bfdf8`.
//!
//! The input is an unchecked byte range. A leading `0x1e` delegates to the
//! retail packed-decimal decoder with scale `3`; every other leading token is
//! decoded by the ported CFF integer helper, converted to Q16.16, then
//! multiplied by 1000 through the retail Q16.16 product helper. The remaining
//! two firmware calls use deterministic host seams. There are no deliberate
//! behavioral deviations.
use crate::ft::cff_parse_integer::cff_parse_integer;

/// Two pointer words consumed by [`encoded_fixed_value`].
///
/// `start` and `end` are the exact `r0` and `r1` arguments forwarded to the
/// retail token decoders. The retail implementation dereferences `start`
/// without a NULL or range guard.
#[repr(C)]
pub struct EncodedValueRange {
    pub start: *const u8,
    pub end: *const u8,
}

type FixedProduct = unsafe extern "C" fn(i32, i32) -> i32;
type PackedDecimalValue = unsafe extern "C" fn(*const u8, *const u8, u32) -> u32;


#[cfg(target_arch = "arm")]
unsafe fn fixed_product(left: i32, right: i32) -> i32 {
    let product: FixedProduct = core::mem::transmute(0x0804_d2ccusize);
    product(left, right)
}

#[cfg(target_arch = "arm")]
unsafe fn packed_decimal_value(start: *const u8, end: *const u8, scale: u32) -> u32 {
    let decoder: PackedDecimalValue = core::mem::transmute(0x0808_7bf8usize);
    decoder(start, end, scale)
}


#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_fixed_product(_: i32, _: i32) -> i32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_packed_decimal_value(_: *const u8, _: *const u8, _: u32) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
#[derive(Clone, Copy)]
struct EncodedFixedValueOps {
    fixed_product: FixedProduct,
    packed_decimal_value: PackedDecimalValue,
}

#[cfg(not(target_arch = "arm"))]
static mut ENCODED_FIXED_VALUE_OPS: EncodedFixedValueOps = EncodedFixedValueOps {
    fixed_product: missing_fixed_product,
    packed_decimal_value: missing_packed_decimal_value,
};


#[cfg(not(target_arch = "arm"))]
unsafe fn fixed_product(left: i32, right: i32) -> i32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(ENCODED_FIXED_VALUE_OPS.fixed_product)))(left, right)
}

#[cfg(not(target_arch = "arm"))]
unsafe fn packed_decimal_value(start: *const u8, end: *const u8, scale: u32) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(ENCODED_FIXED_VALUE_OPS.packed_decimal_value)))(start, end, scale)
}

/// Decodes the firmware's compact or packed-decimal fixed-point token.
///
/// # Safety
///
/// `range` must point to a readable [`EncodedValueRange`]; its `start` must
/// point to a readable token. The selected retail decoder owns the remaining
/// range validity requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.encoded_fixed_value")]
#[inline(never)]
pub unsafe extern "C" fn encoded_fixed_value(range: *const EncodedValueRange) -> u32 {
    let start = (*range).start;
    let end = (*range).end;

    if start.read() == 0x1e {
        return packed_decimal_value(start, end, 3);
    }

    let value_q16 = (cff_parse_integer(start, end) as i32).wrapping_shl(16);
    fixed_product(value_q16, 1000) as u32
}


#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn product(left: i32, right: i32) -> i32 {
        ((left as i64 * right as i64) >> 16) as i32
    }

    struct OpsReset(EncodedFixedValueOps);

    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(ENCODED_FIXED_VALUE_OPS), self.0); }
        }
    }

    #[test]
    fn integer_tokens_produce_scaled_signed_values_and_truncation_zero() {
        let _guard = TEST_LOCK.lock();
        let _reset = OpsReset(unsafe { ptr::read_volatile(ptr::addr_of!(ENCODED_FIXED_VALUE_OPS)) });
        unsafe { ENCODED_FIXED_VALUE_OPS.fixed_product = product; }
        for (bytes, expected) in [
            (&[28, 0xff, 0xfe][..], -2000i32),
            (&[247, 0][..], 108_000),
            (&[251, 0][..], -108_000),
            (&[255, 255][..], -1_387_000),
            (&[28, 0xff][..], 0),
        ] {
            let range = EncodedValueRange {
                start: bytes.as_ptr(), end: unsafe { bytes.as_ptr().add(bytes.len()) },
            };
            assert_eq!(unsafe { encoded_fixed_value(&range) }, expected as u32);
        }
    }
}
