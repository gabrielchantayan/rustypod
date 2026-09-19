//! ASN.1 INTEGER conversion used by the vendored OpenSSL object code.
//!
//! `asn1_integer_get` — original: `FUN_08039f74` @ 0x08039f74 (124 bytes,
//! 0x08039f74..0x08039ff0; the next separately linked function begins at
//! 0x08039ff0). Raw ARM has no outbound `bl` instructions; full-image A32
//! decoding finds four plain inbound `bl` calls (0x080ce280, 0x080ce300,
//! 0x080f50f0, 0x082b4b58) and no predicated inbound `bl` calls.
//!
//! The target's three-word `ASN1_STRING` header supplies a byte length, a
//! type, and a big-endian magnitude pointer. NULL headers or payloads return
//! zero. Only `V_ASN1_INTEGER` (2) and `V_ASN1_NEG_INTEGER` (0x102) with at
//! most four payload bytes are accepted; invalid headers return -1. Negative
//! magnitudes are negated after accumulation.
//!
//! Deliberate deviations: none.

const ASN1_INTEGER: u32 = 2;
const ASN1_NEG_INTEGER: u32 = 0x102;

/// Converts a target-layout ASN.1 INTEGER to a signed 32-bit value.
///
/// # Safety
///
/// `value` must be NULL or point to three readable target words. For a
/// non-NULL payload, its `length` bytes must be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn asn1_integer_get(value: *const u32) -> i32 {
    if value.is_null() {
        return 0;
    }

    let length = unsafe { value.read() };
    let kind = unsafe { value.add(1).read() };
    if (kind != ASN1_INTEGER && kind != ASN1_NEG_INTEGER) || length > 4 {
        return -1;
    }

    let data = unsafe { value.add(2).read() } as usize as *const u8;
    if data.is_null() {
        return 0;
    }

    let mut result = 0u32;
    for index in 0..length as usize {
        result = unsafe { data.add(index).read() as u32 } | (result << 8);
    }
    if kind == ASN1_NEG_INTEGER {
        result.wrapping_neg() as i32
    } else {
        result as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ASN1_INTEGER_GET, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<*mut u32> {
        let slab = *SLAB;
        if slab.is_none() {
            assert!(note_missing_u32_fixture("crypto/asn1_integer_get"));
        }
        let base = slab? as *mut u32;
        unsafe { core::ptr::write_bytes(base.cast::<u8>(), 0, SLAB_LEN); }
        Some(base)
    }

    unsafe fn set_integer(base: *mut u32, length: u32, kind: u32, bytes: &[u8]) {
        unsafe {
            base.write(length);
            base.add(1).write(kind);
            base.add(2).write(base.add(4) as usize as u32);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(4).cast::<u8>(), bytes.len());
        }
    }

    #[test]
    fn null_and_null_payload_return_zero() {
        let _guard = TEST_LOCK.lock();
        assert_eq!(unsafe { asn1_integer_get(core::ptr::null()) }, 0);
        let Some(base) = (unsafe { fixture() }) else { return };
        unsafe { set_integer(base, 1, ASN1_INTEGER, &[1]); base.add(2).write(0); }
        assert_eq!(unsafe { asn1_integer_get(base) }, 0);
    }

    #[test]
    fn accumulates_big_endian_magnitudes_through_four_bytes() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return };
        unsafe { set_integer(base, 4, ASN1_INTEGER, &[0x12, 0x34, 0x56, 0x78]); }
        assert_eq!(unsafe { asn1_integer_get(base) }, 0x1234_5678);
    }

    #[test]
    fn negates_negative_integer_magnitude() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return };
        unsafe { set_integer(base, 3, ASN1_NEG_INTEGER, &[0x12, 0x34, 0x56]); }
        assert_eq!(unsafe { asn1_integer_get(base) }, -0x123456);
    }

    #[test]
    fn rejects_unknown_type_and_oversized_payload() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return };
        unsafe { set_integer(base, 1, 3, &[1]); }
        assert_eq!(unsafe { asn1_integer_get(base) }, -1);
        unsafe { set_integer(base, 5, ASN1_INTEGER, &[1, 2, 3, 4, 5]); }
        assert_eq!(unsafe { asn1_integer_get(base) }, -1);
    }
}
