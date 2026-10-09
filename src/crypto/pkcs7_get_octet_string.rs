//! OpenSSL's PKCS7 octet-string content accessor.
//!
//! `pkcs7_get_octet_string` — retailOS `FUN_080c6930` @ 0x080c6930,
//! 92 bytes, extent [0x080c6930, 0x080c698c); the next function starts
//! with `push {r4,r5,lr}`. Raw aligned A32 decoding verifies two incoming
//! plain BL calls (0x0805fbc0, 0x080602e4), zero predicated incoming BLs,
//! and two outgoing plain BLs to OBJ_obj2nid, zero predicated outgoing BLs.
//!
//! Return the union's data pointer for NID 21. Otherwise resolve the type
//! again, reject the unsigned wrapping range NIDs 21..=26, and return the
//! value of a non-NULL ASN1_TYPE only when its tag is OCTET STRING (4).
//! Deliberate deviations: none in this accessor; uses the existing Rust
//! OBJ_obj2nid port (and its documented database deviations). Target-width
//! pointer words remain four bytes apart on hosts too.

use super::obj_dat::{obj_obj2nid, Asn1Object};
use super::pkcs7_set_detached::Pkcs7;
use core::ptr;

/// Extracts the ASN1_STRING pointer without transferring ownership.
///
/// # Safety
/// `message` must contain six readable target-width words. Word 4 must be
/// NULL or point to a valid ASN1_OBJECT; for nonstandard types word 5 must
/// be NULL or point to two readable ASN1_TYPE words. Returned storage has
/// the lifetime and validity supplied by the caller's message.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pkcs7_get_octet_string(message: *const Pkcs7) -> *mut u8 {
    let words = message.cast::<u32>();
    let object = ptr::read_volatile(words.add(4)) as usize as *const Asn1Object;
    if obj_obj2nid(object) == 21 {
        return ptr::read_volatile(words.add(5)) as usize as *mut u8;
    }
    let object = ptr::read_volatile(words.add(4)) as usize as *const Asn1Object;
    if (obj_obj2nid(object) as u32).wrapping_sub(21) <= 5 {
        return ptr::null_mut();
    }
    let other = ptr::read_volatile(words.add(5)) as usize as *const u32;
    if !other.is_null() && other.read() == 4 {
        other.add(1).read() as usize as *mut u8
    } else {
        ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn data_standard_types_and_other_asn1_tags() {
        let Some(slab) = try_map_u32_slab(hints::PKCS7_GET_OCTET_STRING, 4096) else { return };
        let object = slab.cast::<Asn1Object>();
        let other = unsafe { slab.add(128).cast::<u32>() };
        unsafe {
            object.write(Asn1Object {
                sn: ptr::null(), ln: ptr::null(), nid: 21, length: 0,
                data: ptr::null(), flags: 0,
            });
        }
        let mut message = [0u32; 6];
        message[4] = object as usize as u32;
        // Direct data is returned without examining it, even if not readable.
        message[5] = 0x1234_5678;
        let call = |words: &[u32; 6]| unsafe { pkcs7_get_octet_string(words.as_ptr().cast()) as usize };
        assert_eq!(call(&message), 0x1234_5678);
        message[5] = 0;
        assert_eq!(call(&message), 0);
        for nid in 22..=26 {
            unsafe { (*object).nid = nid };
            message[5] = 1; // Rejected types must not dereference the union.
            assert_eq!(call(&message), 0, "nid={nid}");
        }
        for nid in [i32::MIN, -1, 1, 20, 27, i32::MAX] {
            unsafe { (*object).nid = nid };
            message[5] = 0;
            assert_eq!(call(&message), 0, "NULL other, nid={nid}");
            message[5] = other as usize as u32;
            for tag in [0, 3, 4, 5, u32::MAX] {
                unsafe { other.write(tag); other.add(1).write(0x8765_4321) };
                assert_eq!(call(&message), if tag == 4 { 0x8765_4321 } else { 0 }, "nid={nid}, tag={tag}");
            }
            unsafe { other.write(4); other.add(1).write(0) };
            assert_eq!(call(&message), 0);
        }
        // NULL ASN1_OBJECT resolves to NID_undef, taking the other-type path.
        message[4] = 0;
        unsafe { other.write(4); other.add(1).write(0x8765_4321) };
        assert_eq!(call(&message), 0x8765_4321);
    }
}
