//! String-object ordering predicate used by the 0x083e vector algorithms.
//!
//! The unobserved first ABI argument is a stateless comparator object. The
//! firmware never reads it; its two compared operands are the second and third
//! arguments.

use super::string_object::{string_object_c_str, utf8_strcmp_safe, StringObject};

/// `string_object_less` — original: `FUN_083d6550` @ `0x083d6550` (40 bytes,
/// all code; the next separately linked function begins at `0x083d6578`).
/// **Seven direct `bl` call sites**, all unconditional, were verified by
/// decoding every ARM `B`/`BL` word in `osos.dec`; there are no predicated or
/// tail-`b` callers.
///
/// The stateless ordering functor compares `left.payload` directly against
/// `string_object_c_str(right)`, then returns true exactly when the UTF-8
/// comparison result is negative. Thus a NULL left payload is normalized by
/// `utf8_strcmp_safe`, while a NULL right payload first becomes the shared
/// empty C string through `string_object_c_str`. The comparator-object argument
/// is deliberately not dereferenced because the raw body overwrites `r0` with
/// `right` before its first call.
///
/// Decoded raw ARM: save `r1`, call `string_object_c_str(r2)`, then call
/// `utf8_strcmp_safe(left.payload, returned_c_str)`; `lsrs r0,#31` and
/// `movne r0,#1` normalize every signed-negative result to the C++ `bool` 1.
///
/// Deliberate deviations: none. Both callees are existing direct Rust ports.
///
/// # Safety
/// `left` and `right` must be readable [`StringObject`] instances; both
/// payloads must satisfy their respective C-string contracts. As in retailOS,
/// neither operand is NULL-guarded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_less(
    _comparator: *const u8,
    left: *const StringObject,
    right: *const StringObject,
) -> bool {
    utf8_strcmp_safe((*left).payload, string_object_c_str(right)) < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(payload: *mut u8) -> StringObject {
        StringObject {
            vtable: core::ptr::null(),
            payload,
        }
    }

    #[test]
    fn orders_ascii_utf8_and_null_payloads() {
        let mut apple = *b"apple\0";
        let mut banana = *b"banana\0";
        let mut e_acute = [0xc3, 0xa9, 0];
        let mut e_circumflex = [0xc3, 0xaa, 0];
        let mut empty = [0];
        let apple = object(apple.as_mut_ptr());
        let banana = object(banana.as_mut_ptr());
        let e_acute = object(e_acute.as_mut_ptr());
        let e_circumflex = object(e_circumflex.as_mut_ptr());
        let empty = object(empty.as_mut_ptr());
        let null_payload = object(core::ptr::null_mut());

        unsafe {
            assert!(string_object_less(core::ptr::null(), &apple, &banana));
            assert!(!string_object_less(core::ptr::null(), &banana, &apple));
            assert!(!string_object_less(core::ptr::null(), &apple, &apple));
            assert!(string_object_less(core::ptr::null(), &e_acute, &e_circumflex));
            assert!(string_object_less(core::ptr::null(), &null_payload, &banana));
            assert!(!string_object_less(core::ptr::null(), &banana, &null_payload));
            assert!(!string_object_less(core::ptr::null(), &null_payload, &empty));
        }
    }
}
