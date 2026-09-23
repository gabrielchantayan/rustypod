//! Destroy the pair of embedded StringObjects at an opaque record's tail.
//!
//! `opaque_record_string_pair_destroy` — original: `FUN_081bd848` @ load
//! address `0x081bd848` (28 bytes, `0x081bd848..0x081bd863`; the next real
//! function begins with `push {r4, lr}` at `0x081bd864`). Whole-image A32
//! decoding finds **3 inbound plain `bl` calls** (0x081bcff4, 0x081bd040, and
//! 0x081bd30c), with **zero predicated `bl` calls**. The body has two plain
//! `bl` calls, both to [`string_object_destroy`] @ 0x08277484.
//!
//! It destroys the StringObject at target offset +0x254, then the one at
//! +0x24c, and returns the original record address. Deliberate deviation: the
//! opaque target prefix is represented by a named `repr(C)` field and the
//! adjacent StringObjects are named fields, rather than performing the ARM
//! byte arithmetic. This preserves the target's 32-bit offsets while keeping
//! host pointers sound.

use crate::cxx::string_object::{string_object_destroy, StringObject};

/// The observed portion of the otherwise unidentified record.
///
/// On target, `first` and `second` begin at +0x24c and +0x254 respectively.
#[repr(C)]
pub struct OpaqueRecordStringPair {
    pub opaque_prefix: [u32; 0x93],
    pub first: StringObject,
    pub second: StringObject,
}

/// `opaque_record_string_pair_destroy` — original: `FUN_081bd848` @
/// 0x081bd848 (28 bytes; 3 plain inbound `bl` calls, no predicated forms).
///
/// Destroys `second` before `first`, then returns `this`. There is no NULL
/// guard or deleting-destructor behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_string_pair_destroy(
    this: *mut OpaqueRecordStringPair,
) -> *mut OpaqueRecordStringPair {
    string_object_destroy(core::ptr::addr_of_mut!((*this).second));
    string_object_destroy(core::ptr::addr_of_mut!((*this).first));
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;

    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    #[test]
    fn destroys_both_tail_strings_and_returns_record() {
        let mut record = OpaqueRecordStringPair {
            opaque_prefix: [0xfeed_beef; 0x93],
            first: StringObject { vtable: ptr::null(), payload: ptr::null_mut() },
            second: StringObject { vtable: ptr::null(), payload: ptr::null_mut() },
        };

        let returned = unsafe { opaque_record_string_pair_destroy(&mut record) };

        assert!(ptr::eq(returned, &mut record));
        assert!(ptr::eq(record.first.vtable, &STRING_OBJECT_VTABLE));
        assert!(ptr::eq(record.second.vtable, &STRING_OBJECT_VTABLE));
        assert!(record.first.payload.is_null());
        assert!(record.second.payload.is_null());
        assert!(record.opaque_prefix.iter().all(|&word| word == 0xfeed_beef));
    }
}
