//! Teardown of an unidentified record with two opaque words and two strings.
//!
//! `header_string_pair_destroy` — `FUN_082800f8` @ `0x082800f8`, 28 bytes
//! (`0x082800f8..0x08280114`, exclusive; next function starts at 0x08280114).
//! Raw A32 decoding verifies two internal plain BLs to string_object_destroy
//! @ 0x08277484, zero predicated BLs, and two inbound plain BLs at
//! 0x0839c72c and 0x0839c77c (zero predicated inbound BLs).
//!
//! Destroy the string at target +0x10, then the string at +0x08, and return
//! the record base. Both helper returns equal their arguments; the original
//! subtracts eight after each call. The opaque header remains untouched.
//! No NULL guard or storage deallocation is present.
//!
//! Deliberate deviation: repr(C) member addressing accommodates host pointer
//! widening rather than applying target byte offsets to host objects. The
//! known helper's return-this contract permits returning the original base.

use crate::cxx::string_object::{string_object_destroy, StringObject};

#[repr(C)]
pub struct HeaderStringPair {
    /// Target +0x00..+0x07; meaning not recovered.
    pub words: [u32; 2],
    /// Target +0x08.
    pub first: StringObject,
    /// Target +0x10.
    pub second: StringObject,
}

/// `this` must point to a writable record with valid StringObject payloads.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn header_string_pair_destroy(
    this: *mut HeaderStringPair,
) -> *mut HeaderStringPair {
    string_object_destroy(core::ptr::addr_of_mut!((*this).second));
    string_object_destroy(core::ptr::addr_of_mut!((*this).first));
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{
        tests::STRING_OBJECT_OPS_TEST_LOCK, STRING_OBJECT_VTABLE,
    };
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use core::ptr;

    #[test]
    fn teardown_preserves_header_releases_reverse_order_and_is_repeatable() {
        let _heap = mock_heap();
        let _lock = STRING_OBJECT_OPS_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // Exercise both NULL boundaries as well as two live payloads.
        for mask in 0..4 {
            let mut first_storage = [0u8; 8];
            let mut second_storage = [0u8; 8];
            let first = if mask & 1 != 0 { first_storage.as_mut_ptr() } else { ptr::null_mut() };
            let second = if mask & 2 != 0 { second_storage.as_mut_ptr() } else { ptr::null_mut() };
            let mut record = HeaderStringPair {
                words: [0x1122_3344, 0xaabb_ccdd],
                first: StringObject { vtable: ptr::null(), payload: first },
                second: StringObject { vtable: ptr::null(), payload: second },
            };
            let this = ptr::addr_of_mut!(record);
            let before = free_log().0;
            assert_eq!(unsafe { header_string_pair_destroy(this) }, this);
            assert_eq!(record.words, [0x1122_3344, 0xaabb_ccdd]);
            assert_eq!(record.first.vtable, ptr::addr_of!(STRING_OBJECT_VTABLE));
            assert_eq!(record.second.vtable, ptr::addr_of!(STRING_OBJECT_VTABLE));
            assert!(record.first.payload.is_null());
            assert!(record.second.payload.is_null());
            let (calls, last_freed, tag) = free_log();
            assert_eq!(calls - before, (mask & 1) + ((mask >> 1) & 1));
            if mask != 0 {
                // With both live, the first member must be freed LAST.
                assert_eq!(last_freed, if mask & 1 != 0 { first } else { second });
                assert_eq!(tag, 0x34);
            }
            assert_eq!(unsafe { header_string_pair_destroy(this) }, this);
            assert_eq!(free_log().0, calls, "repeated teardown must not double-free");
        }
    }
}
