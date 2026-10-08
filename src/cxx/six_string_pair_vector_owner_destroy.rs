//! Reverse member destructor — `FUN_0812bc8c` @ `0x0812bc8c`.
//! True extent: 68 bytes, `[0x0812bc8c, 0x0812bcd0)`; the next function
//! begins with push at 0x0812bcd0. Seven plain outbound BLs, zero
//! predicated BLs; two plain inbound BLs (0x0839c010, 0x0839c054).
//!
//! Destroy the string-pair vector at +60, then StringObject members at
//! +52, +44, +32, +20, +12, +4; return the containing object without
//! deleting it or changing the three opaque words. Both callees return
//! their input pointer, so typed member addresses preserve the stock
//! pointer chain. Deliberate deviation: repr(C) pointer fields widen on
//! hosts; target offsets remain 32-bit ARM offsets. No NULL guard is added.

use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::cxx::string_object_pair_vector_destroy::{
    string_object_pair_vector_destroy, StringObjectPairVector,
};

/// Three opaque words interspersed among six strings, followed by a vector.
#[repr(C)]
pub struct SixStringPairVectorOwner {
    pub header: u32,
    pub first: StringObject,
    pub second: StringObject,
    pub third: StringObject,
    pub word_28: u32,
    pub fourth: StringObject,
    pub word_40: u32,
    pub fifth: StringObject,
    pub sixth: StringObject,
    pub pairs: StringObjectPairVector,
}

/// # Safety
/// `this` must point to a live owner whose member payloads and vector storage
/// satisfy the existing string and string-pair-vector destructor contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn six_string_pair_vector_owner_destroy(
    this: *mut SixStringPairVectorOwner,
) -> *mut SixStringPairVectorOwner {
    unsafe {
        string_object_pair_vector_destroy(core::ptr::addr_of_mut!((*this).pairs));
        string_object_destroy(core::ptr::addr_of_mut!((*this).sixth));
        string_object_destroy(core::ptr::addr_of_mut!((*this).fifth));
        string_object_destroy(core::ptr::addr_of_mut!((*this).fourth));
        string_object_destroy(core::ptr::addr_of_mut!((*this).third));
        string_object_destroy(core::ptr::addr_of_mut!((*this).second));
        string_object_destroy(core::ptr::addr_of_mut!((*this).first));
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{tests::STRING_OBJECT_OPS_TEST_LOCK, STRING_OBJECT_VTABLE};
    use crate::heap::veneers::tests::{mock_heap, free_log};

    fn string(payload: *mut u8) -> StringObject {
        StringObject { vtable: core::ptr::null(), payload }
    }

    #[test]
    fn empty_members_preserve_opaque_words_and_return_owner() {
        let _heap = mock_heap();
        let _strings = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let null = core::ptr::null_mut();
        let mut owner = SixStringPairVectorOwner {
            header: 0x12345678, first: string(null), second: string(null),
            third: string(null), word_28: 0xabcdef01, fourth: string(null),
            word_40: 0xfedcba98, fifth: string(null), sixth: string(null),
            pairs: StringObjectPairVector { begin: null, end: null, capacity: null },
        };
        unsafe { assert_eq!(six_string_pair_vector_owner_destroy(&mut owner), &mut owner as *mut _); }
        assert_eq!((owner.header, owner.word_28, owner.word_40), (0x12345678, 0xabcdef01, 0xfedcba98));
        for member in [&owner.first, &owner.second, &owner.third, &owner.fourth, &owner.fifth, &owner.sixth] {
            assert_eq!(member.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert!(member.payload.is_null());
        }
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn reserved_empty_vector_and_mixed_payloads_release_before_first_string() {
        let _heap = mock_heap();
        let _strings = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let mut payloads = [0u8; 3];
        let mut storage = [0u32; 8];
        let begin = storage.as_mut_ptr().cast::<u8>();
        let null = core::ptr::null_mut();
        let first = payloads.as_mut_ptr();
        let mut owner = SixStringPairVectorOwner {
            header: 7, first: string(first), second: string(null),
            third: string(unsafe { first.add(1) }), word_28: 8, fourth: string(null),
            word_40: 9, fifth: string(null), sixth: string(unsafe { first.add(2) }),
            pairs: StringObjectPairVector { begin, end: begin, capacity: unsafe { begin.add(32) } },
        };
        unsafe { six_string_pair_vector_owner_destroy(&mut owner); }
        assert_eq!(free_log(), (4, first, 0x34));
        assert_eq!((owner.header, owner.word_28, owner.word_40), (7, 8, 9));
        for member in [&owner.first, &owner.second, &owner.third, &owner.fourth, &owner.fifth, &owner.sixth] {
            assert!(member.payload.is_null());
            assert_eq!(member.vtable, &STRING_OBJECT_VTABLE as *const _);
        }
    }
}
