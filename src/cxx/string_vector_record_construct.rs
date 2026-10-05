//! Default string/vector record constructor — `FUN_08197a74` @ `0x08197a74`.
//!
//! True size: 32 bytes, `0x08197a74..0x08197a94`; the successor starts with
//! its own push at `0x08197a94`. Raw words verify two outbound plain BLs and
//! zero predicated BLs. Whole-image decoding finds two inbound plain BLs at
//! `0x08197b44` and `0x082aae5c`, with no predicated calls.
//! Initializes the COW string with the shared empty representation, clears
//! the adjacent vector's three bounds, and returns the original record.
//! Both verified callees are existing Rust ports. Deliberate deviations:
//! unused r2/r3 spills and allocator addresses in r1 are omitted; host repr(C)
//! pointers widen, so host builds clear pointer fields rather than 12 bytes.

use core::ptr;
use super::string::cxx_string_default_ctor;
use super::string_vector_key_construct::StringVectorRecord;

#[cfg(target_pointer_width = "32")]
const _: [u8; 4] = [0; core::mem::offset_of!(StringVectorRecord, vector)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 16] = [0; core::mem::size_of::<StringVectorRecord>()];

/// # Safety
/// `record` must be aligned writable storage for a `StringVectorRecord`.
/// This is construction, not assignment: existing owned members are not released.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_vector_record_construct(
    record: *mut StringVectorRecord,
) -> *mut StringVectorRecord {
    cxx_string_default_ctor(ptr::addr_of_mut!((*record).string));
    #[cfg(target_os = "none")]
    super::three_word_clear_return::three_word_clear_return(ptr::addr_of_mut!((*record).vector).cast());
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!((*record).vector.begin).write(ptr::null_mut());
        ptr::addr_of_mut!((*record).vector.end).write(ptr::null_mut());
        ptr::addr_of_mut!((*record).vector.capacity).write(ptr::null_mut());
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::string::empty_rep_data;

    #[test]
    fn constructs_uninitialized_storage_without_touching_neighbors() {
        let mut storage = [usize::MAX; 6];
        let record = unsafe { storage.as_mut_ptr().add(1).cast::<StringVectorRecord>() };
        unsafe {
            assert_eq!(string_vector_record_construct(record), record);
            assert_eq!((*record).string, empty_rep_data());
            assert_eq!((*record).string.read(), 0);
            assert!((*record).vector.begin.is_null());
            assert!((*record).vector.end.is_null());
            assert!((*record).vector.capacity.is_null());
        }
        assert_eq!(storage[0], usize::MAX);
        assert_eq!(storage[5], usize::MAX);
    }

    #[test]
    fn adjacent_records_share_empty_string_but_have_independent_vector_heads() {
        let mut storage = [usize::MAX; 8];
        let first = storage.as_mut_ptr().cast::<StringVectorRecord>();
        unsafe {
            let second = first.add(1);
            string_vector_record_construct(first);
            string_vector_record_construct(second);
            (*first).vector.begin = ptr::addr_of_mut!((*first).string).cast();
            assert_eq!((*first).string, (*second).string);
            assert_eq!((*second).string, empty_rep_data());
            assert!((*second).vector.begin.is_null());
            assert!((*second).vector.end.is_null());
            assert!((*second).vector.capacity.is_null());
        }
    }
}
