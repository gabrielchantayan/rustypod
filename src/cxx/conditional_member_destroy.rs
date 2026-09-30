//! `conditional_member_destroy` — retailOS `FUN_082a7868` @ `0x082a7868`.
//!
//! True extent: 28 bytes, seven A32 words through `0x082a7880`; the next
//! real function starts at `0x082a7884` with two loads and a word comparison.
//! Whole-image raw branch decoding finds two incoming plain BL calls
//! (`0x082a77cc`, `0x082a7ea8`), zero predicated BL calls, and one outgoing
//! plain BL to `shared_handle_owner_destroy` @ `0x082a94d0`.
//! A zero flag returns the record unchanged without touching memory. Otherwise
//! destroy the embedded owner one target word after the record, then subtract
//! one word from the destructor's return value to recover the containing record.
//! Deliberate deviations: reuse the existing Rust owner destructor rather than
//! calling resident firmware; LLVM chooses the conditional return sequence.

use crate::cxx::shared_handle_owner_destroy::shared_handle_owner_destroy;

/// With a nonzero flag, `record` must contain a writable twelve-word owner at
/// word one, with valid owned pointer fields. With zero, no memory is accessed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn conditional_member_destroy(record: *mut u32, destroy_member: u32) -> *mut u32 {
    if destroy_member == 0 {
        record
    } else {
        shared_handle_owner_destroy(record.add(1)).sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::shared_handle_owner_destroy::{CALLBACK_DISPATCH, SHARED_HANDLE_RELEASE};

    #[test]
    fn zero_flag_preserves_null_and_untouched_storage() {
        unsafe {
            assert_eq!(conditional_member_destroy(core::ptr::null_mut(), 0), core::ptr::null_mut());
            let mut words = [0xdead_beef; 14];
            let record = words.as_mut_ptr();
            assert_eq!(conditional_member_destroy(record, 0), record);
            assert_eq!(words, [0xdead_beef; 14]);
        }
    }

    unsafe extern "C" fn mark_callback(owner: *mut u32, event: u32, context: u32) {
        assert_eq!((event, context), (0, 0));
        assert_eq!(owner.read(), 0x089a_8aac);
        owner.add(1).write(0x1234_5678);
    }

    unsafe extern "C" fn mark_release(handle: *mut u32) -> *mut u32 {
        handle.write(0x7654_3210);
        handle
    }

    #[test]
    fn every_nonzero_flag_destroys_offset_owner_and_preserves_container() {
        unsafe {
            let old_callback = CALLBACK_DISPATCH;
            let old_release = SHARED_HANDLE_RELEASE;
            CALLBACK_DISPATCH = mark_callback;
            SHARED_HANDLE_RELEASE = mark_release;
            for flag in [1, 2, 0x8000_0000, u32::MAX] {
                let mut words = [0u32; 14];
                words[0] = 0xaaaa_bbbb;
                words[13] = 0xcccc_dddd;
                let record = words.as_mut_ptr();
                let returned = conditional_member_destroy(record, flag);
                assert_eq!(returned, record);
                assert_eq!(words[0], 0xaaaa_bbbb);
                assert_eq!(words[1], 0x089a_8aac);
                assert_eq!(words[2], 0x1234_5678);
                assert_eq!(words[7], 0x7654_3210);
                assert_eq!(words[13], 0xcccc_dddd);
                assert_eq!(&words[8..13], &[0; 5]);
            }
            CALLBACK_DISPATCH = old_callback;
            SHARED_HANDLE_RELEASE = old_release;
        }
    }
}
