//! Assignment for an unidentified 0x1c-byte record containing three opaque
//! words followed by two [`StringObject`] members.
//!
//! `two_string_record_assign` — original: `FUN_08267864` @ `0x08267864`
//! (68 bytes, `0x08267864..0x082678a8`). Raw ARM has two unconditional
//! internal `bl 0x082774a8` instructions and no predicated internal BL; a
//! whole-image B/BL decode finds four unconditional inbound BL sites and no
//! predicated inbound sites. It copies the three leading words, assigns each
//! embedded StringObject in order, and returns `this`.
//!
//! Deliberate deviation: `repr(C)` preserves the target's 32-bit member order
//! on ARM while allowing StringObject pointers to widen on host tests.

use crate::cxx::string_object::{string_object_assign, string_object_destroy, StringObject};

/// The target's 0x1c-byte record; its role is not yet identified.
#[repr(C)]
pub struct TwoStringRecord {
    /// +0x00..+0x08 — copied without interpretation.
    pub words: [u32; 3],
    /// +0x0c — assigned before `second`.
    pub first: StringObject,
    /// +0x14 — assigned after `first`.
    pub second: StringObject,
}

/// Copy the opaque header and assign both embedded string objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_string_record_assign(
    this: *mut TwoStringRecord,
    source: *const TwoStringRecord,
) -> *mut TwoStringRecord {
    (*this).words[0] = (*source).words[0];
    (*this).words[1] = (*source).words[1];
    (*this).words[2] = (*source).words[2];
    string_object_assign(&mut (*this).first, &(*source).first);
    string_object_assign(&mut (*this).second, &(*source).second);
    this
}

/// two_string_record_destroy — original: `FUN_08267848` @ `0x08267848`
/// (28 bytes, `0x08267848..0x08267863`; the next separately linked function
/// begins at `0x08267864`). Whole-image ARM B/BL decoding finds **3 inbound
/// plain `bl` calls** and zero predicated calls.
///
/// Destroys the embedded StringObjects in reverse member order: `second` at
/// target offset +0x14, then `first` at +0x0c. The raw return derives `this`
/// from the second destructor's return (`sub r0, r0, #0xc`); both values are
/// the original record base. The three opaque header words are untouched.
///
/// Deliberate deviation: native-widened host StringObject fields are addressed
/// by their `repr(C)` members rather than ARM byte offsets. Both direct
/// callees are the ported `string_object_destroy`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_string_record_destroy(
    this: *mut TwoStringRecord,
) -> *mut TwoStringRecord {
    string_object_destroy(&mut (*this).second);
    string_object_destroy(&mut (*this).first);
    this
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, StringObjectVtable, STRING_OBJECT_ASSIGN_CSTR_OPS,
        STRING_OBJECT_VTABLE,
    };
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;
    use core::ptr;
    use std::sync::MutexGuard;

    static mut CLEARED: [usize; 2] = [0; 2];
    static mut CLEAR_COUNT: usize = 0;

    unsafe extern "C" fn no_allocate(
        _this: *mut StringObject,
        _requested_size: usize,
        _flags: u32,
    ) -> *mut u8 {
        ptr::null_mut()
    }

    unsafe extern "C" fn record_clear(this: *mut StringObject) {
        CLEARED[CLEAR_COUNT] = this as usize;
        CLEAR_COUNT += 1;
    }

    struct StringOpsGuard {
        _lock: MutexGuard<'static, ()>,
        saved: StringObjectAssignCstrOps,
    }

    impl Drop for StringOpsGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(self.saved);
            }
        }
    }

    fn record_clears() -> StringOpsGuard {
        let lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read_volatile();
            ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(StringObjectAssignCstrOps {
                allocate_payload: no_allocate,
                clear_payload: record_clear,
            });
            CLEARED = [0; 2];
            CLEAR_COUNT = 0;
            StringOpsGuard { _lock: lock, saved }
        }
    }

    fn empty_string() -> StringObject {
        StringObject {
            vtable: ptr::null::<StringObjectVtable>(),
            payload: ptr::null_mut(),
        }
    }

    #[test]
    fn copies_header_and_assigns_embedded_strings_in_order() {
        let _guard = record_clears();
        let mut destination = TwoStringRecord {
            words: [0; 3],
            first: empty_string(),
            second: empty_string(),
        };
        let source = TwoStringRecord {
            words: [0x1122_3344, 0x5566_7788, 0x99aa_bbcc],
            first: empty_string(),
            second: empty_string(),
        };

        let returned = unsafe { two_string_record_assign(&mut destination, &source) };

        assert_eq!(returned, ptr::addr_of_mut!(destination));
        assert_eq!(destination.words, source.words);
        assert_eq!(unsafe { CLEAR_COUNT }, 2);
        assert_eq!(unsafe { CLEARED }, [ptr::addr_of_mut!(destination.first) as usize, ptr::addr_of_mut!(destination.second) as usize]);
    }

    #[test]
    fn self_assignment_skips_both_string_payload_assignments() {
        let _guard = record_clears();
        let mut record = TwoStringRecord {
            words: [7, 8, 9],
            first: empty_string(),
            second: empty_string(),
        };
        let record_ptr = ptr::addr_of_mut!(record);

        let returned = unsafe { two_string_record_assign(record_ptr, record_ptr) };

        assert_eq!(returned, record_ptr);
        assert_eq!(record.words, [7, 8, 9]);
    }

    #[test]
    fn destroy_keeps_header_and_destroys_strings_in_reverse_member_order() {
        let mut record = TwoStringRecord {
            words: [0x1122_3344, 0x5566_7788, 0x99aa_bbcc],
            first: StringObject {
                vtable: 0xdead_beefusize as *const StringObjectVtable,
                payload: ptr::null_mut(),
            },
            second: StringObject {
                vtable: 0xcafe_f00dusize as *const StringObjectVtable,
                payload: ptr::null_mut(),
            },
        };
        let this = ptr::addr_of_mut!(record);

        assert_eq!(unsafe { two_string_record_destroy(this) }, this);
        assert_eq!(record.words, [0x1122_3344, 0x5566_7788, 0x99aa_bbcc]);
        assert_eq!(record.first.vtable, &STRING_OBJECT_VTABLE as *const _);
        assert_eq!(record.second.vtable, &STRING_OBJECT_VTABLE as *const _);
    }
}
