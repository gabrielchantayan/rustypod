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

use crate::cxx::string_object::{string_object_assign, StringObject};

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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, StringObjectVtable, STRING_OBJECT_ASSIGN_CSTR_OPS,
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
}
