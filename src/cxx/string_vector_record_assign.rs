//! `cxx_string_vector_record_assign` — `FUN_08197c68` @ 0x08197c68.
//!
//! True size: 44 bytes, ending at 0x08197c94 (the next function's push).
//! Raw A32 decoding finds two outgoing plain BLs and zero predicated BLs;
//! whole-image decoding finds two inbound plain BLs (0x080e40f8,
//! 0x082aaf94), zero predicated forms. Assigns the leading COW string,
//! assigns the embedded vector of string/vector records, copies the byte at
//! target +0x10, and returns destination, including for self-assignment.
//!
//! Deliberate deviations: the unported record-vector assignment remains a
//! direct firmware seam at 0x083e25a4. Named repr(C) fields preserve target
//! layout while permitting native-width host pointers. Ghidra's extra vector
//! arguments are saved scratch registers, not inputs; only r0/r1 are passed.

use super::string_vector_record_destroy::StringVectorRecord;
use super::string_vector_record_destroy::StringVectorRecordVector;

/// The four-word string/vector header followed by an uninterpreted flag byte.
#[repr(C)]
pub struct FlaggedStringVectorRecord {
    pub header: StringVectorRecord,
    pub flag: u8,
}

type StringAssign = unsafe extern "C" fn(*mut *mut u8, *const *mut u8) -> *mut *mut u8;
type VectorAssign = unsafe extern "C" fn(
    *mut StringVectorRecordVector, *const StringVectorRecordVector,
) -> *mut StringVectorRecordVector;

/// Assigns an initialized record without bypassing either member's ownership rules.
///
/// # Safety
/// Both pointers must designate live records with valid initialized COW strings
/// and record vectors. Destination must be writable; exact self-aliasing is valid.
/// The firmware vector seam is only executable on the target device.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_vector_record_assign(
    destination: *mut FlaggedStringVectorRecord,
    source: *const FlaggedStringVectorRecord,
) -> *mut FlaggedStringVectorRecord {
    let assign_vector: VectorAssign = unsafe { core::mem::transmute(0x083e_25a4usize) };
    unsafe {
        assign_with(destination, source, super::string::cxx_string_assign, assign_vector)
    }
}

#[inline(always)]
unsafe fn assign_with(
    destination: *mut FlaggedStringVectorRecord,
    source: *const FlaggedStringVectorRecord,
    assign_string: StringAssign,
    assign_vector: VectorAssign,
) -> *mut FlaggedStringVectorRecord {
    unsafe {
        assign_string(
            core::ptr::addr_of_mut!((*destination).header.string),
            core::ptr::addr_of!((*source).header.string),
        );
        assign_vector(
            core::ptr::addr_of_mut!((*destination).header.records),
            core::ptr::addr_of!((*source).header.records),
        );
        (*destination).flag = (*source).flag;
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::*;

    // Isolate the local byte-copy behavior from the unported firmware operation.
    unsafe extern "C" fn preserve_string(p: *mut *mut u8, _: *const *mut u8) -> *mut *mut u8 { p }
    unsafe extern "C" fn preserve_vector(
        p: *mut StringVectorRecordVector, _: *const StringVectorRecordVector,
    ) -> *mut StringVectorRecordVector { p }

    #[repr(C)]
    struct Fixture { record: FlaggedStringVectorRecord, guard: [u8; 8] }

    fn fixture(flag: u8) -> Fixture {
        Fixture {
            record: FlaggedStringVectorRecord {
                header: StringVectorRecord {
                    string: core::ptr::null_mut(),
                    records: StringVectorRecordVector {
                        begin: core::ptr::null_mut(), end: core::ptr::null_mut(),
                        capacity: core::ptr::null_mut(),
                    },
                },
                flag,
            },
            guard: [0xa5; 8],
        }
    }

    #[test]
    fn copies_all_flag_bits_without_touching_neighbors() {
        for flag in 0..=255u8 {
            let source = fixture(flag);
            let mut destination = fixture(!flag);
            let returned = unsafe {
                assign_with(&mut destination.record, &source.record, preserve_string, preserve_vector)
            };
            assert_eq!(returned, core::ptr::addr_of_mut!(destination.record));
            assert_eq!(destination.record.flag, flag);
            assert_eq!(destination.guard, [0xa5; 8]);
            assert_eq!(source.record.flag, flag);
            assert_eq!(source.guard, [0xa5; 8]);
        }
    }

    #[test]
    fn self_assignment_preserves_non_boolean_flag() {
        let mut value = fixture(0xd7);
        let p = core::ptr::addr_of_mut!(value.record);
        unsafe { assert_eq!(assign_with(p, p, preserve_string, preserve_vector), p); }
        assert_eq!(value.record.flag, 0xd7);
        assert_eq!(value.guard, [0xa5; 8]);
    }
}
