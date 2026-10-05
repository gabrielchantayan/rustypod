//! Copy constructor for an unidentified flagged string record.
//!
//! Original: `FUN_081b01f8` @ 0x081b01f8, 52 bytes, extent
//! [0x081b01f8, 0x081b022c); the next function is the independently called
//! string-owner destructor. Raw A32 words verify two inbound plain BLs
//! (0x081b01d0, 0x083d6394), one outbound plain BL to 0x082773e0,
//! and zero predicated BLs in either set.
//!
//! Copy the byte at +0 and word at +4, copy-construct the StringObject at
//! +8, then copy the word at +0x10 through the callee's returned enclosing
//! pointer and return it. Padding at +1..+3 is untouched. No NULL guard.
//! Deliberate deviation: repr(C) widens StringObject pointers on hosts,
//! moving the trailing word while retaining the embedded string's +8 offset.
//! Uses the existing string_object_copy_construct port, including its modeled
//! vtable; no new seam. The flag and opaque word meanings remain unknown.

use crate::cxx::string_object::{string_object_copy_construct, StringObject};

#[repr(C)]
pub struct FlaggedStringRecord {
    pub flag: u8,
    pub padding: [u8; 3],
    pub opaque_word: u32,
    pub string: StringObject,
    pub trailing_word: u32,
}

/// Safety: both pointers must address valid aligned records; destination
/// must be writable raw storage or the source itself. Source payload must
/// satisfy the StringObject copy constructor's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn flagged_string_record_copy_construct(
    destination: *mut FlaggedStringRecord,
    source: *const FlaggedStringRecord,
) -> *mut FlaggedStringRecord {
    (*destination).flag = (*source).flag;
    (*destination).opaque_word = (*source).opaque_word;
    let string = string_object_copy_construct(
        core::ptr::addr_of_mut!((*destination).string),
        core::ptr::addr_of!((*source).string),
    );
    let result = (string as *mut u8).sub(8) as *mut FlaggedStringRecord;
    (*result).trailing_word = (*source).trailing_word;
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::string_object::{StringObjectAssignCstrOps,
        STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_VTABLE};

    struct OpsGuard(StringObjectAssignCstrOps);
    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write(self.0); }
        }
    }

    unsafe extern "C" fn allocate(this: *mut StringObject, size: usize, _: u32) -> *mut u8 {
        let storage = std::vec![0xa5u8; size].into_boxed_slice();
        let pointer = std::boxed::Box::into_raw(storage) as *mut u8;
        (*this).payload = pointer;
        pointer
    }
    unsafe extern "C" fn fail(_: *mut StringObject, _: usize, _: u32) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe extern "C" fn clear(this: *mut StringObject) {
        (*this).payload = core::ptr::null_mut();
    }
    fn record(payload: *mut u8) -> FlaggedStringRecord {
        FlaggedStringRecord {
            flag: 0x80, padding: [1, 2, 3], opaque_word: u32::MAX,
            string: StringObject { vtable: core::ptr::null(), payload },
            trailing_word: 0x80000000,
        }
    }

    #[test]
    fn copies_fields_and_string_without_copying_padding_even_when_allocation_fails() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK
            .lock().unwrap_or_else(|p| p.into_inner());
        let _guard = OpsGuard(unsafe { core::ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read() });
        for payload in [None, Some(&b"\0"[..]), Some(&b"record\0"[..])] {
            for allocation_fails in [false, true] {
                unsafe {
                    core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write(
                        StringObjectAssignCstrOps {
                            allocate_payload: if allocation_fails { fail } else { allocate },
                            clear_payload: clear,
                        });
                }
                let source_pointer = payload.map_or(core::ptr::null_mut(), |s| s.as_ptr() as *mut u8);
                let source = record(source_pointer);
                let mut destination = record(0xdeadbeefusize as *mut u8);
                destination.flag = 0;
                destination.padding = [0xa5; 3];
                destination.opaque_word = 0;
                destination.trailing_word = 0;
                let returned = unsafe { flagged_string_record_copy_construct(&mut destination, &source) };
                assert_eq!(returned, &mut destination as *mut _);
                assert_eq!(destination.flag, 0x80);
                assert_eq!(destination.padding, [0xa5; 3]);
                assert_eq!(destination.opaque_word, u32::MAX);
                assert_eq!(destination.trailing_word, 0x80000000);
                assert_eq!(destination.string.vtable, &STRING_OBJECT_VTABLE as *const _);
                assert_eq!(source.string.payload, source_pointer);
                if let Some(bytes) = payload.filter(|s| s.len() > 1 && !allocation_fails) {
                    assert_ne!(destination.string.payload, source_pointer);
                    unsafe {
                        let slice = core::ptr::slice_from_raw_parts_mut(destination.string.payload, bytes.len());
                        let storage = std::boxed::Box::from_raw(slice);
                        assert_eq!(&*storage, bytes);
                    }
                } else {
                    assert!(destination.string.payload.is_null());
                }
            }
        }
    }

    #[test]
    fn self_construction_preserves_payload_and_all_record_bytes_except_vtable() {
        let mut bytes = *b"self\0";
        let mut object = record(bytes.as_mut_ptr());
        let pointer = &mut object as *mut FlaggedStringRecord;
        assert_eq!(unsafe { flagged_string_record_copy_construct(pointer, pointer) }, pointer);
        assert_eq!(object.flag, 0x80);
        assert_eq!(object.padding, [1, 2, 3]);
        assert_eq!(object.opaque_word, u32::MAX);
        assert_eq!(object.trailing_word, 0x80000000);
        assert_eq!(object.string.payload, bytes.as_mut_ptr());
        assert_eq!(&bytes, b"self\0");
        assert_eq!(object.string.vtable, &STRING_OBJECT_VTABLE as *const _);
    }
}
