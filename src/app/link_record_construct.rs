use crate::cxx::string_object::{
    StringObject, string_default_construct, string_object_assign_payload, string_object_c_str,
};

/// Link record allocated as 0x24 bytes by the callers at 0x08118aac and
/// 0x08118d24. Pointer-bearing StringObjects widen naturally on hosts.
#[repr(C)]
pub struct LinkRecord {
    pub start_index: u32,
    pub end_index: u32,
    pub destination: StringObject,
    pub anchor: StringObject,
    pub flags: [u8; 4],
    pub auxiliary_first: u32,
    pub auxiliary_second: u32,
}

/// link_record_construct — FUN_08280040 @ 0x08280040, 184 bytes.
/// Raw A32 ends with pop at 0x082800f4; the next function starts at
/// 0x082800f8. Two inbound plain BLs, zero predicated BLs; the body has
/// six plain BLs and zero predicated BLs.
///
/// Stores the index pair, default-constructs destination and anchor, packs
/// enabled into bit 0, kind into bits 1..2, and alternate into bit 7, then
/// stores the secondary flag byte and clears the two auxiliary words.
/// Bits 3..6 are cleared; flag bytes 2..3 remain untouched. Only when the
/// resulting bit 0 is set are non-NULL source objects copied via c_str and
/// assign_payload, destination first. The enabled argument is ORed without
/// boolean normalization, matching the raw register operation.
///
/// Deliberate deviations: repr(C) pointer fields widen on hosts; the existing
/// StringObject ports retain their modeled vtable/allocation boundary. No new
/// seam is introduced. The semantic link name follows the callers' scheme,
/// anchor and bad-link processing; the auxiliary words remain opaque.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn link_record_construct(
    this: *mut LinkRecord,
    start_index: u32,
    end_index: u32,
    enabled: u32,
    kind: u32,
    alternate: u32,
    secondary_flags: u32,
    destination: *const StringObject,
    anchor: *const StringObject,
) -> *mut LinkRecord {
    (*this).start_index = start_index;
    (*this).end_index = end_index;
    string_default_construct(core::ptr::addr_of_mut!((*this).destination));
    string_default_construct(core::ptr::addr_of_mut!((*this).anchor));
    let flags = ((*this).flags[0] & !1) | enabled as u8;
    let flags = (flags & !6) | ((kind & 3) << 1) as u8;
    (*this).flags[0] = (flags & 7) | alternate.wrapping_shl(7) as u8;
    (*this).flags[1] = secondary_flags as u8;
    (*this).auxiliary_first = 0;
    (*this).auxiliary_second = 0;
    if (*this).flags[0] & 1 != 0 {
        if !destination.is_null() {
            string_object_assign_payload(
                core::ptr::addr_of_mut!((*this).destination), string_object_c_str(destination),
            );
        }
        if !anchor.is_null() {
            string_object_assign_payload(
                core::ptr::addr_of_mut!((*this).anchor), string_object_c_str(anchor),
            );
        }
    }
    this
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_VTABLE,
    };
    use std::boxed::Box;

    static mut FAIL_ALLOCATION: bool = false;

    unsafe extern "C" fn allocate(this: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert_eq!(flags, 0);
        assert!(size <= 64);
        if FAIL_ALLOCATION { return core::ptr::null_mut(); }
        let storage = Box::into_raw(Box::new([0xccu8; 64])) as *mut u8;
        (*this).payload = storage;
        storage
    }

    unsafe extern "C" fn clear(this: *mut StringObject) {
        (*this).payload = core::ptr::null_mut();
    }

    struct Restore(StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { STRING_OBJECT_ASSIGN_CSTR_OPS = self.0; }
        }
    }

    fn record(flags: [u8; 4]) -> LinkRecord {
        let empty = || StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() };
        LinkRecord {
            start_index: 99, end_index: 99, destination: empty(), anchor: empty(), flags,
            auxiliary_first: u32::MAX, auxiliary_second: u32::MAX,
        }
    }

    #[test]
    fn packed_flags_preserve_reserved_bytes_and_disabled_sources_are_not_read() {
        for initial in [0, 0xff, 0x56] {
            for enabled in [0u32, 2, 0x100, 0xfe] {
                for kind in [0u32, 1, 2, 3, u32::MAX] {
                    for alternate in [0u32, 1, 2, u32::MAX] {
                        let mut out = record([initial, 0xaa, 0x5a, 0xc3]);
                        unsafe {
                            let invalid = core::ptr::NonNull::<StringObject>::dangling().as_ptr();
                            let returned = link_record_construct(
                                &mut out, u32::MAX, 0, enabled, kind, alternate, 0x123, invalid, invalid,
                            );
                            assert_eq!(returned, &mut out as *mut LinkRecord);
                        }
                        let first = (initial as u32 & !1) | enabled;
                        let second = (first & !6) | ((kind & 3) << 1);
                        let expected = ((second & 7) | ((alternate & 1) << 7)) as u8;
                        assert_eq!(out.flags, [expected, 0x23, 0x5a, 0xc3]);
                        assert_eq!((out.start_index, out.end_index), (u32::MAX, 0));
                        assert_eq!((out.auxiliary_first, out.auxiliary_second), (0, 0));
                        assert!(out.destination.payload.is_null() && out.anchor.payload.is_null());
                        assert_eq!(out.destination.vtable, &STRING_OBJECT_VTABLE as *const _);
                        assert_eq!(out.anchor.vtable, &STRING_OBJECT_VTABLE as *const _);
                    }
                }
            }
        }
    }

    #[test]
    fn optional_sources_copy_independently_and_allocation_failure_leaves_empty() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: clear,
            };
            let source = StringObject {
                vtable: &STRING_OBJECT_VTABLE, payload: b"target\0".as_ptr() as *mut u8,
            };
            let empty = StringObject { vtable: &STRING_OBJECT_VTABLE, payload: core::ptr::null_mut() };
            for fail in [false, true] {
                FAIL_ALLOCATION = fail;
                for first in [core::ptr::null(), &empty, &source] {
                    for second in [core::ptr::null(), &empty, &source] {
                        let mut out = record([0xff; 4]);
                        link_record_construct(&mut out, 2, 1, 1, 3, 1, 7, first, second);
                        for (actual, input) in [(&out.destination, first), (&out.anchor, second)] {
                            if !fail && core::ptr::eq(input, &source) {
                                assert_eq!(core::slice::from_raw_parts(actual.payload, 7), b"target\0");
                                assert_ne!(actual.payload, source.payload);
                                drop(Box::from_raw(actual.payload as *mut [u8; 64]));
                            } else {
                                assert!(actual.payload.is_null());
                            }
                        }
                        assert_eq!(out.flags, [0x87, 7, 0xff, 0xff]);
                    }
                }
            }
            FAIL_ALLOCATION = false;
        }
    }
}
