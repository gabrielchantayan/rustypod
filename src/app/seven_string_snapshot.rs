//! Snapshot extraction from a polymorphic seven-string provider.

use crate::cxx::string_object::{StringObject, string_object_copy_construct};

#[repr(C)]
pub struct SevenStringProvider {
    pub vtable: *const usize,
    pub opaque: [u32; 4],
    pub strings: [StringObject; 7],
    pub flags: [u8; 4],
}

#[repr(C)]
pub struct SevenStringSnapshot {
    pub strings: [StringObject; 7],
    pub flags: [u8; 4],
}

/// seven_string_snapshot_construct — FUN_08155858 @ 0x08155858.
/// True extent: 148 bytes, ending before the prologue at 0x081558ec.
/// Two inbound plain BLs, zero predicated; seven outgoing plain BLs,
/// zero predicated, plus one indirect BLX through source vtable slot +8.
/// Refresh the provider, copy-construct its seven strings at +0x14..+0x44
/// into destination +0..+0x30, then copy bytes +0x4c..+0x4e to +0x38..+0x3a.
/// Return the destination base left in r0 (Ghidra incorrectly says void).
/// No NULL guards; destination must be raw storage or the source string block
/// itself. The fourth flag/padding byte is deliberately untouched.
/// Deviations: native-width repr(C) pointers on hosts; string construction
/// uses the existing port and its documented modeled vtable/allocator seams.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn seven_string_snapshot_construct(
    destination: *mut SevenStringSnapshot,
    source: *mut SevenStringProvider,
) -> *mut SevenStringSnapshot {
    let refresh: unsafe extern "C" fn(*mut SevenStringProvider) =
        core::mem::transmute((*(*source).vtable.add(2)) as usize);
    refresh(source);
    let input = core::ptr::addr_of!((*source).strings).cast::<StringObject>();
    let output = destination.cast::<StringObject>();
    let mut last = string_object_copy_construct(output, input);
    last = string_object_copy_construct(last.add(1), input.add(1));
    last = string_object_copy_construct(last.add(1), input.add(2));
    last = string_object_copy_construct(last.add(1), input.add(3));
    last = string_object_copy_construct(last.add(1), input.add(4));
    last = string_object_copy_construct(last.add(1), input.add(5));
    last = string_object_copy_construct(last.add(1), input.add(6));
    let base = last.sub(6).cast::<SevenStringSnapshot>();
    (*base).flags[0] = (*source).flags[0];
    (*base).flags[1] = (*source).flags[1];
    (*base).flags[2] = (*source).flags[2];
    base
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::string_object::{StringObjectAssignCstrOps,
        STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_VTABLE};

    static mut STORAGE: [[u8; 32]; 7] = [[0; 32]; 7];
    static mut NEXT: usize = 0;
    static mut FAIL: bool = false;

    unsafe extern "C" fn allocate(this: *mut StringObject, size: usize, _flags: u32) -> *mut u8 {
        if FAIL { return core::ptr::null_mut(); }
        assert!(size <= 32);
        let out = core::ptr::addr_of_mut!(STORAGE).cast::<u8>().add(NEXT * 32);
        NEXT += 1;
        (*this).payload = out;
        out
    }
    unsafe extern "C" fn clear(this: *mut StringObject) {
        (*this).payload = core::ptr::null_mut();
    }
    unsafe extern "C" fn refresh(source: *mut SevenStringProvider) {
        (*source).opaque[0] += 1;
        (*source).strings[0].payload = b"refreshed\0".as_ptr() as *mut u8;
        (*source).flags = [0x80, 0xff, 0x42, 0x11];
    }
    fn string(payload: *mut u8) -> StringObject {
        StringObject { vtable: core::ptr::null(), payload }
    }
    struct Restore(StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { STRING_OBJECT_ASSIGN_CSTR_OPS = self.0; } }
    }

    #[test]
    fn refreshed_snapshot_deep_copies_mixed_payloads_and_preserves_padding_on_failure() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: clear,
            };
            for failure in [false, true] {
                FAIL = failure;
                NEXT = 0;
                let vtable = [0, 0, refresh as *const () as usize];
                let payloads = [b"stale\0".as_ptr(), core::ptr::null(), b"\0".as_ptr(),
                    b"artist\0".as_ptr(), b"album\0".as_ptr(), b"title\0".as_ptr(), b"last\0".as_ptr()];
                let mut source = SevenStringProvider {
                    vtable: vtable.as_ptr(), opaque: [0, 11, 22, 33],
                    strings: core::array::from_fn(|i| string(payloads[i] as *mut u8)),
                    flags: [1, 2, 3, 4],
                };
                let mut destination = SevenStringSnapshot {
                    strings: core::array::from_fn(|_| string(1 as *mut u8)),
                    flags: [0xa5; 4],
                };
                let result = seven_string_snapshot_construct(&mut destination, &mut source);
                assert_eq!(result, core::ptr::addr_of_mut!(destination));
                assert_eq!(source.opaque, [1, 11, 22, 33]);
                assert_eq!(destination.flags, [0x80, 0xff, 0x42, 0xa5]);
                for i in 0..7 {
                    assert_eq!(destination.strings[i].vtable, &STRING_OBJECT_VTABLE as *const _);
                    if failure || i == 1 || i == 2 {
                        assert!(destination.strings[i].payload.is_null());
                    } else {
                        let expected = std::ffi::CStr::from_ptr(source.strings[i].payload.cast());
                        let actual = std::ffi::CStr::from_ptr(destination.strings[i].payload.cast());
                        assert_eq!(actual, expected);
                        assert_ne!(destination.strings[i].payload, source.strings[i].payload);
                    }
                }
                assert_eq!(source.strings[6].payload, payloads[6] as *mut u8);
            }
        }
    }

    #[test]
    fn snapshot_over_source_string_block_keeps_payloads_without_allocation() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: clear,
            };
            NEXT = 0;
            FAIL = false;
            let vtable = [0, 0, refresh as *const () as usize];
            let mut source = SevenStringProvider {
                vtable: vtable.as_ptr(), opaque: [0; 4],
                strings: core::array::from_fn(|_| string(b"kept\0".as_ptr() as *mut u8)),
                flags: [0; 4],
            };
            let output = core::ptr::addr_of_mut!(source.strings).cast::<SevenStringSnapshot>();
            assert_eq!(seven_string_snapshot_construct(output, &mut source), output);
            let allocations = NEXT;
            assert_eq!(allocations, 0);
            for i in 0..7 {
                let expected = if i == 0 { &b"refreshed\0"[..] } else { &b"kept\0"[..] };
                assert_eq!(std::ffi::CStr::from_ptr(source.strings[i].payload.cast()).to_bytes_with_nul(), expected);
                assert_eq!(source.strings[i].vtable, &STRING_OBJECT_VTABLE as *const _);
            }
            assert_eq!(source.flags, [0x80, 0xff, 0x42, 0x11]);
        }
    }
}
