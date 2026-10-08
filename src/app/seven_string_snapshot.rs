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

#[repr(C)]
pub struct SevenStringCollection {
    pub vtable: *const usize,
}

#[repr(C)]
pub struct SevenStringSnapshotOwner {
    pub opaque: [u32; 21],
    pub collection: SevenStringCollection,
}

/// seven_string_snapshot_append — FUN_08123d98 @ 0x08123d98.
/// True extent: 156 bytes, [0x08123d98, 0x08123e34); next word is a PUSH.
/// Raw A32 scan: two inbound plain BLs, eight outgoing plain BLs,
/// zero predicated BLs in either direction, one indirect BLX.
/// Allocate 60 bytes, copy-construct seven strings in returned-pointer order,
/// copy three raw flag bytes, and dispatch the owner's collection at +0x54
/// through vtable slot +0x1c with the new snapshot pointer by reference.
/// No NULL checks, no source refresh, no cleanup after dispatch; byte +0x3b
/// is untouched. Only r0/r1 are arguments; Ghidra's r2/r3 are unused.
/// Deviations: repr(C) native pointers widen host snapshots and align the
/// host collection; allocation uses size_of rather than literal 60 (60 on
/// ARM). Inherits the existing string-vtable and heap-dispatch models.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn seven_string_snapshot_append(
    owner: *mut SevenStringSnapshotOwner,
    source: *const SevenStringSnapshot,
) {
    let output = crate::heap::veneers::operator_new(
        core::mem::size_of::<SevenStringSnapshot>(),
    ).cast::<StringObject>();
    let input = core::ptr::addr_of!((*source).strings).cast::<StringObject>();
    let mut last = string_object_copy_construct(output, input);
    last = string_object_copy_construct(last.add(1), input.add(1));
    last = string_object_copy_construct(last.add(1), input.add(2));
    last = string_object_copy_construct(last.add(1), input.add(3));
    last = string_object_copy_construct(last.add(1), input.add(4));
    last = string_object_copy_construct(last.add(1), input.add(5));
    last = string_object_copy_construct(last.add(1), input.add(6));
    let mut snapshot = last.sub(6).cast::<SevenStringSnapshot>();
    (*snapshot).flags[0] = (*source).flags[0];
    (*snapshot).flags[1] = (*source).flags[1];
    (*snapshot).flags[2] = (*source).flags[2];
    let collection = core::ptr::addr_of_mut!((*owner).collection);
    let append: unsafe extern "C" fn(
        *mut SevenStringCollection, *mut *mut SevenStringSnapshot,
    ) = core::mem::transmute(*(*collection).vtable.add(7));
    append(collection, &mut snapshot);
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

    static mut SNAPSHOT: core::mem::MaybeUninit<SevenStringSnapshot> =
        core::mem::MaybeUninit::uninit();
    static mut RECEIVED: *mut SevenStringSnapshot = core::ptr::null_mut();
    static mut COLLECTION: *mut SevenStringCollection = core::ptr::null_mut();

    unsafe extern "C" fn allocate_snapshot(
        _: *mut crate::heap::types::HeapDescriptorDescriptor,
        size: usize, tag: usize,
    ) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<SevenStringSnapshot>());
        assert_eq!(tag, 2);
        let storage = core::ptr::addr_of_mut!(SNAPSHOT).cast::<u8>();
        core::ptr::write_bytes(storage, 0xa5, size);
        storage
    }

    unsafe extern "C" fn append(
        collection: *mut SevenStringCollection, snapshot: *mut *mut SevenStringSnapshot,
    ) {
        assert_eq!(collection, COLLECTION);
        RECEIVED = *snapshot;
        // The argument is a mutable pointer slot, not the snapshot itself.
        *snapshot = core::ptr::null_mut();
    }

    struct RestoreHeap(crate::heap::veneers::HeapVeneerOps);
    impl Drop for RestoreHeap {
        fn drop(&mut self) { unsafe { crate::heap::veneers::HEAP_OPS = self.0; } }
    }

    #[test]
    fn appended_snapshot_owns_copies_preserves_padding_and_survives_payload_failure() {
        let _heap_lock = crate::heap::veneers::tests::mock_heap();
        let _string_lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let _heap_restore = RestoreHeap(crate::heap::veneers::HEAP_OPS);
            crate::heap::veneers::HEAP_OPS.alloc = allocate_snapshot;
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: clear,
            };
            let mut vtable = [0usize; 8];
            vtable[7] = append as *const () as usize;
            let mut owner = SevenStringSnapshotOwner {
                opaque: [0x12345678; 21],
                collection: SevenStringCollection { vtable: vtable.as_ptr() },
            };
            COLLECTION = core::ptr::addr_of_mut!(owner.collection);
            let payloads = [b"first\0".as_ptr(), core::ptr::null(), b"\0".as_ptr(),
                b"artist\0".as_ptr(), b"album\0".as_ptr(), b"title\0".as_ptr(), b"last\0".as_ptr()];
            let source = SevenStringSnapshot {
                strings: core::array::from_fn(|i| string(payloads[i] as *mut u8)),
                flags: [0x80, 0xff, 0x42, 0x19],
            };
            for failure in [false, true] {
                NEXT = 0;
                FAIL = failure;
                RECEIVED = core::ptr::null_mut();
                seven_string_snapshot_append(&mut owner, &source);
                assert_eq!(RECEIVED, core::ptr::addr_of_mut!(SNAPSHOT).cast());
                let copied = &*RECEIVED;
                assert_eq!(copied.flags, [0x80, 0xff, 0x42, 0xa5]);
                assert_eq!(owner.opaque, [0x12345678; 21]);
                for i in 0..7 {
                    assert_eq!(copied.strings[i].vtable, &STRING_OBJECT_VTABLE as *const _);
                    assert_eq!(source.strings[i].payload, payloads[i] as *mut u8);
                    if failure || i == 1 || i == 2 {
                        assert!(copied.strings[i].payload.is_null());
                    } else {
                        assert_ne!(copied.strings[i].payload, source.strings[i].payload);
                        assert_eq!(std::ffi::CStr::from_ptr(copied.strings[i].payload.cast()),
                            std::ffi::CStr::from_ptr(payloads[i].cast()));
                    }
                }
            }
        }
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
