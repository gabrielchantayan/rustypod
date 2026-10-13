//! String-pair range fill — retailOS `FUN_083ea698` @ 0x083ea698.
//! True extent: 60 bytes, ending at the independent function at 0x083ea6d4.
//! Raw A32 scan: two plain outgoing BLs to string_object_assign @ 0x082774a8,
//! zero predicated BLs; one plain incoming BL at 0x083e3994, zero predicated.
//!
//! Walk [first, end), assigning each pair's first string then its second
//! from the same source pair. Re-read source members for every assignment;
//! overlapping source is not snapshotted. Empty ranges do not read source.
//! Deliberate deviation: typed repr(C) pairs scale with host pointer width;
//! on ARM the second member is +8 and the stride is 16, exactly as stock.
//! Allocation/clear dispatch inherits the existing StringObject port's seams.

use super::string_object::{string_object_assign, StringObjectPair};

/// # Safety
/// `first..end` must be a writable, initialized range of StringObjectPairs,
/// with `end` reachable by advancing `first`. For a nonempty range `source`
/// must point to an initialized pair and remain valid through assignments.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_pair_range_fill(
    mut first: *mut StringObjectPair,
    end: *mut StringObjectPair,
    source: *const StringObjectPair,
) {
    while first != end {
        string_object_assign(core::ptr::addr_of_mut!((*first).first),
            core::ptr::addr_of!((*source).first));
        string_object_assign(core::ptr::addr_of_mut!((*first).second),
            core::ptr::addr_of!((*source).second));
        first = first.add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::string_object::{StringObject, StringObjectAssignCstrOps,
        STRING_OBJECT_ASSIGN_CSTR_OPS};
    use core::ptr;

    unsafe extern "C" fn allocate(this: *mut StringObject, size: usize, _: u32) -> *mut u8 {
        if size > 8 { ptr::null_mut() } else { (*this).payload }
    }
    unsafe extern "C" fn clear(this: *mut StringObject) {
        (*this).payload = ptr::null_mut();
    }
    struct Restore(StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { STRING_OBJECT_ASSIGN_CSTR_OPS = self.0; } }
    }
    fn object(payload: *mut u8) -> StringObject {
        StringObject { vtable: ptr::null(), payload }
    }

    #[test]
    fn empty_range_never_reads_null_operands() {
        unsafe { string_pair_range_fill(ptr::null_mut(), ptr::null_mut(), ptr::null()); }
    }

    #[test]
    fn fills_only_the_range_and_preserves_an_aliased_source_pair() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: clear,
            };
            let mut buffers = [[0xa5u8; 8]; 8];
            buffers[2][..4].copy_from_slice(b"one\0");
            buffers[3][..4].copy_from_slice(b"two\0");
            let mut pairs: [StringObjectPair; 4] = core::array::from_fn(|i| StringObjectPair {
                first: object(buffers[2*i].as_mut_ptr()),
                second: object(buffers[2*i+1].as_mut_ptr()),
            });
            let base = pairs.as_mut_ptr();
            string_pair_range_fill(base, base.add(3), base.add(1));
            for i in 0..3 {
                assert_eq!(&buffers[2*i][..4], b"one\0");
                assert_eq!(&buffers[2*i+1][..4], b"two\0");
                assert_eq!(&buffers[2*i][4..], &[0xa5; 4]);
                assert_eq!(&buffers[2*i+1][4..], &[0xa5; 4]);
                assert!(pairs[i].first.vtable.is_null());
                assert!(pairs[i].second.vtable.is_null());
            }
            assert_eq!(buffers[6], [0xa5; 8]);
            assert_eq!(buffers[7], [0xa5; 8]);
        }
    }

    #[test]
    fn allocation_failure_does_not_skip_second_member_or_later_pairs_and_empty_clears() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: clear,
            };
            let mut buffers = [[0xa5u8; 8]; 4];
            let mut pairs: [StringObjectPair; 2] = core::array::from_fn(|i| StringObjectPair {
                first: object(buffers[2*i].as_mut_ptr()),
                second: object(buffers[2*i+1].as_mut_ptr()),
            });
            let source = StringObjectPair {
                first: object(b"too long\0".as_ptr() as *mut u8),
                second: object(b"ok\0".as_ptr() as *mut u8),
            };
            let base = pairs.as_mut_ptr();
            string_pair_range_fill(base, base.add(2), &source);
            for i in 0..2 {
                assert_eq!(buffers[2*i], [0xa5; 8]);
                assert_eq!(&buffers[2*i+1][..3], b"ok\0");
            }
            let empty = StringObjectPair {
                first: object(ptr::null_mut()),
                second: object(b"\0".as_ptr() as *mut u8),
            };
            string_pair_range_fill(base, base.add(2), &empty);
            for pair in &pairs {
                assert!(pair.first.payload.is_null());
                assert!(pair.second.payload.is_null());
            }
        }
    }
}
