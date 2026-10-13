//! Empty string-pair vector constructor — `FUN_083e3a94` at `0x083e3a94`.
//!
//! True extent: 20 bytes, `[0x083e3a94, 0x083e3aa8)`, ending in `bx lr`
//! before the next function's push. Raw A32 decoding verifies one incoming
//! plain BL at `0x08100a68`, zero incoming predicated BLs, and zero outgoing
//! plain or predicated BLs. Writes zero to begin, end, and capacity in order,
//! leaving r0 unchanged. The caller subsequently uses the existing string-pair
//! vector destructor. Deliberate deviations: omit the unused caller argument;
//! native-pointer fields widen on hosts but retain the ARM 12-byte layout.

use crate::cxx::string_object_pair_vector_destroy::StringObjectPairVector;

/// Initializes an empty vector and returns its header without allocating.
///
/// # Safety
/// `vector` must point to aligned, writable storage for a vector header.
/// Previous contents are discarded, not destroyed or deallocated.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_object_pair_vector_construct(
    vector: *mut StringObjectPairVector,
) -> *mut StringObjectPairVector {
    unsafe {
        core::ptr::addr_of_mut!((*vector).begin).write(core::ptr::null_mut());
        core::ptr::addr_of_mut!((*vector).end).write(core::ptr::null_mut());
        core::ptr::addr_of_mut!((*vector).capacity).write(core::ptr::null_mut());
    }
    vector
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discards_nonempty_bounds_without_touching_storage_or_neighbors() {
        #[repr(C)]
        struct Guarded {
            before: usize,
            vector: StringObjectPairVector,
            after: usize,
        }
        let mut storage = [0xa5u8; 48];
        let mut guarded = Guarded {
            before: usize::MAX,
            vector: StringObjectPairVector {
                begin: storage.as_mut_ptr(),
                end: unsafe { storage.as_mut_ptr().add(16) },
                capacity: unsafe { storage.as_mut_ptr().add(48) },
            },
            after: 0x12345678,
        };
        let header = core::ptr::addr_of_mut!(guarded.vector);
        assert_eq!(unsafe { string_object_pair_vector_construct(header) }, header);
        assert!(guarded.vector.begin.is_null());
        assert!(guarded.vector.end.is_null());
        assert!(guarded.vector.capacity.is_null());
        assert_eq!(guarded.before, usize::MAX);
        assert_eq!(guarded.after, 0x12345678);
        assert_eq!(storage, [0xa5; 48]);
    }

    #[test]
    fn accepts_uninitialized_header_and_repeated_initialization() {
        let mut storage = core::mem::MaybeUninit::<StringObjectPairVector>::uninit();
        let header = storage.as_mut_ptr();
        unsafe {
            assert_eq!(string_object_pair_vector_construct(header), header);
            assert_eq!(string_object_pair_vector_construct(header), header);
            let vector = storage.assume_init();
            assert!(vector.begin.is_null());
            assert!(vector.end.is_null());
            assert!(vector.capacity.is_null());
        }
    }
}
