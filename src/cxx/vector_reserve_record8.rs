//! Reserve storage for field-copied 8-byte records — `FUN_083e09c4`
//! at load address 0x083e09c4, true size 224 bytes (220 code + zero-string
//! literal); the next real function begins at 0x083e0aa4.
//! Raw A32 decoding finds seven plain outbound BLs and one BLHI, and one
//! plain inbound BL at 0x0815f554, with no predicated inbound BLs.
//!
//! Report requests above 0x1fffffff, then continue if the handler returns.
//! If capacity is insufficient, allocate max(request, growth(size)) records,
//! copy only their word/byte/halfword fields, free the old allocation, and
//! commit end, begin, then storage end. Growth uses size, not capacity.
//! Deliberate deviations: omit the side-effect-free trivial destruction loop;
//! use repr(C) native pointer fields on hosts and the existing ported callees.
//! The diagnostic uses the original zero-string address, not a new string.

use super::templates::{VectorStorage, VectorBounds, vector_capacity_elem8,
    vector_size_elem8, vector_copy_range_record8};
use super::vector_growth_capacity::vector_growth_capacity;
use crate::heap::new_handler::{cxx_new_handler_dispatch, operator_new_checked};
use crate::heap::veneers::cxx_array_dealloc;

/// # Safety
/// `vector` must be a writable, aligned vector head with valid ordered record
/// bounds. Allocation and error-handler contracts are those of retailOS;
/// allocation failure is not given an invented recovery path.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_reserve_record8(vector: *mut VectorStorage, requested: u32) {
    if requested > 0x1fff_ffff {
        cxx_new_handler_dispatch(8, 0x083e0aa0, 0x083e0aa0, requested as usize);
    }
    if vector_capacity_elem8(vector) as u32 >= requested {
        return;
    }
    // The existing naked target export declares no Rust parameters, but its
    // verified machine ABI consumes and returns r0. Give that symbol its ABI.
    #[cfg(target_os = "none")]
    let vector_growth_capacity: unsafe extern "C" fn(u32) -> u32 =
        core::mem::transmute(vector_growth_capacity as unsafe extern "C" fn());
    let growth = vector_growth_capacity(vector_size_elem8(vector.cast::<VectorBounds>()) as u32);
    let capacity = core::cmp::max(requested, growth);
    let storage = operator_new_checked(capacity.wrapping_shl(3) as usize);
    vector_copy_range_record8((*vector).begin.cast(), (*vector).end.cast(), storage.cast());
    let old_capacity = vector_capacity_elem8(vector);
    cxx_array_dealloc((*vector).begin, old_capacity as usize, 0);
    let size = vector_size_elem8(vector.cast::<VectorBounds>()) as u32;
    (*vector).end = storage.wrapping_add(size.wrapping_shl(3) as usize);
    (*vector).begin = storage;
    (*vector).end_of_storage = storage.wrapping_add(capacity.wrapping_shl(3) as usize);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, alloc_log, free_log};

    #[test]
    fn sufficient_capacity_is_a_noop_including_empty_and_exact_requests() {
        let _heap = mock_heap();
        let mut bytes = [0xa5u32; 8];
        let begin = bytes.as_mut_ptr().cast::<u8>();
        let mut vector = VectorStorage { begin, end: begin.wrapping_add(8),
            end_of_storage: begin.wrapping_add(32) };
        for requested in [0, 1, 4] {
            unsafe { vector_reserve_record8(&mut vector, requested) };
            assert_eq!(vector.begin, begin);
            assert_eq!(vector.end, begin.wrapping_add(8));
            assert_eq!(vector.end_of_storage, begin.wrapping_add(32));
            assert_eq!(bytes, [0xa5; 8]);
            assert_eq!(alloc_log().0, 0);
            assert_eq!(free_log().0, 0);
        }
    }

    #[test]
    fn growth_uses_size_copies_fields_and_leaves_destination_padding() {
        let _heap = mock_heap();
        for (size, old_capacity, requested, expected_capacity) in
            [(0usize, 0usize, 1u32, 32usize), (2, 3, 4, 34),
             (2, 3, 40, 40), (64, 64, 65, 104)] {
            let mut source = [0x11223344u32; 128];
            let mut destination = [0xddddddddu32; 256];
            let begin = source.as_mut_ptr().cast::<u8>();
            let output = destination.as_mut_ptr().cast::<u8>();
            let mut vector = VectorStorage { begin, end: begin.wrapping_add(size * 8),
                end_of_storage: begin.wrapping_add(old_capacity * 8) };
            let before_alloc = alloc_log().0;
            let before_free = free_log().0;
            unsafe {
                set_alloc_ret(output);
                vector_reserve_record8(&mut vector, requested);
            }
            assert_eq!(vector.begin, output);
            assert_eq!(vector.end, output.wrapping_add(size * 8));
            assert_eq!(vector.end_of_storage, output.wrapping_add(expected_capacity * 8));
            assert_eq!(alloc_log(), (before_alloc + 1, expected_capacity * 8, 2));
            assert_eq!(free_log(), (before_free + 1, begin, 2));
            for index in 0..size {
                assert_eq!(destination[index * 2], 0x11223344);
                assert_eq!(destination[index * 2 + 1], 0x1122dd44);
            }
            assert!(destination[size * 2..].iter().all(|word| *word == 0xdddddddd));
            assert_eq!(source, [0x11223344; 128]);
        }
    }
}
