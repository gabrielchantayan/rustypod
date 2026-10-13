//! Assign a vector of trivial 24-byte records.
//! Original: FUN_083e2dac @ 0x083e2dac, 412 bytes through 0x083e2f48.
//! Raw A32 decoding: 17 outgoing plain BLs, zero predicated BLs; one
//! incoming plain BL at 0x0822c6f4 and zero predicated incoming BLs.
//! Self-assignment is a no-op. Insufficient storage grows to max(source size,
//! old size + 32, old size + old size/2 + old size/8), copies, then frees
//! the old allocation. Otherwise assign the live prefix and construct the
//! tail. Shrink/equal assignment also sets storage end to the new live end.
//! Deliberate deviations: omit empty trivial-destructor loops and inline
//! the registered signed byte-distance/24 helpers; retain existing allocation
//! and copy seams. repr(C) storage uses native pointers for host fixtures.

use super::templates::{VectorStorage, vector_copy_range_elem24_alias_8cf0};
use super::vector_record24_copy::vector_record24_copy;
use crate::heap::new_handler::operator_new_checked;
use crate::heap::veneers::cxx_array_dealloc;

unsafe fn count(begin: *mut u8, end: *mut u8) -> u32 {
    ((end as usize).wrapping_sub(begin as usize) as i32 / 24) as u32
}

/// # Safety
/// Both heads must be valid, with aligned readable live records and writable
/// destination storage. Distinct vectors must not share allocations. Distances
/// must fit signed 32-bit firmware arithmetic; allocation failure follows the
/// retail allocator's behavior rather than introducing a new recovery path.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_record24_assign(
    destination: *mut VectorStorage,
    source: *const VectorStorage,
) -> *mut VectorStorage {
    if destination as *const VectorStorage == source { return destination; }
    let source_size = count((*source).begin, (*source).end);
    let capacity = count((*destination).begin, (*destination).end_of_storage);
    let old_size = count((*destination).begin, (*destination).end);
    if source_size > capacity {
        let growth = old_size.wrapping_add(old_size >> 1).wrapping_add(old_size >> 3);
        let new_capacity = source_size.max(old_size.wrapping_add(32).max(growth));
        let allocation = operator_new_checked(new_capacity.wrapping_mul(24) as usize);
        vector_copy_range_elem24_alias_8cf0((*source).begin, (*source).end, allocation);
        cxx_array_dealloc((*destination).begin, capacity as usize, 0);
        (*destination).begin = allocation;
        (*destination).end = allocation.wrapping_add(source_size.wrapping_mul(24) as usize);
        (*destination).end_of_storage = allocation.wrapping_add(new_capacity.wrapping_mul(24) as usize);
    } else if old_size >= source_size {
        vector_record24_copy((*source).begin, (*source).end, (*destination).begin);
        let end = (*destination).begin.wrapping_add(source_size.wrapping_mul(24) as usize);
        (*destination).end = end;
        (*destination).end_of_storage = end;
    } else {
        let prefix_bytes = old_size.wrapping_mul(24) as usize;
        vector_record24_copy((*source).begin, (*source).begin.wrapping_add(prefix_bytes), (*destination).begin);
        (*destination).end = (*destination).begin.wrapping_add(source_size.wrapping_mul(24) as usize);
        vector_copy_range_elem24_alias_8cf0((*source).begin.wrapping_add(prefix_bytes), (*source).end,
            (*destination).begin.wrapping_add(prefix_bytes));
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::{self, HEAP_OPS};
    static mut ALLOCATION: *mut u8 = core::ptr::null_mut();
    unsafe extern "C" fn allocate(
        _: *mut crate::heap::types::HeapDescriptorDescriptor, _: usize, _: usize,
    ) -> *mut u8 { ALLOCATION }

    #[test]
    fn assignment_paths_preserve_records_and_retail_storage_end() {
        let _lock = veneers::tests::mock_heap();
        unsafe {
            let saved = core::ptr::read(core::ptr::addr_of!(HEAP_OPS));
            HEAP_OPS.alloc = allocate;
            for &(old_size, capacity, source_size, expected_capacity) in &[
                (0, 0, 0, 0), (3, 8, 0, 0), (3, 8, 2, 2), (3, 8, 3, 3),
                (2, 8, 5, 8), (0, 0, 1, 32), (3, 3, 40, 40), (64, 64, 65, 104),
            ] {
                let mut old = [0xa5a5a5a5u32; 1200];
                let mut fresh = [0xccccccccu32; 1200];
                let mut records = [0u32; 1200];
                for (i, word) in records.iter_mut().enumerate() { *word = i as u32 ^ 0x12345678; }
                let old_begin = old.as_mut_ptr().cast::<u8>();
                ALLOCATION = fresh.as_mut_ptr().cast();
                let mut dst = VectorStorage { begin: old_begin,
                    end: old_begin.add(old_size * 24), end_of_storage: old_begin.add(capacity * 24) };
                let src_begin = records.as_mut_ptr().cast::<u8>();
                let src = VectorStorage { begin: src_begin, end: src_begin.add(source_size * 24),
                    end_of_storage: src_begin.add(source_size * 24) };
                assert_eq!(vector_record24_assign(&mut dst, &src), &mut dst as *mut _);
                let expected_begin = if source_size > capacity { ALLOCATION } else { old_begin };
                assert_eq!(dst.begin, expected_begin);
                assert_eq!(dst.end, expected_begin.add(source_size * 24));
                assert_eq!(dst.end_of_storage, expected_begin.add(expected_capacity * 24));
                assert_eq!(core::slice::from_raw_parts(dst.begin.cast::<u32>(), source_size * 6),
                    &records[..source_size * 6]);
                assert_eq!(*dst.end.cast::<u32>(), if source_size > capacity { 0xcccccccc } else { 0xa5a5a5a5 });
            }
            core::ptr::addr_of_mut!(HEAP_OPS).write(saved);
        }
    }

    #[test]
    fn self_assignment_does_not_read_or_change_bounds() {
        let mut head = VectorStorage { begin: 4usize as *mut u8, end: 28usize as *mut u8,
            end_of_storage: 100usize as *mut u8 };
        let ptr = &mut head as *mut VectorStorage;
        assert_eq!(unsafe { vector_record24_assign(ptr, ptr) }, ptr);
        assert_eq!((head.begin as usize, head.end as usize, head.end_of_storage as usize), (4, 28, 100));
    }
}
