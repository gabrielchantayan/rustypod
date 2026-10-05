//! String/vector/flag copy constructor — `FUN_08197b90` @ `0x08197b90`.
//!
//! Raw extent: 152 bytes, ending at the next prologue at `0x08197c28`.
//! Five outbound plain BLs, zero predicated BLs: string copy, vector size,
//! checked new, entry range copy, vector size. Two inbound plain BLs.
//! COW-copies the leading string, clears vector bounds, allocates
//! max(unsigned size, 32) * 16 bytes, constructs the entries, recomputes end,
//! sets capacity_end, and copies the flag byte. Deliberate deviations: dead
//! r2/r3 arguments and stack spills are omitted; host size reads target-width
//! bounds directly. Existing range-copy dispatch retains the retail entry
//! constructor. All object fields remain target-width words on hosts.

use crate::cxx::templates::{vector_copy_construct_range_elem16_alt, VectorStorage};
use crate::cxx::string::cxx_string_copy_ctor;
use crate::heap::new_handler::operator_new_checked;

#[inline(never)]
unsafe fn entry_count(bounds: *const u32) -> u32 {
    #[cfg(target_os = "none")]
    { crate::cxx::templates::vector_size_elem16(bounds.cast()) as u32 }
    #[cfg(not(target_os = "none"))]
    { ((bounds.add(1).read().wrapping_sub(bounds.read()) as i32) >> 4) as u32 }
}

/// Copies a 20-byte target-layout {string, begin, end, capacity_end, flag}.
///
/// # Safety
/// Objects must be aligned, nonoverlapping, and valid for the existing string
/// and entry constructors. Source bounds delimit whole readable 16-byte entries;
/// the allocator must provide the selected capacity, as required by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_vector_flag_copy_construct(destination: *mut u8, source: *const u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    let destination = cxx_string_copy_ctor(destination.cast(), source.cast()).cast::<u8>();
    #[cfg(not(target_os = "none"))]
    {
        let string = source.cast::<u32>().read() as usize as *mut u8;
        let mut copied = core::ptr::null_mut();
        cxx_string_copy_ctor(&mut copied, &string);
        destination.cast::<u32>().write(copied as usize as u32);
    }
    let bounds = destination.add(4).cast::<u32>();
    bounds.write(0);
    bounds.add(1).write(0);
    bounds.add(2).write(0);
    let source_bounds = source.add(4).cast::<u32>();
    let capacity = core::cmp::max(entry_count(source_bounds), 32);
    let allocation = operator_new_checked(capacity.wrapping_shl(4) as usize);
    bounds.write(allocation as usize as u32);
    vector_copy_construct_range_elem16_alt(
        source_bounds.read() as usize as *const u8,
        source_bounds.add(1).read() as usize as *const u8,
        allocation, bounds.cast::<VectorStorage>(),
    );
    let begin = bounds.read();
    bounds.add(1).write(begin.wrapping_add(entry_count(source_bounds).wrapping_shl(4)));
    bounds.add(2).write(begin.wrapping_add(capacity.wrapping_shl(4)));
    destination.add(16).write(source.add(16).read());
    destination
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};

    #[test]
    fn empty_vector_still_reserves_minimum_and_copies_flag_without_padding() {
        let _heap = mock_heap();
        unsafe {
            let Some(rep) = crate::testing::try_map_u32_slab(
                crate::testing::hints::STRING_VECTOR_FLAG_COPY_CONSTRUCT, 0x1000,
            ) else { assert!(crate::testing::note_missing_u32_fixture("string_vector_flag_copy_construct")); return; };
            rep.cast::<u32>().write(0); // shareable refcount
            rep.add(4).cast::<u32>().write(0); // capacity
            rep.add(8).cast::<u32>().write(0); // length
            rep.add(12).write(0);
            let mut source = [0u32; 6];
            source[0] = rep.add(12) as usize as u32;
            source[4] = 0x4433_22a7;
            let mut destination = [0xcccc_ccccu32; 6];
            set_alloc_ret(0x1234_0000usize as *mut u8);
            let output = destination.as_mut_ptr().cast();
            assert_eq!(string_vector_flag_copy_construct(output, source.as_ptr().cast()), output);
            assert_eq!(&destination[1..4], &[0x1234_0000, 0x1234_0000, 0x1234_0200]);
            assert_eq!(destination[4], 0xcccc_cca7);
            assert_eq!(destination[0], source[0]);
            assert_eq!(rep.cast::<u32>().read(), 1);
            assert_eq!(destination[5], 0xcccc_cccc);
        }
        assert_eq!(alloc_log(), (1, 512, 2));
    }

    #[test]
    fn count_uses_signed_target_subtraction_then_unsigned_capacity() {
        unsafe {
            for (begin, end, expected) in [(0x1000, 0x11f0, 31), (0x1000, 0x1200, 32),
                (0x1000, 0x1210, 33), (0xffff_fff0, 0x10, 2), (0x1010, 0x1000, u32::MAX)] {
                assert_eq!(entry_count([begin, end].as_ptr()), expected);
            }
        }
    }
}
