//! Allocate a resource slot record with room for target-width items.
//!
//! `FUN_080d8cac` @ `0x080d8cac`: 48 bytes, ending at the distinct hardware
//! routine at `0x080d8cdc`. Raw A32 decoding verifies two incoming plain BLs,
//! zero predicated BLs, and one outgoing plain BL to `malloc_tag4`.
//! Allocates `20 + count * 4` bytes with wrapping u32 arithmetic; on success
//! writes completed_count=0 at +12, count at +4, and allocation size at +8.
//! Words +0 and +16 and the item storage remain untouched. NULL passes through.
//! Deliberate deviations: Rust supplies ABI register saves and calls the named
//! ported allocator; an inline allocator parameter shares this exact algorithm
//! with the existing materializer's injectable allocation boundary.

use crate::heap::veneers::malloc_tag4;

#[inline(always)]
pub(crate) unsafe fn allocate_slot_record_with(
    count: u32,
    allocate: unsafe extern "C" fn(usize) -> *mut u8,
) -> *mut u8 {
    let size = count.wrapping_mul(4).wrapping_add(20);
    let record = allocate(size as usize);
    if !record.is_null() {
        let words = record.cast::<u32>();
        words.add(3).write(0);
        words.add(1).write(count);
        words.add(2).write(size);
    }
    record
}

/// Allocate an unfilled slot record using heap tag 4.
///
/// # Safety
/// The allocator must return NULL or aligned writable storage covering the
/// initialized words (+4..+16), including for wrapped allocation sizes. The
/// caller owns a successful allocation and releases it with `free_tag4`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn allocate_slot_record(count: u32) -> *mut u8 {
    allocate_slot_record_with(count, malloc_tag4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};

    #[test]
    fn initializes_only_record_metadata_for_zero_and_nonzero_counts() {
        let _heap = mock_heap();
        for count in [0, 1, 7, 0x4000_0000, u32::MAX] {
            let mut record = [0xa5a5_5a5a_u32; 12];
            set_alloc_ret(record.as_mut_ptr().cast());
            let result = unsafe { allocate_slot_record(count) };
            let size = count.wrapping_mul(4).wrapping_add(20);
            assert_eq!(result, record.as_mut_ptr().cast());
            assert_eq!(alloc_log().1, size as usize);
            assert_eq!(alloc_log().2, 4);
            let mut expected = [0xa5a5_5a5a_u32; 12];
            expected[1] = count;
            expected[2] = size;
            expected[3] = 0;
            assert_eq!(record, expected);
        }
    }

    #[test]
    fn allocation_failure_returns_null() {
        let _heap = mock_heap();
        set_alloc_ret(core::ptr::null_mut());
        assert!(unsafe { allocate_slot_record(3) }.is_null());
        assert_eq!(alloc_log(), (1, 32, 4));
    }
}
