//! `dynamic_array_resize` — `FUN_080a6314` @ 0x080a6314.
//! True size: 164 bytes, ending at the independently entered 0x080a63b8.
//! Raw A32 words verify two outgoing plain BLs to array_buffer_set_size,
//! two incoming plain BLs (0x0803bc4c, 0x08058ad4), and no predicated BLs.
//! Adjust length by a signed delta using wrapping target-width arithmetic.
//! Grow by max(delta_bytes, min(max(capacity, delta_bytes), 65536)); if
//! speculative growth fails, retry the exact required size. Shrink by the
//! removed byte count, preserving spare capacity. Commit length/used bytes
//! only after success. Deliberate deviations: calls the existing Rust backing
//! size port instead of the retail address; no algorithmic deviations.

use crate::heap::array_buffer_set_size::array_buffer_set_size;

/// Adjust the element count and backing allocation of a retail dynamic array.
///
/// # Safety
/// `array` must contain seven aligned writable target-width words; word six
/// must satisfy `array_buffer_set_size`'s MemH ownership requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dynamic_array_resize(array: *mut u32, change: i32) -> i32 {
    let length = array.add(2).read().wrapping_add(change as u32);
    let element_size = array.add(1).read();
    let required = length.wrapping_mul(element_size);
    let capacity = array.add(4).read();
    if capacity < required {
        let delta_bytes = (change as u32).wrapping_mul(element_size);
        let increment = delta_bytes.max(capacity.max(delta_bytes).min(0x10000));
        if array_buffer_set_size(array, 0, capacity.wrapping_add(increment)) != 0 {
            let status = array_buffer_set_size(array, 0, required);
            if status != 0 {
                return status;
            }
        }
    } else if change < 0 {
        let size = required.wrapping_add(capacity.wrapping_sub(array.add(3).read()));
        let status = array_buffer_set_size(array, 0, size);
        if status != 0 {
            return status;
        }
    }
    array.add(2).write(length);
    array.add(3).write(required);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::memh_handle::MEMH_MAGIC;
    use crate::heap::memh_set_len::MemhBufferHeader;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::LazyLock;

    static SLAB: LazyLock<usize> = LazyLock::new(|| {
        try_map_u32_slab(hints::DYNAMIC_ARRAY_RESIZE, 0x1000)
            .expect("dynamic array resize requires a target-width mapping") as usize
    });

    fn fixture(capacity: u32, length: u32) -> *mut MemhBufferHeader {
        let header = *SLAB as *mut MemhBufferHeader;
        unsafe { header.write(MemhBufferHeader {
            payload: (*SLAB + 0x100) as u32, magic: MEMH_MAGIC, capacity, length,
        }); }
        header
    }

    #[test]
    fn in_capacity_and_wrapping_updates_do_not_touch_storage() {
        let mut array = [77, 4, 2, 8, 16, 99, 1];
        assert_eq!(unsafe { dynamic_array_resize(array.as_mut_ptr(), 2) }, 0);
        assert_eq!(array, [77, 4, 4, 16, 16, 99, 1]);
        let mut array = [77, 4, u32::MAX, u32::MAX - 3, 0, 99, 1];
        assert_eq!(unsafe { dynamic_array_resize(array.as_mut_ptr(), 1) }, 0);
        assert_eq!(array[2..5], [0, 0, 0]);
    }

    #[test]
    fn growth_policy_doubles_caps_increment_and_honors_large_delta() {
        let _heap = mock_heap();
        for (capacity, change, expected) in [(16, 1, 32), (0x20000, 1, 0x30000), (16, 0x10001, 0x10011)] {
            let header = fixture(expected, capacity);
            let mut array = [77, 1, capacity, capacity, capacity, 99, header as usize as u32];
            assert_eq!(unsafe { dynamic_array_resize(array.as_mut_ptr(), change) }, 0);
            assert_eq!(array[2..5], [capacity + change as u32, capacity + change as u32, expected]);
            assert_eq!(unsafe { (*header).length }, expected);
        }
    }

    #[test]
    fn failed_speculation_retries_exact_size_and_failure_preserves_counts() {
        let _heap = mock_heap();
        set_alloc_ret(core::ptr::null_mut());
        let header = fixture(20, 16);
        let mut array = [77, 4, 4, 16, 16, 99, header as usize as u32];
        assert_eq!(unsafe { dynamic_array_resize(array.as_mut_ptr(), 1) }, 0);
        assert_eq!(array[2..5], [5, 20, 20]);
        assert_eq!(unsafe { (*header).length }, 20);
        assert_eq!(alloc_log(), (1, 32, 4));
        let before = array;
        assert_eq!(unsafe { dynamic_array_resize(array.as_mut_ptr(), 1) }, -108);
        assert_eq!(array, before);
        assert_eq!(alloc_log(), (3, 24, 4));
    }

    #[test]
    fn shrink_preserves_slack_and_propagates_error_before_commit() {
        let _heap = mock_heap();
        let header = fixture(24, 24);
        let mut array = [77, 4, 4, 16, 24, 99, header as usize as u32];
        assert_eq!(unsafe { dynamic_array_resize(array.as_mut_ptr(), -1) }, 0);
        assert_eq!(array[2..5], [3, 12, 20]);
        assert_eq!(unsafe { (*header).length }, 20);
        unsafe { (*header).magic = 0; }
        let before = array;
        assert_eq!(unsafe { dynamic_array_resize(array.as_mut_ptr(), -1) }, -50);
        assert_eq!(array, before);
    }
}
