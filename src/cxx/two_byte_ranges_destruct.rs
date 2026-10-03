//! Destructor for a polymorphic owner of two trivial byte ranges.

use crate::heap::trivial_range_destroy_and_deallocate::cxx_trivial_range_destroy_and_deallocate;
use crate::heap::veneers::cxx_array_dealloc;

/// two_byte_ranges_destruct — original `FUN_0826832c` @ 0x0826832c.
/// True extent: 76 bytes, 0x0826832c..0x08268377 (72 instruction bytes plus
/// the vtable literal); the next independently entered function starts at
/// 0x08268378. Two plain internal BLs, zero predicated BLs; two plain inbound
/// BLs at 0x08267ca4 and 0x08267cc0, zero predicated inbound BLs.
///
/// Installs vtable 0x089a8110, destroys/deallocates the three-word byte range
/// at +20, then walks the trivial elements of the range at +8 and deallocates
/// its begin pointer with capacity-minus-begin and element size zero. Returns
/// the original object without clearing either range. Word indices preserve
/// the target's four-byte field layout on hosts. No deliberate deviations;
/// LLVM may eliminate the empty trivial-destructor walk.
///
/// # Safety
/// `owner` must point to eight writable target-width words. Both ranges must
/// contain valid owned allocations (or null empty ranges) for operator delete.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_byte_ranges_destruct(owner: *mut u32) -> *mut u32 {
    owner.write(0x089a_8110);
    let trailing = cxx_trivial_range_destroy_and_deallocate(owner.add(5));
    let leading = trailing.sub(3);
    let begin = leading.read();
    let end = leading.add(1).read();
    let mut cursor = begin;
    while cursor != end {
        cursor = cursor.wrapping_add(1);
    }
    cxx_array_dealloc(
        begin as usize as *mut u8,
        leading.add(2).read().wrapping_sub(begin) as usize,
        0,
    );
    leading.sub(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn releases_both_ranges_in_reverse_order_without_clearing_fields() {
        let Some(slab) = try_map_u32_slab(hints::TWO_BYTE_RANGES_DESTRUCT, 0x1000) else { return; };
        let _heap = mock_heap();
        unsafe {
            let owner = slab.cast::<u32>();
            let first = slab.add(0x100);
            let last = slab.add(0x200);
            let words = [0xdead_beef, 0x1234_5678, first as u32, first.add(7) as u32,
                first.add(32) as u32, last as u32, last.add(9) as u32, last.add(48) as u32];
            core::ptr::copy_nonoverlapping(words.as_ptr(), owner, 8);
            assert_eq!(two_byte_ranges_destruct(owner), owner);
            assert_eq!(free_log(), (2, first, 2));
            assert_eq!(owner.read(), 0x089a_8110);
            assert_eq!(core::slice::from_raw_parts(owner.add(1), 7), &words[1..]);
        }
    }

    #[test]
    fn null_and_empty_allocated_ranges_preserve_the_delete_guard() {
        let Some(slab) = try_map_u32_slab(hints::TWO_BYTE_RANGES_DESTRUCT, 0x1000) else { return; };
        let _heap = mock_heap();
        unsafe {
            let owner = slab.cast::<u32>();
            owner.write(0);
            owner.add(1).write(0xa5a5_a5a5);
            for index in 2..8 { owner.add(index).write(0); }
            assert_eq!(two_byte_ranges_destruct(owner), owner);
            assert_eq!(free_log().0, 0);
            let allocated = slab.add(0x300) as u32;
            owner.add(5).write(allocated);
            owner.add(6).write(allocated);
            owner.add(7).write(allocated + 16);
            assert_eq!(two_byte_ranges_destruct(owner), owner);
            assert_eq!(free_log(), (1, allocated as usize as *mut u8, 2));
            assert_eq!(owner.add(1).read(), 0xa5a5_a5a5);
        }
    }
}
