//! Four-byte deque back-segment retirement.

use crate::heap::block_deque::deque_seg_capacity;
use crate::heap::veneers::cxx_array_dealloc;

/// deque_back_retire_segment — original: `FUN_083df8e4` @ 0x083df8e4.
/// True size: 164 bytes, 0x083df8e4..0x083df988 (next real prologue).
/// Raw A32: seven outgoing plain BLs, zero predicated BLs; one incoming
/// plain BL at 0x083dfd88, zero predicated incoming BLs.
/// Also ports `FUN_083df574` @ 0x083df574: true size 164 bytes through
/// 0x083df618, seven outgoing plain BLs and zero predicated BLs. Whole-image
/// decoding finds one incoming plain BL at 0x0825d2e8, no predicated calls.
/// Every non-BL instruction is identical to the 0x083df8e4 body; its distinct
/// capacity, empty-predicate and iterator-init targets are verified equivalent.
/// The existing export intentionally serves both addresses, with no wrapper.
///
/// Retreats the back map slot and frees its former segment. The caller has
/// already decremented the element cursor and count. If count is zero, clears
/// both iterators and frees the map, leaving the count and map metadata intact.
/// Otherwise initializes the back iterator at the preceding segment's end.
///
/// Deliberate deviations: the existing capacity port serves 0x083da450;
/// iterator-init (0x083da47c) is expressed as four target-width word stores,
/// and the 0x083d7630 empty predicate is expressed as count == 0. A generic
/// allocator callback follows the neighboring front-release port's test seam.
/// The unused restored r0-r3 register values are not modeled as a return value:
/// the sole raw caller ignores them. No element is destroyed or count changed.
///
/// # Safety
/// `deque` points to eleven writable target-width words. Its back map slot
/// and, for a nonempty deque, preceding slot must be readable aligned words.
/// Retired segment and empty-deque map allocations must be valid for delete[].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_back_retire_segment(deque: *mut u32) {
    deque_back_retire_segment_with(deque, |ptr, count, elem| {
        cxx_array_dealloc(ptr as usize as *mut u8, count as usize, elem as usize)
    });
}

unsafe fn deque_back_retire_segment_with<D>(deque: *mut u32, mut deallocate: D)
where
    D: FnMut(u32, u32, u32),
{
    let old_slot = deque.add(7).read();
    deque.add(7).write(old_slot.wrapping_sub(4));
    let segment = (old_slot as usize as *const u32).read();
    deallocate(segment, deque_seg_capacity() as u32, 0);

    if deque.add(8).read() == 0 {
        for index in 4..8 {
            deque.add(index).write(0);
        }
        for index in 0..4 {
            deque.add(index).write(0);
        }
        deallocate(deque.add(9).read(), deque.add(10).read(), 0);
    } else {
        let capacity = deque_seg_capacity() as u32;
        let slot = deque.add(7).read();
        let base = (slot as usize as *const u32).read();
        let end = base.wrapping_add(capacity * 4);
        deque.add(4).write(end);
        deque.add(5).write(base);
        deque.add(6).write(end);
        deque.add(7).write(slot);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::deque_back_retire_segment_with;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn reanchors_previous_segment_preserving_front_count_and_map() {
        let Some(slab) = try_map_u32_slab(hints::DEQUE_BACK_RETIRE_SEGMENT, 4096) else {
            return;
        };
        let slots = slab.cast::<u32>();
        unsafe {
            slots.write(0x4000);
            slots.add(1).write(0x5000);
        }
        for (base, count) in [(0x4000u32, 1), (0, 2), (0xffff_ffc0, u32::MAX)] {
            unsafe { slots.write(base) };
            let slot = unsafe { slots.add(1) } as usize as u32;
            let mut deque = [11, 22, 33, 44, 0x5000, 0x5000, 0x5080, slot, count, 0x6000, 9];
            let mut frees = std::vec::Vec::new();
            unsafe {
                deque_back_retire_segment_with(deque.as_mut_ptr(), |p, n, e| frees.push((p, n, e)));
            }
            let end = base.wrapping_add(128);
            assert_eq!(deque, [11, 22, 33, 44, end, base, end, slot - 4, count, 0x6000, 9]);
            assert_eq!(frees, [(0x5000, 32, 0)]);
        }
    }

    #[test]
    fn empty_deque_frees_segment_then_map_without_reading_previous_slot() {
        let Some(slab) = try_map_u32_slab(hints::DEQUE_BACK_RETIRE_SEGMENT_EMPTY, 4096) else {
            return;
        };
        let slot = slab.cast::<u32>();
        unsafe { slot.write(0x7000) };
        let mut deque = [11, 22, 33, 44, 55, 66, 77, slot as usize as u32, 0, 0x8000, 13];
        let mut frees = std::vec::Vec::new();
        unsafe {
            deque_back_retire_segment_with(deque.as_mut_ptr(), |p, n, e| frees.push((p, n, e)));
        }
        assert_eq!(deque, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x8000, 13]);
        assert_eq!(frees, [(0x7000, 32, 0), (0x8000, 13, 0)]);
    }

    #[test]
    fn retired_null_segment_does_not_clear_a_nonempty_deque() {
        let Some(slab) = try_map_u32_slab(hints::DEQUE_BACK_RETIRE_SEGMENT_NULL, 4096) else {
            return;
        };
        let slots = slab.cast::<u32>();
        unsafe {
            slots.write(0xffff_ff80);
            slots.add(1).write(0);
        }
        let slot = unsafe { slots.add(1) } as usize as u32;
        let mut deque = [11, 22, 33, 44, 0, 0, 0, slot, 0x8000_0000, 0x6000, 9];
        let mut frees = std::vec::Vec::new();
        unsafe {
            deque_back_retire_segment_with(deque.as_mut_ptr(), |p, n, e| frees.push((p, n, e)));
        }
        assert_eq!(deque, [11, 22, 33, 44, 0, 0xffff_ff80, 0, slot - 4,
            0x8000_0000, 0x6000, 9]);
        assert_eq!(frees, [(0, 32, 0)]);
    }
}
