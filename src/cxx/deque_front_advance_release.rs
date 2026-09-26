//! Four-byte deque-front advancement with release.

use crate::cxx::string::cxx_string_release;
use crate::heap::block_deque::deque_seg_capacity;
use crate::heap::veneers::cxx_array_dealloc;

/// deque_front_advance_release — original: `FUN_083df7e4` @ 0x083df7e4
/// (212 bytes; raw extent 0x083df7e4..0x083df8b8, bounded by the next real
/// function at 0x083df8b8).
///
/// Raw A32 has seven unconditional plain `bl` instructions and no predicated
/// `bl`: `cxx_string_release` @ 0x083d8b04, `container_is_empty` @
/// 0x083d7620 twice, `deque_seg_capacity` @ 0x083da3dc, `cxx_array_dealloc`
/// @ 0x08266f2c, and `deque_iter_init_elem4_alias_a3e4` @ 0x083da3e4 twice.
/// Complete branch decoding finds two inbound unconditional plain `bl` sites
/// (0x0825c3b4 and 0x083df8c8), with no predicated inbound calls.
///
/// Releases the four-byte front element, advances the cursor, and decrements
/// the count. At a spent segment or an empty deque it advances the map slot,
/// deallocates the retired segment, then either re-anchors the front iterator
/// at the next segment or NULL-initializes both iterators and frees the map.
/// All fields are word indices so host pointer width cannot alter target
/// offsets +0x00..+0x28.
///
/// Deliberate deviations: existing shared ports replace the adjacent capacity
/// and iterator-init copies. The iterator initialization is expressed as its
/// four target-width stores; callbacks make the two allocator boundaries
/// observable in host tests rather than reproducing retail direct `bl`s.
///
/// # Safety
/// `deque` must point to eleven writable target-width words describing a
/// nonempty four-byte deque. Every nonzero encoded address must be valid for
/// the original callee's documented access.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_front_advance_release(deque: *mut u32) {
    deque_front_advance_release_with(
        deque,
        |element| cxx_string_release(element as usize as *mut *mut u8),
        |ptr, count, elem| cxx_array_dealloc(ptr as usize as *mut u8, count as usize, elem as usize),
    );
}

unsafe fn deque_front_advance_release_with<R, D>(
    deque: *mut u32,
    mut release: R,
    mut deallocate: D,
) where
    R: FnMut(u32),
    D: FnMut(u32, u32, u32),
{
    let words = core::slice::from_raw_parts_mut(deque, 11);
    let old_element = words[0];
    words[0] = old_element.wrapping_add(4);
    words[8] = words[8].wrapping_sub(1);
    release(old_element);

    if words[8] != 0 && words[0] != words[2] {
        return;
    }

    let old_slot = words[3];
    words[3] = old_slot.wrapping_add(4);
    let old_segment = (old_slot as usize as *const u32).read();
    deallocate(old_segment, deque_seg_capacity() as u32, 0);

    if words[8] != 0 {
        let next_segment = (words[3] as usize as *const u32).read();
        words[0] = next_segment;
        words[1] = next_segment;
        words[2] = next_segment.wrapping_add((deque_seg_capacity() * 4) as u32);
        return;
    }

    let empty_iter = [0; 4];
    words[4..8].copy_from_slice(&empty_iter);
    words[0..4].copy_from_slice(&empty_iter);
    deallocate(words[9], words[10], 0);
}

#[cfg(test)]
mod tests {
    use super::deque_front_advance_release_with;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn advances_and_releases_without_retiring_the_segment() {
        let mut deque = [0u32; 11];
        deque[0] = 0x1000;
        deque[2] = 0x1080;
        deque[3] = 0x2000;
        deque[8] = 2;
        let mut released = 0;
        let mut frees = 0;

        unsafe {
            deque_front_advance_release_with(deque.as_mut_ptr(), |element| released = element, |_, _, _| frees += 1);
        }

        assert_eq!(deque[0], 0x1004);
        assert_eq!(deque[8], 1);
        assert_eq!(released, 0x1000);
        assert_eq!(frees, 0);
    }

    #[test]
    fn retires_segment_and_reanchors_nonempty_deque() {
        let Some(slots) = try_map_u32_slab(hints::DEQUE_FRONT_ADVANCE_RELEASE, 8) else {
            return;
        };
        let slots = slots.cast::<u32>();
        unsafe {
            slots.write(0x3000);
            slots.add(1).write(0x4000);
        }
        let mut deque = [0u32; 11];
        deque[0] = 0x107c;
        deque[2] = 0x1080;
        deque[3] = slots as usize as u32;
        deque[8] = 2;
        let mut released = 0;

        unsafe {
            deque_front_advance_release_with(deque.as_mut_ptr(), |element| released = element, |ptr, count, elem| {
                assert_eq!((ptr, count, elem), (0x3000, 0x20, 0));
            });
        }

        assert_eq!(released, 0x107c);
        assert_eq!(deque[0], 0x4000);
        assert_eq!(deque[1], 0x4000);
        assert_eq!(deque[2], 0x4080);
        assert_eq!(deque[3], unsafe { slots.add(1) } as usize as u32);
        assert_eq!(deque[8], 1);
    }

    #[test]
    fn empties_iterators_and_releases_map() {
        let Some(slots) = try_map_u32_slab(hints::DEQUE_FRONT_ADVANCE_RELEASE_EMPTY, 4) else {
            return;
        };
        let slots = slots.cast::<u32>();
        unsafe { slots.write(0x3000) };
        let mut deque = [0u32; 11];
        deque[0] = 0x107c;
        deque[2] = 0x1080;
        deque[3] = slots as usize as u32;
        deque[8] = 1;
        deque[9] = 0x5000;
        deque[10] = 6;
        let mut released = 0;
        let mut frees = [(0, 0, 1); 2];
        let mut free_count = 0;

        unsafe {
            deque_front_advance_release_with(deque.as_mut_ptr(), |element| released = element, |ptr, count, elem| {
                frees[free_count] = (ptr, count, elem);
                free_count += 1;
            });
        }

        assert_eq!(released, 0x107c);
        assert_eq!(deque[0..8], [0; 8]);
        assert_eq!(frees, [(0x3000, 0x20, 0), (0x5000, 6, 0)]);
    }
}
