//! Drain the four-byte deque used by path-processing temporaries.
//!
//! `FUN_083df8b8` @ 0x083df8b8: true size 44 bytes, ending at the
//! independent PUSH at 0x083df8e4. Whole-image aligned A32 decoding finds
//! one inbound plain BL (0x0825c434), zero predicated inbound BLs. The body
//! has two plain BLs (front advancement at 0x083df8c8 and emptiness at
//! 0x083df8d0), zero predicated BLs. Test emptiness before each removal,
//! repeatedly advance/release the front, then return the original pointer.
//!
//! Deliberate deviations: reuse container_is_empty for its byte-identical
//! alias at 0x083d7620. Host tests inject release/deallocation into the real
//! front-advancement algorithm; the exported path calls existing ports.

use crate::cxx::deque_front_advance_release::deque_front_advance_release;
use crate::cxx::templates::container_is_empty;

/// # Safety
/// `deque` must describe eleven writable target-width words and valid owned
/// elements, segments, and map storage for every front removal.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_drain_front_release(deque: *mut u32) -> *mut u32 {
    drain_with(deque, |deque| deque_front_advance_release(deque))
}

#[inline(always)]
unsafe fn drain_with<F: FnMut(*mut u32)>(deque: *mut u32, mut advance: F) -> *mut u32 {
    while container_is_empty(deque.cast()) == 0 {
        advance(deque);
    }
    deque
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::cxx::deque_front_advance_release::deque_front_advance_release_with;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn empty_export_preserves_all_words_and_returns_self() {
        let mut words = [0xdead_beef; 11];
        words[8] = 0;
        let before = words;
        let pointer = words.as_mut_ptr();
        assert_eq!(unsafe { deque_drain_front_release(pointer) }, pointer);
        assert_eq!(words, before);
    }

    #[test]
    fn drains_singleton_and_cross_segment_range_in_release_order() {
        let Some(slab) = try_map_u32_slab(hints::DEQUE_DRAIN_FRONT_RELEASE, 16) else { return; };
        let slots = slab.cast::<u32>();
        for count in [1, 3] {
            unsafe { slots.write(0x1000); slots.add(1).write(0x2000); }
            let mut words = [0u32; 11];
            words[..4].copy_from_slice(&[0x107c, 0x1000, 0x1080, slots as usize as u32]);
            words[4..8].copy_from_slice(&[0x2008, 0x2000, 0x2080, unsafe { slots.add(1) } as usize as u32]);
            words[8] = count;
            words[9] = slots as usize as u32;
            words[10] = 2;
            let pointer = words.as_mut_ptr();
            let mut released = std::vec::Vec::new();
            let mut frees = std::vec::Vec::new();
            let result = unsafe {
                drain_with(pointer, |deque| deque_front_advance_release_with(deque,
                    |element| released.push(element),
                    |ptr, capacity, size| frees.push((ptr, capacity, size))))
            };
            assert_eq!(result, pointer);
            assert_eq!(released, if count == 1 { std::vec![0x107c] } else { std::vec![0x107c, 0x2000, 0x2004] });
            let mut expected = std::vec![(0x1000, 0x20, 0)];
            if count == 3 { expected.push((0x2000, 0x20, 0)); }
            expected.push((slots as usize as u32, 2, 0));
            assert_eq!(frees, expected);
            assert_eq!(&words[..9], &[0; 9]);
            assert_eq!(&words[9..], &[slots as usize as u32, 2]);
        }
    }
}
