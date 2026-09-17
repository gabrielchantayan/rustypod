//! Current deque-iterator word retrieval.

use crate::cxx::templates::{container_is_empty, deque_iter_assign_alias_a34c};

/// `deque_iterator_current_or_zero` — original: `FUN_082156b8` @ `0x082156b8`.
///
/// Raw ARM establishes a 56-byte extent (`0x082156b8..0x082156ef`): it saves
/// r0-r3, r4-r6 and lr, calls `container_is_empty` (`0x083d7610`), copies the
/// four-word iterator with `deque_iter_assign_alias_a34c` (`0x083da34c`) when
/// nonempty, loads the copied iterator's current word, and returns it. The
/// separately linked prologue at `0x082156f0` fixes the boundary. Four inbound
/// plain `bl` call sites (`0x082155f4`, `0x08215824`, `0x082158c4`, and
/// `0x082158f4`) and zero predicated `bl` call sites are verified from raw A32
/// branch encodings.
///
/// The iterator's count word is at `+0x20`; an empty iterator returns zero
/// without reading its four-word state. A nonempty iterator performs the same
/// forward four-word copy as retailOS before returning its first (`current`)
/// word. Deliberate deviations: none; the existing ports preserve both direct
/// callees and the target's aligned 32-bit word layout.
///
/// # Safety
///
/// `iterator` must point to at least nine readable aligned `u32` words. When
/// its ninth word is nonzero, its first four words must also be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_iterator_current_or_zero(iterator: *const u32) -> u32 {
    if container_is_empty(iterator.cast()) != 0 {
        return 0;
    }

    let mut copy = [0u32; 4];
    deque_iter_assign_alias_a34c(copy.as_mut_ptr(), iterator);
    copy[0]
}

#[cfg(test)]
mod tests {
    use super::deque_iterator_current_or_zero;

    #[test]
    fn returns_zero_for_empty_iterator_without_mutation() {
        unsafe {
            let mut iterator = [0xfeed_faceu32; 9];
            iterator[0] = 0x1234_5678;
            iterator[8] = 0;
            let before = iterator;

            assert_eq!(deque_iterator_current_or_zero(iterator.as_ptr()), 0);
            assert_eq!(iterator, before);
        }
    }

    #[test]
    fn returns_current_word_for_each_nonzero_count() {
        unsafe {
            for count in [1, 2, u32::MAX] {
                let mut iterator = [0u32; 9];
                iterator[..4].copy_from_slice(&[0x89ab_cdef, 0, u32::MAX, 0x1020_3040]);
                iterator[8] = count;
                let before = iterator;

                assert_eq!(deque_iterator_current_or_zero(iterator.as_ptr()), 0x89ab_cdef);
                assert_eq!(iterator, before, "count {count:#x} must not mutate the iterator");
            }
        }
    }
}
