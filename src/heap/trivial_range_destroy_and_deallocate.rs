//! Destruction and deallocation of a range with trivial element destructors.

use crate::heap::veneers::cxx_array_dealloc;

/// cxx_trivial_range_destroy_and_deallocate — original `FUN_083e12a0` @
/// 0x083e12a0 (60 bytes): one internal plain `bl` to `cxx_array_dealloc`;
/// two direct incoming plain `bl` call sites (0x08268318 and 0x08268338), and
/// no predicated `bl` instructions.
///
/// Raw ARM words establish the exact 60-byte extent 0x083e12a0..0x083e12db:
/// `pop {r4,pc}` returns at its end and the next independently linked function
/// begins with `push {r4-r8,lr}` at 0x083e12dc. The three target-width words
/// are `{begin, end, capacity}`. retailOS walks `begin..end` to run the empty
/// element destructor, then deallocates `begin` with `capacity - begin` and
/// element size zero. Rust preserves the otherwise empty walk and its
/// wrapping u32 cursor arithmetic; target-width pointer words remain explicit
/// on 64-bit hosts. No deliberate deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_trivial_range_destroy_and_deallocate(range: *mut u32) -> *mut u32 {
    let begin = range.read();
    let end = range.add(1).read();
    let mut cursor = begin;
    while cursor != end {
        cursor = cursor.wrapping_add(1);
    }
    let capacity = range.add(2).read();
    cxx_array_dealloc(
        begin as usize as *mut u8,
        capacity.wrapping_sub(begin) as usize,
        0,
    );
    range
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn deallocates_begin_with_capacity_span_and_preserves_range_words() {
        let Some(slab) = try_map_u32_slab(hints::TRIVIAL_RANGE_DESTROY_AND_DEALLOCATE, 0x1000) else {
            return;
        };
        let _heap = mock_heap();
        let range = slab.cast::<u32>();
        let begin = unsafe { slab.add(0x100) };
        unsafe {
            range.write(begin as u32);
            range.add(1).write(begin.add(0x14) as u32);
            range.add(2).write(begin.add(0x40) as u32);
            assert_eq!(cxx_trivial_range_destroy_and_deallocate(range), range);
            assert_eq!(free_log(), (1, begin, 2));
            assert_eq!(range.read(), begin as u32);
            assert_eq!(range.add(1).read(), begin.add(0x14) as u32);
            assert_eq!(range.add(2).read(), begin.add(0x40) as u32);
        }
    }

    #[test]
    fn empty_null_range_reaches_the_delete_null_guard() {
        let Some(slab) = try_map_u32_slab(hints::TRIVIAL_RANGE_DESTROY_AND_DEALLOCATE_NULL, 0x1000) else {
            return;
        };
        let _heap = mock_heap();
        let range = slab.cast::<u32>();
        unsafe {
            range.write(0);
            range.add(1).write(0);
            range.add(2).write(0);
            assert_eq!(cxx_trivial_range_destroy_and_deallocate(range), range);
            assert_eq!(free_log().0, 0);
        }
    }
}
