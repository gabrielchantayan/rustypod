//! Binary-heap adjustment from retailOS.
//!
//! `FUN_083e7f40` @ `0x083e7f40` is **172 bytes**
//! (`0x083e7f40..0x083e7fec`; the next independently linked function starts
//! at `0x083e7fec`). Raw ARM decoding verifies two incoming unconditional
//! plain `bl` calls (`0x083e7d74`, `0x083e81d8`) and no predicated `bl`
//! calls. Its body has two unconditional indirect `blx r7` comparator calls.
//!
//! Algorithm: place `value` into the hole at `hole_index` in a binary heap of
//! `element_count` u32 values. First promote a child to the hole, preferring
//! the left child only when `compare(right, left)` is non-zero, until a leaf is
//! reached; then sift `value` upward while `compare(parent, value)` is
//! non-zero. This is the C++ `adjust_heap` primitive used by the adjacent
//! heap build and removal helpers.
//!
//! Deliberate deviations: Rust names the opaque predicate `compare` and uses
//! a typed function pointer rather than the retail register-held code pointer;
//! it otherwise retains the exact non-zero predicate convention and aligned
//! 32-bit element accesses.

/// Opaque retail comparator used by [`heap_adjust`]. The routine preserves
/// only its observed non-zero predicate convention.
pub type HeapCompare = unsafe extern "C" fn(u32, u32) -> i32;

/// Restores a binary heap after the element at `hole_index` has been removed.
///
/// # Safety
///
/// `heap` must point to at least `element_count` aligned u32 elements;
/// `hole_index` must select an element within that range. `compare` must be a
/// valid retailOS-style comparator for every element pair the heap walk reads.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn heap_adjust(
    heap: *mut u32,
    hole_index: i32,
    element_count: i32,
    value: u32,
    compare: HeapCompare,
) {
    let mut hole = hole_index;
    let mut child = hole * 2 + 2;

    while child < element_count {
        if compare(*heap.add(child as usize), *heap.add((child - 1) as usize)) != 0 {
            child -= 1;
        }
        *heap.add(hole as usize) = *heap.add(child as usize);
        hole = child;
        child = hole * 2 + 2;
    }

    if child == element_count {
        *heap.add(hole as usize) = *heap.add((child - 1) as usize);
        hole = child - 1;
    }

    while hole_index < hole {
        let parent = (hole - 1) / 2;
        if compare(*heap.add(parent as usize), value) == 0 {
            break;
        }
        *heap.add(hole as usize) = *heap.add(parent as usize);
        hole = parent;
    }

    *heap.add(hole as usize) = value;
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn first_is_greater(left: u32, right: u32) -> i32 {
        (left > right) as i32
    }

    #[test]
    fn promotes_left_child_when_no_right_child_exists() {
        let mut heap = [1, 2, 3, 4, 5, 6];
        unsafe { heap_adjust(heap.as_mut_ptr(), 2, 6, 7, first_is_greater) };
        assert_eq!(heap, [1, 2, 6, 4, 5, 7]);
    }

    #[test]
    fn chooses_right_child_when_the_predicate_is_false() {
        let mut heap = [1, 3, 2, 4, 5, 6, 7];
        unsafe { heap_adjust(heap.as_mut_ptr(), 0, 7, 9, first_is_greater) };
        assert_eq!(heap, [2, 3, 6, 4, 5, 9, 7]);
    }

    #[test]
    fn sifts_value_back_up_after_descending_to_a_leaf() {
        let mut heap = [1, 2, 3, 4, 5, 6, 7];
        unsafe { heap_adjust(heap.as_mut_ptr(), 0, 7, 0, first_is_greater) };
        assert_eq!(heap, [0, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn singleton_heap_keeps_the_replacement_value() {
        let mut heap = [0];
        unsafe { heap_adjust(heap.as_mut_ptr(), 0, 1, 42, first_is_greater) };
        assert_eq!(heap, [42]);
    }
}
