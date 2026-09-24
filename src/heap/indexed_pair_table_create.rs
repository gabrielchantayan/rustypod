//! `indexed_pair_table_create` — original: `FUN_0805e51c` @ 0x0805e51c
//! (36 bytes; 0x0805e51c..0x0805e53f). Raw `osos.dec` words establish that
//! 0x0805e540 is the next function boundary. Whole-image A32 decoding finds
//! three incoming plain `bl` call sites and no predicated forms; this body has
//! one plain outgoing `bl` to `malloc_tag4` and no predicated direct calls.
//!
//! Allocates a 12-byte count header followed by `count` eight-byte pairs using
//! heap tag 4. It stores `count` in the header only when allocation succeeds
//! and returns NULL unchanged on failure. The target's 32-bit size arithmetic
//! deliberately wraps before crossing Rust's host-width allocator ABI.

use crate::heap::veneers::malloc_tag4;

const HEADER_SIZE: u32 = 12;
const PAIR_SIZE: u32 = 8;

/// Allocates a count-prefixed table of eight-byte entries.
///
/// # Safety
///
/// On success the caller owns the returned tag-4 heap block and must treat its
/// first target word as the count followed by `count` eight-byte entries.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.indexed_pair_table_create")]
pub unsafe extern "C" fn indexed_pair_table_create(count: u32) -> *mut u32 {
    let size = count.wrapping_mul(PAIR_SIZE).wrapping_add(HEADER_SIZE);
    let table = malloc_tag4(size as usize).cast::<u32>();
    if !table.is_null() {
        *table = count;
    }
    table
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use core::ptr;

    #[test]
    fn allocates_count_header_and_pair_entries() {
        let _heap = mock_heap();
        let mut table = [0_u32; 3];
        set_alloc_ret(table.as_mut_ptr().cast());

        let result = unsafe { indexed_pair_table_create(2) };

        assert_eq!(result, table.as_mut_ptr());
        assert_eq!(alloc_log(), (1, 28, 4));
        assert_eq!(table[0], 2);
    }

    #[test]
    fn allocation_failure_returns_null_without_writing() {
        let _heap = mock_heap();
        set_alloc_ret(ptr::null_mut());

        assert!(unsafe { indexed_pair_table_create(7) }.is_null());
        assert_eq!(alloc_log(), (1, 68, 4));
    }

    #[test]
    fn target_width_size_arithmetic_wraps() {
        let _heap = mock_heap();
        let mut table = [0_u32; 3];
        set_alloc_ret(table.as_mut_ptr().cast());

        unsafe { indexed_pair_table_create(0x2000_0000) };

        assert_eq!(alloc_log(), (1, 12, 4));
        assert_eq!(table[0], 0x2000_0000);
    }
}
