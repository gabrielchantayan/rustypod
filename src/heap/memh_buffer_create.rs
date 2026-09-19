//! `memh_buffer_create` — original: `FUN_0805d170` @ 0x0805d170
//! (100 bytes: 96 instruction bytes plus the required trailing `"MemH"`
//! literal at 0x0805d1d0; the next independent function begins at
//! 0x0805d1d4). Four incoming plain `bl` call sites and no predicated calls
//! target it; decoding its body finds three plain outgoing `bl`s and no
//! predicated `bl`s.
//!
//! Allocates a 16-byte MemH header with heap tag 4, then a zeroed payload of
//! `size` bytes with the same tag. On success it writes `{ payload, "MemH",
//! size, size }` and returns the header. If either allocation fails, it
//! returns NULL; a payload failure first releases the header. The allocator
//! wrappers are already ported, so Rust directly calls them rather than
//! creating a seam for their verified identities.

use crate::heap::memh_set_len::MemhBufferHeader;
use crate::heap::veneers::{calloc_wrapper, free_wrapper, malloc_wrapper};
use crate::heap::memh_handle::MEMH_MAGIC;

const MEMH_HEAP_TAG: usize = 4;
const MEMH_HEADER_SIZE: usize = 16;

/// Allocates a zero-filled MemH buffer with `size` bytes initially in use.
///
/// # Safety
///
/// The returned pointer, when non-NULL, is owned by the tag-4 heap family and
/// must eventually be released through the MemH destructor path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.memh_buffer_create")]
pub unsafe extern "C" fn memh_buffer_create(size: u32) -> *mut MemhBufferHeader {
    let header = malloc_wrapper(MEMH_HEADER_SIZE, MEMH_HEAP_TAG).cast::<MemhBufferHeader>();
    if header.is_null() {
        return core::ptr::null_mut();
    }

    let payload = calloc_wrapper(size as usize, MEMH_HEAP_TAG);
    if payload.is_null() {
        free_wrapper(header.cast(), MEMH_HEAP_TAG);
        return core::ptr::null_mut();
    }

    (*header).payload = payload as usize as u32;
    (*header).magic = MEMH_MAGIC;
    (*header).capacity = size;
    (*header).length = size;
    header
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, alloc_zero_log, mock_heap, set_alloc_ret};
    use core::ptr;

    #[test]
    fn allocates_header_then_zeroed_payload_and_initializes_all_target_words() {
        let _heap = mock_heap();
        let mut storage = MemhBufferHeader {
            payload: 0,
            magic: 0,
            capacity: 0,
            length: 0,
        };
        set_alloc_ret(ptr::addr_of_mut!(storage).cast());

        let header = unsafe { memh_buffer_create(0x31) };

        assert!(!header.is_null());
        assert_eq!(alloc_log(), (1, MEMH_HEADER_SIZE, MEMH_HEAP_TAG));
        assert_eq!(alloc_zero_log(), (1, 0x31, MEMH_HEAP_TAG));
        assert_eq!(unsafe { (*header).magic }, MEMH_MAGIC);
        assert_eq!(unsafe { ((*header).capacity, (*header).length) }, (0x31, 0x31));
        assert_eq!(unsafe { (*header).payload }, header as usize as u32);
    }

    #[test]
    fn header_allocation_failure_skips_the_payload_allocator() {
        let _heap = mock_heap();
        set_alloc_ret(core::ptr::null_mut());

        assert!(unsafe { memh_buffer_create(1) }.is_null());
        assert_eq!(alloc_log(), (1, MEMH_HEADER_SIZE, MEMH_HEAP_TAG));
        assert_eq!(alloc_zero_log().0, 0);
    }
}
