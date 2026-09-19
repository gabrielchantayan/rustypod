//! `memh_resize` — original: `FUN_0805d1e4` @ 0x0805d1e4 (140 bytes;
//! 3 plain `bl` plus 1 predicated `blgt` call site, binary-verified from
//! osos.dec). The next function begins with `push {r4-r6,lr}` at 0x0805d270,
//! confirming Ghidra's 140-byte extent.
//!
//! Resizes the optional MemH buffer stored in `*slot`. A NULL slot, or a
//! negative relative resize that would make the current length negative,
//! returns -50. An empty slot allocates a 16-byte MemH header and a zeroed
//! payload of the requested size; allocation failure returns -108 and leaves
//! the slot NULL. An existing header is resized through `memh_set_len`; a
//! successful positive relative resize explicitly zeroes the appended bytes.
//!
//! Deliberate deviations: the retail constructor calls the unported local
//! entry @ 0x0805d170, and the zeroing path calls bzero @ 0x0805cfb4. This
//! port inlines the verified constructor sequence through the existing heap
//! wrappers and uses Rust volatile byte stores, preserving allocation and
//! zero-fill semantics without creating unidentified seams.

use crate::heap::memh_handle::MEMH_MAGIC;
use crate::heap::memh_set_len::{memh_set_len, MemhBufferHeader};
use crate::heap::veneers::{calloc_wrapper, free_wrapper, malloc_wrapper};

const MEMH_HEAP_TAG: usize = 4;
const ERR_BAD_HANDLE: i32 = -50;
const ERR_ALLOC_FAILED: i32 = -108;

/// Resizes the optional MemH buffer in `slot` by `delta` bytes.
///
/// # Safety
///
/// `slot` must be NULL or point to a readable/writable target-width pointer.
/// A non-NULL `*slot` must be a valid [`MemhBufferHeader`] accepted by
/// [`memh_set_len`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.memh_resize")]
pub unsafe extern "C" fn memh_resize(slot: *mut *mut MemhBufferHeader, delta: i32) -> i32 {
    if slot.is_null() {
        return ERR_BAD_HANDLE;
    }

    let header = *slot;
    if header.is_null() {
        let new_header = malloc_wrapper(core::mem::size_of::<MemhBufferHeader>(), MEMH_HEAP_TAG)
            .cast::<MemhBufferHeader>();
        if new_header.is_null() {
            return ERR_ALLOC_FAILED;
        }
        let payload = calloc_wrapper(delta as u32 as usize, MEMH_HEAP_TAG);
        if payload.is_null() {
            free_wrapper(new_header.cast(), MEMH_HEAP_TAG);
            return ERR_ALLOC_FAILED;
        }
        new_header.write(MemhBufferHeader {
            payload: payload as usize as u32,
            magic: MEMH_MAGIC,
            capacity: delta as u32,
            length: delta as u32,
        });
        *slot = new_header;
        return 0;
    }

    let old_len = (*header).length as i32;
    let new_len = old_len.wrapping_add(delta);
    if delta < 0 && new_len < 0 {
        return ERR_BAD_HANDLE;
    }
    let status = memh_set_len(header, new_len as u32);
    if status == 0 && delta > 0 {
        let appended = ((*header).payload as usize as *mut u8).add(old_len as usize);
        for offset in 0..delta as usize {
            core::ptr::write_volatile(appended.add(offset), 0);
        }
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, free_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x400;
    const PAYLOAD_OFF: usize = 0x100;
    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::MEMH_RESIZE, FIXTURE_LEN).map(|p| p as usize));

    fn fixture(length: u32, capacity: u32) -> Option<*mut MemhBufferHeader> {
        let slab = (*SLAB)? as *mut u8;
        unsafe {
            for offset in 0..FIXTURE_LEN {
                slab.add(offset).write(0xA5);
            }
            slab.cast::<MemhBufferHeader>().write(MemhBufferHeader {
                payload: slab.add(PAYLOAD_OFF) as usize as u32,
                magic: MEMH_MAGIC,
                capacity,
                length,
            });
        }
        Some(slab.cast())
    }

    #[test]
    fn null_slot_returns_bad_handle_without_allocating() {
        let _heap = mock_heap();
        assert_eq!(unsafe { memh_resize(core::ptr::null_mut(), 1) }, ERR_BAD_HANDLE);
        assert_eq!(alloc_log().0, 0);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn negative_resize_past_zero_leaves_header_untouched() {
        let _heap = mock_heap();
        let Some(header) = fixture(3, 16) else {
            note_missing_u32_fixture("heap::memh_resize");
            return;
        };
        let mut slot = header;
        assert_eq!(unsafe { memh_resize(&mut slot, -4) }, ERR_BAD_HANDLE);
        assert_eq!(unsafe { (*header).length }, 3);
        assert_eq!(alloc_log().0, 0);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn positive_resize_within_capacity_zeros_only_the_new_tail() {
        let _heap = mock_heap();
        let Some(header) = fixture(3, 16) else {
            note_missing_u32_fixture("heap::memh_resize");
            return;
        };
        let slab = (*SLAB).unwrap() as *mut u8;
        unsafe {
            slab.add(PAYLOAD_OFF).write(0x11);
            slab.add(PAYLOAD_OFF + 1).write(0x22);
            slab.add(PAYLOAD_OFF + 2).write(0x33);
        }
        let mut slot = header;
        assert_eq!(unsafe { memh_resize(&mut slot, 4) }, 0);
        assert_eq!(unsafe { (*header).length }, 7);
        assert_eq!(unsafe { slab.add(PAYLOAD_OFF).read() }, 0x11);
        assert_eq!(unsafe { slab.add(PAYLOAD_OFF + 2).read() }, 0x33);
        for offset in 3..7 {
            assert_eq!(unsafe { slab.add(PAYLOAD_OFF + offset).read() }, 0);
        }
        assert_eq!(unsafe { slab.add(PAYLOAD_OFF + 7).read() }, 0xA5);
    }

    #[test]
    fn empty_slot_header_allocation_failure_keeps_slot_null() {
        let _heap = mock_heap();
        set_alloc_ret(core::ptr::null_mut());
        let mut slot = core::ptr::null_mut();
        assert_eq!(unsafe { memh_resize(&mut slot, 8) }, ERR_ALLOC_FAILED);
        assert!(slot.is_null());
        assert_eq!(alloc_log().0, 1);
        assert_eq!(free_log().0, 0);
    }
}
