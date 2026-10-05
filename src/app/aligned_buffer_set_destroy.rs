//! Aligned-buffer set destruction — `FUN_0818dab8` @ 0x0818dab8.
//!
//! True executable size: 148 bytes, [0x0818dab8,0x0818db4c); the
//! vtable literal occupies the next four bytes, then the next independent
//! function starts at 0x0818db50. Raw whole-image branch decoding verifies
//! two inbound plain BLs, no predicated BLs; this body has ten plain BLs
//! (five reset/delete pairs), no predicated BLs.
//!
//! Install vtable 0x08989a94, destroy aligned-buffer owners at word indices
//! 0x119, 0x11b, 0x11c, 0x11a, 0x11d in that order, clearing each of the
//! first four slots even when absent. Leave the last slot unchanged, clear
//! word 0x101, and return this. The containing class is not identified.
//! Deliberate deviations: loop rather than five unrolled pairs; existing
//! heap dispatch in the ported callees. Target pointer words stay u32 on hosts.

use crate::heap::aligned_buffer::aligned_buffer_reset;
use crate::heap::veneers::operator_delete;

const VTABLE: u32 = 0x0898_9a94;
const OWNER_WORDS: [usize; 5] = [0x119, 0x11b, 0x11c, 0x11a, 0x11d];

/// # Safety
/// `owner` must cover 0x11e writable aligned words. Each nonzero owner slot
/// must name a live tag-2 two-word aligned-buffer object, with its allocation
/// word satisfying `aligned_buffer_reset`'s contract. Destroy only once when
/// the last slot is nonzero: the firmware leaves that freed pointer installed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn aligned_buffer_set_destroy(owner: *mut u32) -> *mut u32 {
    owner.write_volatile(VTABLE);
    for word in OWNER_WORDS {
        let buffer = owner.add(word).read_volatile() as usize as *mut u8;
        if !buffer.is_null() {
            let reset = aligned_buffer_reset(buffer);
            operator_delete(reset);
        }
        if word != 0x11d {
            owner.add(word).write_volatile(0);
        }
    }
    owner.add(0x101).write_volatile(0);
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::{HEAP_OPS, tests::mock_heap};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};
    use std::sync::LazyLock;
    use std::vec::Vec;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ALIGNED_BUFFER_SET_DESTROY, 0x1000).map(|p| p as usize)
    });
    static mut FREES: Vec<(usize, usize)> = Vec::new();

    unsafe extern "C" fn observe_free(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        ptr: *mut u8, tag: usize,
    ) {
        if tag == 2 {
            assert_eq!(unsafe { ptr.cast::<u32>().read() }, 0);
            assert_eq!(unsafe { ptr.cast::<u32>().add(1).read() }, 0);
        }
        unsafe { (*core::ptr::addr_of_mut!(FREES)).push((ptr as usize, tag)) };
    }

    #[test]
    fn every_presence_mask_preserves_order_tags_and_the_uncleared_last_slot() {
        let _heap_guard = mock_heap();
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("app/aligned_buffer_set_destroy"));
            return;
        };
        let saved = unsafe { HEAP_OPS };
        unsafe { HEAP_OPS.free = observe_free };
        for mask in 0..32 {
            let mut owner = [0xa5a5_a5a5; 0x11e];
            let mut expected_owner = owner;
            let mut expected_frees = Vec::new();
            for (i, word) in OWNER_WORDS.into_iter().enumerate() {
                let buffer = (slab + i * 8) as *mut u32;
                // Some present owners have no allocation, but still need tag-2 deletion.
                let allocation = if i % 2 == 0 { 0x1230 + i as u32 * 16 } else { 0 };
                unsafe { buffer.write(0xdead_beef); buffer.add(1).write(allocation) };
                let present = mask & (1 << i) != 0;
                owner[word] = if present { buffer as u32 } else { 0 };
                expected_owner[word] = if i == 4 { owner[word] } else { 0 };
                if present {
                    if allocation != 0 { expected_frees.push((allocation as usize, 3)); }
                    expected_frees.push((buffer as usize, 2));
                }
            }
            expected_owner[0] = VTABLE;
            expected_owner[0x101] = 0;
            unsafe { (*core::ptr::addr_of_mut!(FREES)).clear() };
            let ptr = owner.as_mut_ptr();
            assert_eq!(unsafe { aligned_buffer_set_destroy(ptr) }, ptr);
            assert_eq!(owner, expected_owner, "presence mask {mask:#x}");
            assert_eq!(unsafe { &*core::ptr::addr_of!(FREES) }, &expected_frees);
        }
        unsafe { HEAP_OPS = saved };
    }
}
