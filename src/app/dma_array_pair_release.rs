//! `dma_array_pair_release` — `FUN_081e17d4` @ 0x081e17d4.
//!
//! True extent: 72 bytes, 0x081e17d4..0x081e181c, ending in pop
//! {r4,r5,r6,pc} before the next independent push. Whole-image raw A32
//! decoding finds two inbound plain BLs (0x081e1a78, 0x081e1c14), zero
//! predicated BLs. The body has four plain BLs, zero predicated BLs:
//! dma_aligned_array_destroy and operator_delete for each owner.
//!
//! Destroy and tag-2-delete nonzero owners at +0x3c and +0x40 in order,
//! clearing each slot after deletion. Reload the second owner after releasing
//! the first. Finally clear the first array's view (+0x2c) and count (+0x34);
//! retain the second view (+0x30) and count (+0x38), even if now stale.
//! Deliberate deviations: none beyond the existing callees' documented
//! implementations. Word indices preserve target offsets on 64-bit hosts;
//! the containing class's identity is not established. No return value is
//! promised: r0 is callee-dependent in the original.

use crate::cxx::dma_aligned_array_destroy::{dma_aligned_array_destroy, DmaAlignedArray};
use crate::heap::veneers::operator_delete;

/// # Safety
/// `state` must point to at least 17 writable, aligned target-width words.
/// Each nonzero owner must name a distinct live tag-2 DmaAlignedArray object
/// satisfying `dma_aligned_array_destroy`'s allocation safety requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_array_pair_release(state: *mut u32) {
    unsafe {
        let first = state.add(15).read();
        if first != 0 {
            let owner = dma_aligned_array_destroy(first as usize as *mut DmaAlignedArray);
            operator_delete(owner.cast());
            state.add(15).write(0);
        }
        let second = state.add(16).read();
        if second != 0 {
            let owner = dma_aligned_array_destroy(second as usize as *mut DmaAlignedArray);
            operator_delete(owner.cast());
            state.add(16).write(0);
        }
        state.add(11).write(0);
        state.add(13).write(0);
    }
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
        try_map_u32_slab(hints::DMA_ARRAY_PAIR_RELEASE, 0x1000).map(|p| p as usize)
    });
    static mut FREES: Vec<(usize, usize)> = Vec::new();

    unsafe extern "C" fn observe_free(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        ptr: *mut u8, tag: usize,
    ) {
        if tag == 2 {
            // Real destruction must finish before deleting the array object.
            assert_eq!(unsafe { (*ptr.cast::<DmaAlignedArray>()).constructed }, 0);
        }
        unsafe { (*core::ptr::addr_of_mut!(FREES)).push((ptr as usize, tag)) };
    }

    #[test]
    fn optional_owners_release_in_order_preserving_second_view_and_count() {
        let _guard = mock_heap();
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("app/dma_array_pair_release"));
            return;
        };
        let saved = unsafe { HEAP_OPS };
        unsafe { HEAP_OPS.free = observe_free };
        for mask in 0..4 {
            let mut state = [0x1122_3344u32; 17];
            let mut expected = Vec::new();
            for index in 0..2 {
                let owner = (slab + index * 0x100) as *mut DmaAlignedArray;
                let allocation = slab + 0x400 + index * 0x100;
                unsafe { owner.write(DmaAlignedArray {
                    allocation: allocation as u32, aligned_data: allocation as u32,
                    element_count: index as u32 + 1, constructed: 1,
                }) };
                state[15 + index] = if mask & (1 << index) != 0 {
                    expected.push((allocation, 3));
                    expected.push((owner as usize, 2));
                    owner as usize as u32
                } else { 0 };
            }
            let mut reference = state;
            for index in [11, 13, 15, 16] { reference[index] = 0; }
            unsafe {
                (*core::ptr::addr_of_mut!(FREES)).clear();
                dma_array_pair_release(state.as_mut_ptr());
            }
            assert_eq!(state, reference);
            assert_eq!(unsafe { &*core::ptr::addr_of!(FREES) }, &expected);
            unsafe { dma_array_pair_release(state.as_mut_ptr()) };
            assert_eq!(state, reference);
            assert_eq!(unsafe { &*core::ptr::addr_of!(FREES) }, &expected);
        }
        unsafe { HEAP_OPS = saved };
    }
}
