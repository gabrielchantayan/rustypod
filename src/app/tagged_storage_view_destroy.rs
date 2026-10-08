//! Tagged storage view destruction — `FUN_08144124` @ 0x08144124.
//!
//! True extent: 56 bytes [0x08144124,0x0814415c): 52 instruction bytes
//! and the vtable literal 0x089860b0. The next function begins with
//! push {r4,r5,r6,lr}. Whole-image ARM word decoding finds two incoming
//! plain BLs (0x0807f848,0x0810316c), zero predicated BLs. This body has
//! zero plain BLs, one BLNE to free_wrapper @ 0x080e7970, and a tail B
//! to 0x08275cfc, itself a B to the bare BX LR at 0x08275bc8.
//!
//! Install the derived vtable, then free the pointer word at +0x0c only
//! when it is nonzero and the ownership byte at +0x23 is nonzero, passing
//! the byte at +0x20 as heap tag. Return the original object; do not clear
//! its pointer or flags. Both callers destroy 36-byte stack objects built
//! by 0x081440d8. The concrete class and other fields remain unidentified.
//! Deliberate deviations: omit the identity root-destructor tail veneer;
//! use the existing heap dispatch. Fixed u32 words preserve target layout
//! on hosts; volatile accesses retain the original read/write ordering.

use crate::heap::veneers::free_wrapper;

const VTABLE: u32 = 0x0898_60b0;

/// # Safety
/// `view` must point to nine writable, aligned u32 words. If word 3 and
/// byte +0x23 are nonzero, word 3 must be a live allocation compatible
/// with free_wrapper and the tag at +0x20. Destruction is not idempotent:
/// the firmware leaves the freed pointer and ownership byte installed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_storage_view_destroy(view: *mut u32) -> *mut u32 {
    view.write_volatile(VTABLE);
    let storage = view.add(3).read_volatile();
    if storage != 0 && view.cast::<u8>().add(0x23).read_volatile() != 0 {
        let tag = view.cast::<u8>().add(0x20).read_volatile();
        free_wrapper(storage as usize as *mut u8, tag as usize);
    }
    view
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
        try_map_u32_slab(hints::TAGGED_STORAGE_VIEW_DESTROY, 0x1000).map(|p| p as usize)
    });
    static mut FREES: Vec<(usize, usize, u32)> = Vec::new();
    static mut VIEW: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn observe_free(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        ptr: *mut u8, tag: usize,
    ) {
        let vtable = unsafe { (*core::ptr::addr_of!(VIEW)).read_volatile() };
        unsafe { (*core::ptr::addr_of_mut!(FREES)).push((ptr as usize, tag, vtable)) };
    }

    #[test]
    fn null_borrowed_and_owned_storage_preserve_fields_and_use_byte_tag() {
        let _guard = mock_heap();
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("app/tagged_storage_view_destroy"));
            return;
        };
        let saved = unsafe { HEAP_OPS };
        unsafe { HEAP_OPS.free = observe_free };
        for storage in [0, slab as u32] {
            for owned in [0u8, 1, 0x80, 0xff] {
                for tag in [0u8, 3, 0xff] {
                    let mut view = [0xa5a5_a5a5; 9];
                    view[3] = storage;
                    view[8] = u32::from_le_bytes([tag, 0x56, 0x78, owned]);
                    let mut expected = view;
                    expected[0] = VTABLE;
                    let ptr = view.as_mut_ptr();
                    unsafe {
                        VIEW = ptr;
                        (*core::ptr::addr_of_mut!(FREES)).clear();
                        assert_eq!(tagged_storage_view_destroy(ptr), ptr);
                    }
                    assert_eq!(view, expected);
                    let expected_frees = if storage != 0 && owned != 0 {
                        std::vec![(storage as usize, tag as usize, VTABLE)]
                    } else { std::vec![] };
                    assert_eq!(unsafe { &*core::ptr::addr_of!(FREES) }, &expected_frees);
                }
            }
        }
        unsafe { HEAP_OPS = saved; VIEW = core::ptr::null_mut() };
    }
}
