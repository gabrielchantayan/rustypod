//! `element_array3_expand` — `FUN_083d3b28` @ **0x083d3b28**.
//! True code size: 120 bytes [0x083d3b28,0x083d3ba0); occupied extent
//! is 180 bytes through the next function at 0x083d3bdc, including strings.
//! Raw A32 scan: zero inbound plain BLs, one BLEQ at 0x083d3ad8;
//! three outbound plain BLs at 0x083d3b44 (realloc 0x0802edec),
//! 0x083d3b64 (zero-fill veneer 0x08037db8), and 0x083d3b98
//! (tracker_trace 0x083d3a8c); zero outbound predicated BLs.
//! Multiply capacity by growth modulo 2^32, publish realloc's result even
//! on failure, clear the added tail on success, then commit capacity.
//! Reuse the identical tracker algorithm and four-byte header word layout.
//! Deliberate deviation: omit diagnostic arguments and tracker_trace, whose
//! raw body is bx lr and whose returned r0 is not consumed. The zero-fill
//! veneer targets the IRAM mirror of ported memzero_aligned (0x0800027c).
//! LLVM may fold this body with other identical tracker expansion exports.

use super::element_tracker_array_expand::expand_with_realloc;

/// Grow an array-3 tracker, preserving its allocation-failure mutations.
///
/// # Safety
/// Header must be aligned and writable for six u32 words. Its storage word
/// and successful allocation must be valid for all wrapped byte ranges.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_array3_expand(array: *mut u32) {
    let reallocate = core::ptr::read_volatile(
        &(crate::runtime::malloc_rt::realloc as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
    );
    expand_with_realloc(array, reallocate);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::malloc_rt::{HEAP_OPS, tests::lock_ops};
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::LazyLock;

    static BACKING: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ELEMENT_ARRAY3_EXPAND, 0x1000).map(|p| p as usize)
    });
    static mut RESULT: *mut u8 = core::ptr::null_mut();
    static mut REQUEST: (*mut u8, usize) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn resize(storage: *mut u8, bytes: usize) -> *mut u8 {
        REQUEST = (storage, bytes);
        RESULT
    }

    unsafe extern "C" fn release(storage: *mut u8) {
        REQUEST = (storage, 0);
    }

    #[test]
    fn relocation_clears_only_new_slots_and_preserves_other_header_fields() {
        let _lock = lock_ops();
        let Some(address) = *BACKING else {
            crate::testing::note_missing_u32_fixture("app/element_array3_expand");
            return;
        };
        unsafe {
            let saved = HEAP_OPS;
            HEAP_OPS.realloc = resize;
            HEAP_OPS.free = release;
            for (old, growth) in [(2u32, 1u32), (2, 3), (7, 2)] {
                let words = core::slice::from_raw_parts_mut(address as *mut u32, 20);
                words.fill(0xdead_beef);
                let mut header = [0x1234, old, 1, 0x7654, growth, 0x5678];
                RESULT = address as *mut u8;
                element_array3_expand(header.as_mut_ptr());
                let count = old * growth;
                assert_eq!(header, [address as u32, count, 1, 0x7654, growth, 0x5678]);
                assert_eq!(REQUEST, (0x1234 as *mut u8, count as usize * 4));
                for (index, word) in words.iter().enumerate() {
                    assert_eq!(*word, if index >= old as usize && index < count as usize { 0 } else { 0xdead_beef });
                }
            }
            HEAP_OPS = saved;
        }
    }

    #[test]
    fn failure_discards_storage_but_preserves_capacity_with_wrapped_byte_counts() {
        let _lock = lock_ops();
        unsafe {
            let saved = HEAP_OPS;
            HEAP_OPS.realloc = resize;
            HEAP_OPS.free = release;
            RESULT = core::ptr::null_mut();
            for (old, growth, bytes) in [(0, 3, 0), (2, 3, 24), (7, 0, 0), (0x4000_0001, 4, 16), (u32::MAX, 2, 0xffff_fff8)] {
                let mut header = [0x1234, old, 7, 8, growth, 9];
                element_array3_expand(header.as_mut_ptr());
                assert_eq!(header, [0, old, 7, 8, growth, 9]);
                assert_eq!(REQUEST, (0x1234 as *mut u8, bytes));
            }
            HEAP_OPS = saved;
        }
    }
}
