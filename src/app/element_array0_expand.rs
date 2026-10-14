//! `element_array0_expand` — `FUN_083d3d88` @ **0x083d3d88**.
//! True code size: 120 bytes (`0x083d3d88..0x083d3e00`); occupied extent
//! is 180 bytes through the next function at 0x083d3e3c, including strings.
//! Raw A32 scan: zero inbound plain BLs, one inbound BLEQ at 0x083d3d38;
//! three outbound plain BLs at 0x083d3da4 (realloc 0x0802edec),
//! 0x083d3dc4 (zero-fill veneer 0x08037db8), and 0x083d3df8 (diagnostic
//! 0x083d3cec), zero outbound predicated BLs. Multiply capacity by growth
//! modulo 2^32, publish realloc's result including NULL, clear the added
//! tail on success, then commit capacity. Failure preserves capacity.
//! Reuse the identical tracker algorithm with four-byte header words.
//! Deliberate deviation: omit diagnostic arguments and the call to the
//! verified bx-lr no-op at 0x083d3cec; its returned r0 is not consumed.
//! LLVM may fold this identical body with other tracker expansion exports.

use super::element_tracker_array_expand::expand_with_realloc;

/// Grow the element-array-0 tracker, preserving failure mutations.
///
/// # Safety
/// Header must be aligned and writable for six u32 words. Its storage word
/// and successful allocation must be valid for the wrapped byte ranges.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_array0_expand(array: *mut u32) {
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
        try_map_u32_slab(hints::ELEMENT_ARRAY0_EXPAND, 0x1000).map(|p| p as usize)
    });
    static mut RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn resize(_storage: *mut u8, _bytes: usize) -> *mut u8 {
        RESULT
    }

    unsafe extern "C" fn release(_storage: *mut u8) {}

    #[test]
    fn growth_preserves_existing_slots_and_clears_only_tail() {
        let _lock = lock_ops();
        let Some(address) = *BACKING else {
            crate::testing::note_missing_u32_fixture("app/element_array0_expand");
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
                element_array0_expand(header.as_mut_ptr());
                let count = old * growth;
                assert_eq!(header, [address as u32, count, 1, 0x7654, growth, 0x5678]);
                for (index, word) in words.iter().enumerate() {
                    assert_eq!(*word, if index >= old as usize && index < count as usize { 0 } else { 0xdead_beef });
                }
            }
            HEAP_OPS = saved;
        }
    }

    #[test]
    fn allocation_failure_loses_storage_but_preserves_capacity_and_metadata() {
        let _lock = lock_ops();
        unsafe {
            let saved = HEAP_OPS;
            HEAP_OPS.realloc = resize;
            RESULT = core::ptr::null_mut();
            HEAP_OPS.free = release;
            for (old, growth) in [(0, 3), (2, 3), (0x4000_0001, 4), (u32::MAX, 2), (7, 0)] {
                let mut header = [0x1234, old, 7, 8, growth, 9];
                element_array0_expand(header.as_mut_ptr());
                assert_eq!(header, [0, old, 7, 8, growth, 9]);
            }
            HEAP_OPS = saved;
        }
    }
}
