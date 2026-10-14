//! `element_array1_expand` — `FUN_083d4250` @ **0x083d4250**.
//! True code size: 120 bytes (`0x083d4250..0x083d42c8`); occupied extent
//! is 180 bytes through the next function at 0x083d4304, including strings.
//! Raw A32 scan: zero inbound plain BLs, one inbound BLEQ at 0x083d4200;
//! three outbound plain BLs at 0x083d426c, 0x083d428c, and 0x083d42c0,
//! zero outbound predicated BLs. Multiply capacity by growth modulo 2^32,
//! publish realloc's result including NULL, clear the added tail on success,
//! then commit capacity. Failure preserves capacity and other header words.
//! Reuse the identical tracker algorithm and ported realloc (0x0802edec)
//! and memzero_aligned (0x0800027c via the 0x08037db8 IRAM veneer).
//! Deliberate deviation: omit diagnostic arguments and the call to
//! 0x083d41b4, whose sole word is bx lr with no consumed return value.
//! Header fields retain four-byte strides on hosts. LLVM may fold this
//! identical body with other tracker expansion exports.

use super::element_tracker_array_expand::expand_with_realloc;

/// Grow an element-array-1 tracker, preserving the original failure mutations.
///
/// # Safety
/// Header must be aligned and writable for six u32 words. Its storage word
/// and successful allocation must be valid for the wrapped byte ranges.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_array1_expand(array: *mut u32) {
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
        try_map_u32_slab(hints::ELEMENT_ARRAY1_EXPAND, 0x1000).map(|p| p as usize)
    });
    static mut RESULT: *mut u8 = core::ptr::null_mut();
    static mut REQUEST: (*mut u8, usize) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn resize(storage: *mut u8, bytes: usize) -> *mut u8 {
        REQUEST = (storage, bytes);
        RESULT
    }

    #[test]
    fn exported_growth_preserves_prefix_and_clears_only_added_slots() {
        let _lock = lock_ops();
        let Some(address) = *BACKING else {
            crate::testing::note_missing_u32_fixture("app/element_array1_expand");
            return;
        };
        unsafe {
            let saved = HEAP_OPS;
            HEAP_OPS.realloc = resize;
            for (old, growth) in [(2u32, 1u32), (2, 3), (7, 2)] {
                let words = core::slice::from_raw_parts_mut(address as *mut u32, 20);
                words.fill(0xdead_beef);
                let mut header = [0x1234, old, 1, 0x7654, growth, 0x5678];
                RESULT = address as *mut u8;
                element_array1_expand(header.as_mut_ptr());
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
    fn exported_failure_publishes_null_without_committing_wrapped_capacity() {
        let _lock = lock_ops();
        unsafe {
            let saved = HEAP_OPS;
            HEAP_OPS.realloc = resize;
            RESULT = core::ptr::null_mut();
            for (old, growth, bytes) in [(2, 3, 24), (0x4000_0001, 4, 16), (u32::MAX, 2, 0xffff_fff8)] {
                let mut header = [0x1234, old, 7, 8, growth, 9];
                element_array1_expand(header.as_mut_ptr());
                assert_eq!(header, [0, old, 7, 8, growth, 9]);
                assert_eq!(REQUEST, (0x1234 as *mut u8, bytes));
            }
            HEAP_OPS = saved;
        }
    }
}
