//! `element_tracker_array_expand` — `FUN_083d533c` @ **0x083d533c**.
//! True code size: 120 bytes (`0x083d533c..0x083d53b4`); occupied extent
//! through the next real function at 0x083d53f0 includes 60 bytes of strings.
//! Raw ARM decoding: one inbound BLEQ, zero inbound plain BLs; three outbound
//! plain BLs (realloc 0x0802edec, zero-fill veneer 0x08037db8, diagnostic
//! 0x083d52a0), zero outbound predicated BLs.
//! Multiply allocated slots by the growth factor with wrapping u32 arithmetic,
//! publish realloc's result even on failure, clear the grown tail, and commit
//! the count only on success. Header words retain the target's four-byte stride.
//! Deliberate deviation: omit the diagnostic call and its argument preparation;
//! raw 0x083d52a0 is exactly bx lr, with no memory effects or consumed result.

const STORAGE: usize = 0;
const ALLOCATED: usize = 1;
const GROWTH_FACTOR: usize = 4;

unsafe fn expand_with_realloc(
    array: *mut u32,
    reallocate: unsafe extern "C" fn(*mut u8, usize) -> *mut u8,
) {
    let expanded = (*array.add(GROWTH_FACTOR)).wrapping_mul(*array.add(ALLOCATED));
    let storage = reallocate(*array.add(STORAGE) as *mut u8, expanded.wrapping_mul(4) as usize);
    *array.add(STORAGE) = storage as u32;
    if !storage.is_null() {
        let allocated = *array.add(ALLOCATED);
        let zero = core::ptr::read_volatile(
            &(crate::libc::memzero::memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
        );
        let _ = zero(
            (storage as usize).wrapping_add(allocated.wrapping_mul(4) as usize) as *mut u8,
            expanded.wrapping_sub(allocated).wrapping_mul(4) as usize,
        );
        *array.add(ALLOCATED) = expanded;
    }
}

/// Expands an element tracker table, preserving the original failure state.
/// The header and successful allocation must be valid for all wrapped byte ranges.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_tracker_array_expand(array: *mut u32) {
    let reallocate = core::ptr::read_volatile(
        &(crate::runtime::malloc_rt::realloc as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
    );
    expand_with_realloc(array, reallocate);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static BACKING: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ELEMENT_TRACKER_ARRAY_EXPAND, 0x1000).map(|p| p as usize)
    });
    static mut RESULT: *mut u8 = core::ptr::null_mut();
    static mut ARGUMENTS: (*mut u8, usize) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn allocate(storage: *mut u8, bytes: usize) -> *mut u8 {
        ARGUMENTS = (storage, bytes);
        RESULT
    }

    #[test]
    fn growth_preserves_prefix_and_header_and_clears_only_tail() {
        let _lock = LOCK.lock();
        let Some(address) = *BACKING else { return };
        unsafe {
            let storage = address as *mut u32;
            for (old, factor) in [(0u32, 3u32), (2, 1), (2, 3), (7, 2)] {
                let words = core::slice::from_raw_parts_mut(storage, 16);
                words.fill(0xdead_beef);
                let mut header = [address as u32, old, 1, 0x1234, factor, 0x5678];
                RESULT = storage.cast();
                expand_with_realloc(header.as_mut_ptr(), allocate);
                let count = old * factor;
                assert_eq!(header, [address as u32, count, 1, 0x1234, factor, 0x5678]);
                for i in 0..16 {
                    assert_eq!(words[i], if i >= old as usize && i < count as usize { 0 } else { 0xdead_beef });
                }
            }
        }
    }

    #[test]
    fn failure_publishes_null_and_preserves_count_including_wrapped_sizes() {
        let _lock = LOCK.lock();
        unsafe {
            for (old, factor, bytes) in [(2, 3, 24), (0x4000_0001, 4, 16), (u32::MAX, 2, 0xffff_fff8)] {
                let mut header = [0x1234, old, 7, 8, factor, 9];
                RESULT = core::ptr::null_mut();
                expand_with_realloc(header.as_mut_ptr(), allocate);
                assert_eq!(header, [0, old, 7, 8, factor, 9]);
                assert_eq!(ARGUMENTS, (0x1234 as *mut u8, bytes));
            }
        }
    }
}
