//! `element_array6_expand` — `FUN_083d4994` @ **0x083d4994**.
//! Code size: 120 bytes (`0x083d4994..0x083d4a0c`); true occupied extent
//! is 180 bytes through the next function at 0x083d4a48, including strings.
//! Independent raw-word scan: zero inbound plain BLs, one inbound BLEQ at
//! 0x083d4944; three outbound plain BLs, zero outbound predicated BLs.
//! Multiply capacity by growth with wrapping u32 arithmetic, publish realloc's
//! result even on failure, clear only the added slots, then commit capacity.
//! Reuse the identical element-tracker expansion algorithm and ported realloc
//! (0x0802edec) and memzero_aligned (0x0800027c via IRAM veneer 0x08037db8).
//! Deliberate deviation: omit diagnostic argument preparation and its call to
//! 0x083d48f8, verified as exactly bx lr. Headers always use four-byte words,
//! including on hosts; host insertion fixtures retain their pointer-width adapter.
//! Exported-entry host smoke used an mmap-backed moving allocator: preserved
//! two original slots, zeroed exactly four added slots, and committed capacity.

use super::element_tracker_array_expand::expand_with_realloc;

/// Grow a six-word element-array header, preserving failure mutations.
///
/// # Safety
/// Header must be aligned and writable for six u32 words. Its storage word
/// and successful allocation must be valid for the wrapped byte ranges.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_array6_expand(array: *mut u32) {
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
        try_map_u32_slab(hints::ELEMENT_ARRAY6_EXPAND, 0x1000).map(|p| p as usize)
    });
    static mut RESULT: *mut u8 = core::ptr::null_mut();
    static mut REQUEST: (*mut u8, usize) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn resize(storage: *mut u8, bytes: usize) -> *mut u8 {
        REQUEST = (storage, bytes);
        RESULT
    }

    #[test]
    fn moved_storage_preserves_prefix_and_clears_exact_tail() {
        let _lock = LOCK.lock();
        let Some(address) = *BACKING else { return };
        unsafe {
            let words = core::slice::from_raw_parts_mut(address as *mut u32, 20);
            for (old, growth) in [(0u32, 3u32), (2, 1), (2, 3), (7, 2)] {
                words.fill(0xdead_beef);
                let mut header = [0x1234, old, 1, 0x7654, growth, 0x5678];
                RESULT = address as *mut u8;
                expand_with_realloc(header.as_mut_ptr(), resize);
                let count = old * growth;
                assert_eq!(header, [address as u32, count, 1, 0x7654, growth, 0x5678]);
                for (index, value) in words.iter().enumerate() {
                    assert_eq!(*value, if index >= old as usize && index < count as usize { 0 } else { 0xdead_beef });
                }
            }
        }
    }

    #[test]
    fn allocation_failure_loses_storage_but_preserves_other_header_words() {
        let _lock = LOCK.lock();
        unsafe {
            for (old, growth, bytes) in [(2, 3, 24), (0, 2, 0), (0x4000_0001, 4, 16), (u32::MAX, 2, 0xffff_fff8)] {
                let mut header = [0x1234, old, 7, 8, growth, 9];
                RESULT = core::ptr::null_mut();
                expand_with_realloc(header.as_mut_ptr(), resize);
                assert_eq!(header, [0, old, 7, 8, growth, 9]);
                assert_eq!(REQUEST, (0x1234 as *mut u8, bytes));
            }
        }
    }
}
