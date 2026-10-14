//! `pointer_tracker_expand` — `FUN_083d4714` @ **0x083d4714**.
//! True code size: 120 bytes [0x083d4714,0x083d478c); occupied extent
//! is 180 bytes through the next function at 0x083d47c8, including strings.
//! Raw word scan: zero inbound plain BLs, one BLEQ at 0x083d46c4;
//! three outbound plain BLs (0x083d4730, 0x083d4750, 0x083d4784),
//! zero outbound predicated BLs. Multiply capacity by the growth factor,
//! publish realloc's result even on failure, clear only added word slots,
//! and commit capacity only on success. Reuse the identical tracker algorithm,
//! ported realloc at 0x0802edec and memzero_aligned via 0x08037db8.
//! Deliberate deviation: omit diagnostic arguments and the call to
//! 0x083d4678, whose raw body is exactly bx lr with no consumed return.
//! Header fields retain four-byte strides on hosts. LLVM folds this export
//! into `.text.element_array6_expand` (96 bytes, including literals).
//! match.py on that canonical symbol retains multiply, pointer publication,
//! failure branch, tail clear and capacity commit; helper calls use BLX.

use super::element_tracker_array_expand::expand_with_realloc;

/// Expand a pointer-slot tracker using its multiplicative growth factor.
///
/// # Safety
/// Header must be aligned and writable for six u32 words; its storage and
/// successful allocation must be valid for the wrapped byte ranges.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pointer_tracker_expand(array: *mut u32) {
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
        try_map_u32_slab(hints::POINTER_TRACKER_EXPAND, 0x1000).map(|p| p as usize)
    });
    static mut RESULT: *mut u8 = core::ptr::null_mut();
    static mut REQUEST: (*mut u8, usize) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn resize(storage: *mut u8, bytes: usize) -> *mut u8 {
        REQUEST = (storage, bytes);
        RESULT
    }

    #[test]
    fn success_clears_only_new_slots_and_preserves_tracker_metadata() {
        let _lock = LOCK.lock();
        let Some(address) = *BACKING else { return };
        unsafe {
            let words = core::slice::from_raw_parts_mut(address as *mut u32, 16);
            for (old, growth) in [(0u32, 3u32), (2, 1), (3, 4)] {
                words.fill(0xdead_beef);
                let mut header = [0x1234, old, 2, 0x7654, growth, 0x5678];
                RESULT = address as *mut u8;
                expand_with_realloc(header.as_mut_ptr(), resize);
                let count = old * growth;
                assert_eq!(header, [address as u32, count, 2, 0x7654, growth, 0x5678]);
                for (index, value) in words.iter().enumerate() {
                    assert_eq!(*value, if index >= old as usize && index < count as usize { 0 } else { 0xdead_beef });
                }
            }
        }
    }

    #[test]
    fn failure_publishes_null_without_committing_wrapped_capacity() {
        let _lock = LOCK.lock();
        unsafe {
            RESULT = core::ptr::null_mut();
            for (old, growth, bytes) in [(2, 3, 24), (0x4000_0001, 4, 16), (u32::MAX, 2, 0xffff_fff8)] {
                let mut header = [0x1234, old, 7, 8, growth, 9];
                expand_with_realloc(header.as_mut_ptr(), resize);
                assert_eq!(header, [0, old, 7, 8, growth, 9]);
                assert_eq!(REQUEST, (0x1234 as *mut u8, bytes));
            }
        }
    }

}
