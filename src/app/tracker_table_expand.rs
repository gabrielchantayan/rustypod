//! `tracker_table_expand` — `FUN_083d50d8` @ **0x083d50d8**.
//! True code size: 120 bytes (`0x083d50d8..0x083d5150`); the occupied
//! extent ends at the next real function, 0x083d518c, after 60 string bytes.
//! Raw ARM decoding: zero inbound plain BLs, one inbound BLEQ (0x083d5088);
//! three outbound plain BLs (realloc 0x0802edec, zero-fill veneer 0x08037db8,
//! diagnostic 0x083d503c), zero outbound predicated BLs.
//! Multiply capacity by the growth factor with wrapping word arithmetic,
//! publish realloc's result even on failure, clear the added byte range, then
//! commit capacity only on success. Header fields retain four-byte spacing.
//! Deliberate deviations: omit the diagnostic argument preparation and call
//! to the verified single bx lr at 0x083d503c (return value unused); use
//! volatile pointers to the existing allocator and zero-fill ports to retain
//! call boundaries and avoid LLVM builtin substitution.
//! LLVM intentionally folds this export with `element_tracker_array_expand`;
//! both symbols are present in the same ARM archive section. match.py cannot
//! select the alias, so its identical canonical body was reviewed: 22 versus
//! 30 instructions, retaining multiply, unconditional pointer publication,
//! failure branch, wrapped tail clear, and success-only capacity commit.

const STORAGE: usize = 0;
const CAPACITY: usize = 1;
const GROWTH_FACTOR: usize = 4;

unsafe fn expand_with_realloc(
    table: *mut u32,
    reallocate: unsafe extern "C" fn(*mut u8, usize) -> *mut u8,
) {
    let expanded = (*table.add(GROWTH_FACTOR)).wrapping_mul(*table.add(CAPACITY));
    let storage = reallocate(*table.add(STORAGE) as *mut u8, expanded.wrapping_mul(4) as usize);
    *table.add(STORAGE) = storage as u32;
    if !storage.is_null() {
        let capacity = *table.add(CAPACITY);
        let zero = core::ptr::read_volatile(
            &(crate::libc::memzero::memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
        );
        let _ = zero(
            (storage as usize).wrapping_add(capacity.wrapping_mul(4) as usize) as *mut u8,
            expanded.wrapping_sub(capacity).wrapping_mul(4) as usize,
        );
        *table.add(CAPACITY) = expanded;
    }
}

/// Expands tracker slots; the header and successful allocation must be valid
/// for the wrapped byte ranges computed by the original firmware.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tracker_table_expand(table: *mut u32) {
    let reallocate = core::ptr::read_volatile(
        &(crate::runtime::malloc_rt::realloc as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
    );
    expand_with_realloc(table, reallocate);
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
        try_map_u32_slab(hints::TRACKER_TABLE_EXPAND, 0x1000).map(|p| p as usize)
    });
    static mut RESULT: *mut u8 = core::ptr::null_mut();
    static mut ARGUMENTS: (*mut u8, usize) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn allocate(storage: *mut u8, bytes: usize) -> *mut u8 {
        ARGUMENTS = (storage, bytes);
        RESULT
    }

    #[test]
    fn relocated_growth_preserves_prefix_and_clears_only_added_slots() {
        let _lock = LOCK.lock();
        let address = BACKING.expect("target-width tracker fixture");
        unsafe {
            let old_storage = address as *mut u32;
            let storage = old_storage.add(32);
            for (old, factor) in [(0u32, 3u32), (2, 1), (2, 3), (7, 2)] {
                let source = core::slice::from_raw_parts_mut(old_storage, 16);
                source.fill(0x1234_5678);
                let words = core::slice::from_raw_parts_mut(storage, 16);
                words.fill(0xdead_beef);
                words[..old as usize].copy_from_slice(&source[..old as usize]);
                let mut header = [address as u32, old, 1, 0x1234, factor, 0x5678];
                RESULT = storage.cast();
                expand_with_realloc(header.as_mut_ptr(), allocate);
                let count = old * factor;
                assert_eq!(header, [storage as u32, count, 1, 0x1234, factor, 0x5678]);
                assert_eq!(ARGUMENTS, (old_storage.cast(), (count * 4) as usize));
                for i in 0..16 {
                    assert_eq!(words[i], if i < old as usize { 0x1234_5678 } else if i < count as usize { 0 } else { 0xdead_beef });
                }
                assert_eq!(source, [0x1234_5678; 16]);
            }
        }
    }

    #[test]
    fn failure_publishes_null_without_committing_capacity_or_other_fields() {
        let _lock = LOCK.lock();
        unsafe {
            for (old, factor, bytes) in [(2, 3, 24), (2, 0, 0), (0x4000_0001, 4, 16), (u32::MAX, 2, 0xffff_fff8)] {
                let mut header = [0x1234, old, 7, 8, factor, 9];
                RESULT = core::ptr::null_mut();
                expand_with_realloc(header.as_mut_ptr(), allocate);
                assert_eq!(header, [0, old, 7, 8, factor, 9]);
                assert_eq!(ARGUMENTS, (0x1234 as *mut u8, bytes));
            }
        }
    }
}

