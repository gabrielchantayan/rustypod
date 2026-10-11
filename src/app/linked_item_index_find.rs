//! Cached item key lookup — `FUN_08055638` @ `0x08055638`.
//! True size: 148 bytes; next real entry begins at 0x080556cc.
//! Whole-image raw A32 decoding: two incoming plain BLs (0x0806e6a4,
//! 0x080b57f0), zero predicated BLs; two outgoing plain BLs, zero predicated.
//!
//! Reject a non-tdat collection or NULL item with zero. Lazily build the
//! collection's +0x900 pointer index, then return the first index whose item
//! key words at +0x114 and +0x110 match; missing cache/key returns -1.
//! Deliberate deviations: call existing Rust class/index-builder ports rather
//! than stock addresses. Preserve four-byte pointer words and the signed
//! comparison against wrapping count-minus-one, including malformed counts.

use crate::app::linked_item_index_build::linked_item_index_build;
use crate::ui::tdat_class_check::ui_element_is_tdat_class;

/// # Safety
/// Non-NULL collection must have an aligned readable class word at +4;
/// accepted collections must be writable through +0x900 and satisfy the
/// index builder's contract. Item and indexed nodes must have readable
/// aligned words through +0x114. Cache entries are target-width pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_item_index_find(collection: *mut u32, item: *const u32) -> i32 {
    if ui_element_is_tdat_class(collection.cast()) == 0 || item.is_null() {
        return 0;
    }
    let cache = collection.add(0x900 / 4);
    if cache.read() == 0 {
        linked_item_index_build(collection);
    }
    let address = cache.read();
    if address == 0 { return -1; }
    let index = address as usize as *const u32;
    let last = index.add(2).read().wrapping_sub(1) as i32;
    let mut position = 0_i32;
    while position <= last {
        let candidate = index.add(3 + position as usize).read() as usize as *const u32;
        let high = candidate.add(0x114 / 4).read();
        let low = candidate.add(0x110 / 4).read();
        if high == item.add(0x114 / 4).read() && low == item.add(0x110 / 4).read() {
            return position;
        }
        position = position.wrapping_add(1);
    }
    -1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};

    #[test]
    fn keys_duplicates_signed_counts_and_lazy_build_failures() {
        let _heap = mock_heap();
        let Some(slab) = try_map_u32_slab(hints::LINKED_ITEM_INDEX_FIND, 0x2000) else {
            note_missing_u32_fixture("linked_item_index_find");
            return;
        };
        unsafe {
            assert_eq!(linked_item_index_find(core::ptr::null_mut(), core::ptr::null()), 0);
            let mut collection = [0_u32; 577];
            let mut item = [0_u32; 70];
            // Invalid class must not touch an invalid item or cache pointer.
            collection[576] = 1;
            assert_eq!(linked_item_index_find(collection.as_mut_ptr(), 1 as *const u32), 0);
            collection[1] = 0x74646174;
            assert_eq!(linked_item_index_find(collection.as_mut_ptr(), core::ptr::null()), 0);
            let index = slab.cast::<u32>();
            let first = slab.add(0x100).cast::<u32>();
            let second = slab.add(0x300).cast::<u32>();
            let third = slab.add(0x500).cast::<u32>();
            item[68] = 0x12345678;
            item[69] = 0xabcdef01;
            for node in [first, second, third] {
                node.add(68).write(item[68]);
                node.add(69).write(item[69]);
            }
            first.add(69).write(0); // Same low word is insufficient.
            second.add(68).write(0); // Same high word is insufficient.
            index.add(3).write(first as usize as u32);
            index.add(4).write(second as usize as u32);
            index.add(5).write(third as usize as u32);
            collection[576] = index as usize as u32;
            index.add(2).write(3);
            assert_eq!(linked_item_index_find(collection.as_mut_ptr(), item.as_ptr()), 2);
            second.add(68).write(item[68]);
            assert_eq!(linked_item_index_find(collection.as_mut_ptr(), item.as_ptr()), 1);
            item[68] = 7;
            assert_eq!(linked_item_index_find(collection.as_mut_ptr(), item.as_ptr()), -1);
            for count in [0, 0x80000001, u32::MAX] {
                index.add(2).write(count);
                index.add(3).write(1); // Signed empty ranges must not read it.
                assert_eq!(linked_item_index_find(collection.as_mut_ptr(), item.as_ptr()), -1);
            }
            item[68] = 0x12345678;
            first.add(69).write(item[69]);
            first.add(1).write(0);
            collection[9] = 1;
            collection[10] = first as usize as u32;
            collection[576] = 0;
            set_alloc_ret(slab);
            assert_eq!(linked_item_index_find(collection.as_mut_ptr(), item.as_ptr()), 0);
            assert_eq!(collection[576], index as usize as u32);
            collection[576] = 0;
            collection[9] = 2; // Short list: builder frees and clears cache.
            assert_eq!(linked_item_index_find(collection.as_mut_ptr(), item.as_ptr()), -1);
            assert_eq!(collection[576], 0);
            set_alloc_ret(core::ptr::null_mut());
            assert_eq!(linked_item_index_find(collection.as_mut_ptr(), item.as_ptr()), -1);
            assert_eq!(collection[576], 0);
        }
    }
}
