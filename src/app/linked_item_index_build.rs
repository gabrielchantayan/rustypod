//! Lazy linked-item pointer index — `FUN_0809d98c` @ `0x0809d98c`.
//! True extent: 176 bytes, ending at the distinct CMP entry at 0x0809da3c.
//! Raw A32: two outgoing plain BLs, zero predicated BLs; two incoming plain
//! BLs (0x08050db0, 0x08055668), zero predicated BLs.
//!
//! Reuses an existing +0x900 cache. Otherwise allocates count*4+16 bytes,
//! leaves header word zero untouched, stores byte size and count in words
//! one and two, and copies list pointers into word three onward. The extra
//! allocated word allows detecting one excess node without overrunning.
//! A short or long list frees the allocation and returns -50; allocation
//! failure returns -108. Success publishes the index and returns zero.
//! Deliberate deviations: existing Rust heap dispatch replaces direct calls;
//! target-width pointer words and wrapping size arithmetic are retained on
//! hosts. No additional validation or list traversal is introduced.

use crate::heap::veneers::{malloc_tag4, free_tag4};

/// # Safety
/// `collection` has the retail word layout through +0x900; list nodes have a
/// valid next-pointer word at +4. Allocation and list sizes must permit the
/// original accesses, including one excess pointer on a count mismatch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_item_index_build(collection: *mut u32) -> i32 {
    let cache = collection.add(0x900 / 4);
    if cache.read() != 0 { return 0; }
    let expected = collection.add(9).read();
    let size = expected.wrapping_mul(4).wrapping_add(16);
    let mut index = malloc_tag4(size as usize).cast::<u32>();
    let mut status = 0;
    if index.is_null() {
        status = -108;
    } else {
        index.add(2).write(0);
        index.add(1).write(size);
        let mut node = collection.add(10).read();
        let mut count = 0_u32;
        while node != 0 {
            index.add(3 + count as usize).write(node);
            count = count.wrapping_add(1);
            index.add(2).write(count);
            if count > collection.add(9).read() { break; }
            node = (node as usize as *const u32).add(1).read();
        }
        if count != collection.add(9).read() {
            status = -50;
            free_tag4(index.cast());
            index = core::ptr::null_mut();
        }
    }
    cache.write(index as usize as u32);
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, alloc_log, free_log};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};

    #[test]
    fn cache_success_failure_and_list_count_boundaries() {
        let _heap = mock_heap();
        let Some(slab) = try_map_u32_slab(hints::LINKED_ITEM_INDEX_BUILD, 0x2000) else {
            note_missing_u32_fixture("linked_item_index_build");
            return;
        };
        unsafe {
            let index = slab.cast::<u32>();
            let first = slab.add(0x100).cast::<u32>();
            let second = slab.add(0x120).cast::<u32>();
            first.add(1).write(second as usize as u32);
            second.add(1).write(0);
            let mut collection = [0_u32; 577];
            collection[9] = 2;
            collection[10] = first as usize as u32;
            index.write(0xdeadbeef);
            index.add(5).write(0xaabbccdd);
            set_alloc_ret(slab);
            assert_eq!(linked_item_index_build(collection.as_mut_ptr()), 0);
            assert_eq!(collection[576], index as usize as u32);
            assert_eq!(core::slice::from_raw_parts(index, 6),
                &[0xdeadbeef, 24, 2, first as usize as u32, second as usize as u32, 0xaabbccdd]);
            assert_eq!(alloc_log(), (1, 24, 4));
            assert_eq!(free_log().0, 0);
            // Existing cache must not traverse even an invalid list pointer.
            collection[10] = 1;
            assert_eq!(linked_item_index_build(collection.as_mut_ptr()), 0);
            assert_eq!(alloc_log().0, 1);
            assert_eq!(collection[576], index as usize as u32);
            collection[576] = 0;
            set_alloc_ret(core::ptr::null_mut());
            assert_eq!(linked_item_index_build(collection.as_mut_ptr()), -108);
            assert_eq!(collection[576], 0);
            assert_eq!(free_log().0, 0);
            set_alloc_ret(slab);
            // Empty, short, exact, excess, and cyclic lists; excess detection
            // must stop before reading the excess node's next pointer.
            for (expected, head, next, result, copied) in [
                (0, 0, 0, 0, 0),
                (2, 0, 0, -50, 0),
                (2, first as usize as u32, 0, -50, 1),
                (1, first as usize as u32, 0, 0, 1),
                (0, first as usize as u32, 1, -50, 1),
                (1, first as usize as u32, first as usize as u32, -50, 2),
            ] {
                collection[576] = 0;
                collection[9] = expected;
                collection[10] = head;
                first.add(1).write(next);
                let frees = free_log().0;
                assert_eq!(linked_item_index_build(collection.as_mut_ptr()), result);
                assert_eq!(index.add(2).read(), copied);
                assert_eq!(index.add(1).read(), expected * 4 + 16);
                assert_eq!(collection[576], if result == 0 { index as usize as u32 } else { 0 });
                assert_eq!(free_log().0, frees + usize::from(result != 0));
                if result != 0 { assert_eq!(free_log().1, slab); assert_eq!(free_log().2, 4); }
            }
        }
    }
}
