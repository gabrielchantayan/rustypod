//! Opaque keyed-collection item lookup by identifier.
//!
//! `opaque_keyed_collection_find_item_by_id` — original: `FUN_0829e280` @
//! `0x0829e280` (96 bytes, `0x0829e280..0x0829e2e0`). Raw ARM confirms the
//! next separately entered function begins at `0x0829e2e0`; there is no
//! literal pool:
//!
//! ```text
//! 0829e280  push {r4,r5,r6,r7,r8,lr}
//! 0829e28c  bl   0x0829e310
//! 0829e29c  ldr  r0,[r5]
//! 0829e2a0  ldr  r0,[r0,r4,lsl #2]
//! 0829e2a4  ldr  r1,[r0,#4]
//! 0829e2bc  str  r0,[r7]
//! 0829e2c0  mov  r0,#1
//! 0829e2cc  bl   0x083d78e4
//! ```
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds exactly seven plain,
//! unconditional `bl` call sites — `0x0817eb24`, `0x0817fb80`, `0x0817fe60`,
//! `0x0817fed8`, `0x0817ff60`, `0x08180004`, and `0x08180088` — and no
//! predicated calls. No 32-bit data word in `osos.dec` equals this function's
//! address.
//!
//! # Algorithm
//!
//! The unported selector `FUN_0829e310` receives the collection and selector
//! word, and returns a vector head. Starting at index zero, this function
//! dereferences each vector entry as an opaque item and compares its word at
//! +4 with `item_id`. A match writes the entry pointer to `result` and returns
//! one; exhaustion returns zero without writing `result`. The ARM loop performs
//! its first unchecked entry read before testing the vector size, and
//! sign-extends its 16-bit index after every miss, so it cannot visit index
//! 32768 or higher.
//!
//! # Deliberate deviation
//!
//! `FUN_0829e310` remains unported. This port reuses the existing keyed-vector
//! selector seam from its sibling accessors: target builds call its verified
//! retail address, while host tests install a recording selector. The concrete
//! collection, selector, and item types are not recovered.

use core::ptr;

use super::opaque_keyed_collection_item_at::OPAQUE_KEYED_COLLECTION_VECTOR;
#[cfg(target_os = "none")]
use crate::cxx::templates::{vector_size_elem4_alias_78e4, VectorBounds};

#[cfg(target_os = "none")]
unsafe fn keyed_vector_count(vector: *const super::opaque_keyed_collection_item_at::OpaqueKeyedCollectionVector) -> u32 {
    vector_size_elem4_alias_78e4(vector.cast::<VectorBounds>()) as u32
}

#[cfg(not(target_os = "none"))]
unsafe fn keyed_vector_count(vector: *const super::opaque_keyed_collection_item_at::OpaqueKeyedCollectionVector) -> u32 {
    let begin = ptr::addr_of!((*vector).begin).read_volatile();
    let end = ptr::addr_of!((*vector).end).read_volatile();
    ((end.wrapping_sub(begin) as i32) >> 2) as u32
}


/// opaque_keyed_collection_find_item_by_id — original: `FUN_0829e280` @
/// `0x0829e280` (96 bytes; 7 plain `bl` call sites, no predicated calls;
/// binary-scanned).
///
/// Finds the first selected-vector entry whose aligned target word at +4 equals
/// `item_id`. It preserves the firmware's unchecked first entry read and its
/// signed-16-bit index limit. `result` is written only on a match.
///
/// # Safety
///
/// `collection` and `selector` must be accepted by the installed selector. It
/// must return an aligned vector head whose `begin` and `end` target words
/// describe readable entry pointers; each examined entry must name an aligned,
/// readable two-word item. `result` must be writable when a match occurs.
#[cfg_attr(target_os = "none", link_section = ".text.opaque_keyed_collection_find_item_by_id")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_keyed_collection_find_item_by_id(
    collection: *const u8,
    selector: u32,
    item_id: u32,
    result: *mut u32,
) -> u32 {
    let select = ptr::read_volatile(ptr::addr_of!(OPAQUE_KEYED_COLLECTION_VECTOR));
    let vector = select(collection, selector);
    let mut index = 0i16;

    loop {
        let begin = ptr::addr_of!((*vector).begin).read_volatile();
        let entry = (begin as usize as *const u32)
            .wrapping_add(index as u16 as usize)
            .read_volatile();
        let entry_id = (entry as usize as *const u32).add(1).read_volatile();
        if entry_id == item_id {
            result.write_volatile(entry);
            return 1;
        }

        index = index.wrapping_add(1);
        let count = keyed_vector_count(vector);
        if count <= (index as i32 as u32) {
            return 0;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::opaque_keyed_collection_item_at::{
        OpaqueKeyedCollectionVector, OpaqueKeyedCollectionVectorSelect,
    };
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab,
        OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK,
    };
    use std::sync::LazyLock;

    static FIXTURE_BASE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OPAQUE_KEYED_COLLECTION_FIND_ITEM_BY_ID, 0x40000)
            .map(|p| p as usize)
    });
    static mut CALL: Option<(usize, u32)> = None;
    static mut SELECTED_VECTOR: *const OpaqueKeyedCollectionVector = ptr::null();

    const ENTRIES_WORD: usize = 4;
    const ITEMS_WORD: usize = 33_000;

    unsafe extern "C" fn recording_vector_selector(
        collection: *const u8,
        selector: u32,
    ) -> *const OpaqueKeyedCollectionVector {
        ptr::addr_of_mut!(CALL).write(Some((collection as usize, selector)));
        ptr::read_volatile(ptr::addr_of!(SELECTED_VECTOR))
    }

    struct SeamGuard {
        previous: OpaqueKeyedCollectionVectorSelect,
    }

    impl SeamGuard {
        unsafe fn install(vector: *const OpaqueKeyedCollectionVector) -> Self {
            ptr::addr_of_mut!(SELECTED_VECTOR).write_volatile(vector);
            ptr::addr_of_mut!(CALL).write(None);
            let seam = ptr::addr_of_mut!(OPAQUE_KEYED_COLLECTION_VECTOR);
            let previous = seam.read_volatile();
            seam.write_volatile(recording_vector_selector);
            Self { previous }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(OPAQUE_KEYED_COLLECTION_VECTOR).write_volatile(self.previous);
            }
        }
    }

    fn fixture(entry_count: usize) -> Option<(*mut u32, *mut OpaqueKeyedCollectionVector, *mut u32)> {
        let base = (*FIXTURE_BASE)? as *mut u32;
        unsafe {
            let entries = base.add(ENTRIES_WORD);
            let vector = base as *mut OpaqueKeyedCollectionVector;
            let items = base.add(ITEMS_WORD);
            ptr::addr_of_mut!((*vector).begin).write(entries as usize as u32);
            ptr::addr_of_mut!((*vector).end).write(entries.add(entry_count) as usize as u32);
            Some((entries, vector, items))
        }
    }

    #[test]
    fn finds_first_matching_item_and_forwards_selector() {
        let _lock = OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK.lock();
        let Some((entries, vector, items)) = fixture(3) else {
            assert!(note_missing_u32_fixture("app::opaque_keyed_collection_find_item_by_id"));
            return;
        };
        let collection = [0u32; 4];
        unsafe {
            let mismatch = items;
            let matched = items.add(2);
            mismatch.write(0xaaaa_aaaa);
            mismatch.add(1).write(0x1111_2222);
            matched.write(0xbbbb_bbbb);
            matched.add(1).write(0xfeed_c0de);
            entries.add(0).write(mismatch as usize as u32);
            entries.add(1).write(matched as usize as u32);
            entries.add(2).write(mismatch as usize as u32);
            let _seam = SeamGuard::install(vector);
            let mut result = 0;
            assert_eq!(
                opaque_keyed_collection_find_item_by_id(
                    collection.as_ptr() as *const u8,
                    0x8123_4567,
                    0xfeed_c0de,
                    &mut result,
                ),
                1
            );
            assert_eq!(result, matched as usize as u32);
            assert_eq!(ptr::addr_of!(CALL).read(), Some((collection.as_ptr() as usize, 0x8123_4567)));
        }
    }

    #[test]
    fn misses_without_writing_result() {
        let _lock = OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK.lock();
        let Some((entries, vector, items)) = fixture(1) else {
            assert!(note_missing_u32_fixture("app::opaque_keyed_collection_find_item_by_id"));
            return;
        };
        unsafe {
            items.write(0);
            items.add(1).write(0x1111_2222);
            entries.write(items as usize as u32);
            let _seam = SeamGuard::install(vector);
            let mut result = 0xdead_beef;
            assert_eq!(opaque_keyed_collection_find_item_by_id(ptr::null(), 0, 0x3333_4444, &mut result), 0);
            assert_eq!(result, 0xdead_beef);
        }
    }

    #[test]
    fn examines_index_zero_before_checking_vector_size() {
        let _lock = OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK.lock();
        let Some((entries, vector, items)) = fixture(0) else {
            assert!(note_missing_u32_fixture("app::opaque_keyed_collection_find_item_by_id"));
            return;
        };
        unsafe {
            items.write(0);
            items.add(1).write(0x0bad_f00d);
            entries.write(items as usize as u32);
            let _seam = SeamGuard::install(vector);
            let mut result = 0;
            assert_eq!(opaque_keyed_collection_find_item_by_id(ptr::null(), 1, 0x0bad_f00d, &mut result), 1);
            assert_eq!(result, items as usize as u32);
        }
    }

    #[test]
    fn stops_after_the_signed_sixteen_bit_index_range() {
        let _lock = OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK.lock();
        let Some((entries, vector, items)) = fixture(32_769) else {
            assert!(note_missing_u32_fixture("app::opaque_keyed_collection_find_item_by_id"));
            return;
        };
        unsafe {
            let mismatch = items;
            let unreachable_match = items.add(2);
            mismatch.write(0);
            mismatch.add(1).write(0x1111_2222);
            unreachable_match.write(0);
            unreachable_match.add(1).write(0x7654_3210);
            for index in 0..32_768 {
                entries.add(index).write(mismatch as usize as u32);
            }
            entries.add(32_768).write(unreachable_match as usize as u32);
            let _seam = SeamGuard::install(vector);
            let mut result = 0xa5a5_a5a5;
            assert_eq!(
                opaque_keyed_collection_find_item_by_id(ptr::null(), u32::MAX, 0x7654_3210, &mut result),
                0
            );
            assert_eq!(result, 0xa5a5_a5a5);
        }
    }
}
