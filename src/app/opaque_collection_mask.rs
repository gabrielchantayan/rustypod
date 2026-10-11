//! Recursive opaque collection mask — `FUN_08054b0c` @ `0x08054b0c`.
//! True extent: 152 bytes, ending at the next entry prologue at `0x08054ba4`.
//! Raw aligned ARM decoding verifies two inbound plain BLs (0x08054b68,
//! 0x0806792c), six outgoing plain BLs, and zero predicated BLs.
//!
//! Retain the collection; on failure return zero without releasing. Snapshot
//! its entry count, copy entries until exhausted or a copy fails, and OR the
//! 64-bit masks of leaf tags or recursively visited child collections. Release
//! once after successful retain, including early copy failure; ignore release
//! status. No cycle detection is added.
//!
//! Deviations: reuse existing Rust object/entry ports. The unported leaf-tag
//! mapper remains a stock ARM call at 0x08057958; hosts use its raw-verified
//! mapping as a reference backend. Pointer fields stay target-width u32.

use crate::app::opaque_collection_copy_entry::opaque_collection_copy_entry;
use crate::cxx::magic_tagged_object_entry_count::magic_tagged_object_entry_count;
use crate::cxx::magic_tagged_object_retain::magic_tagged_object_retain;
use crate::cxx::magic_tagged_object_release::magic_tagged_object_release;

#[cfg(target_os = "none")]
unsafe fn leaf_tag_mask(tag: u32) -> u64 {
    let mapper: unsafe extern "C" fn(u32) -> u64 = unsafe { core::mem::transmute(0x08057958usize) };
    unsafe { mapper(tag) }
}

// Reference for the still-stock mapper: its branch table and r0/r1 return
// paths were decoded from osos.dec, not inferred from tag names.
#[cfg(not(target_os = "none"))]
fn leaf_tag_mask(tag: u32) -> u64 {
    match tag {
        1 => 0x100000,
        2..=13 => 1u64 << (tag - 2),
        14 => 0x80000, 15 => 0x20000, 16 => 0x2000000,
        17 => 0x200000, 18 => 0x4000000, 19 => 0x8000000,
        20 => 0x10000000, 21 => 0x40000, 22 => 0x20000000,
        23 => 0x40000000, 24 => 1u64 << 32, 25 => 2u64 << 32,
        29 => 0x40u64 << 32, 31 => 0x80000000,
        34 => 0x80u64 << 32, 35 => 0x100u64 << 32,
        37 => 0x200u64 << 32, 39 => 0x800u64 << 32,
        40 => 0x1000u64 << 32, 54 => 0x2000u64 << 32,
        68 => 0x400000u64 << 32, 69 => 0x800000u64 << 32,
        _ => 0,
    }
}

/// Unions leaf-tag masks throughout a retained opaque collection tree.
///
/// # Safety
/// Every valid collection and child must satisfy the retain/release and entry
/// copy contracts, including writable reference counts and readable entry
/// tables. The child graph must terminate; the original also recurses freely.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_collection_mask(collection: *mut u32) -> u64 {
    if unsafe { magic_tagged_object_retain(collection) } != 0 {
        return 0;
    }
    let count = unsafe { magic_tagged_object_entry_count(collection) };
    let mut mask = 0u64;
    let mut index = 0u32;
    let mut entry = [0u32; 5];
    while index < count {
        if unsafe { opaque_collection_copy_entry(collection, index, entry.as_mut_ptr()) } != 0 {
            break;
        }
        let child_mask = if entry[2] as u8 != 0 {
            unsafe { opaque_collection_mask(entry[3] as usize as *mut u32) }
        } else {
            unsafe { leaf_tag_mask(entry[0]) }
        };
        mask |= child_mask;
        index += 1;
    }
    let _ = unsafe { magic_tagged_object_release(collection) };
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::magic_tagged_object::MAGIC_TAGGED_OBJECT_TAG;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn invalid_and_empty_collections_return_zero_without_unbalanced_references() {
        assert_eq!(unsafe { opaque_collection_mask(core::ptr::null_mut()) }, 0);
        let mut object = [0u32; 32];
        object[2] = 9;
        assert_eq!(unsafe { opaque_collection_mask(object.as_mut_ptr()) }, 0);
        assert_eq!(object[2], 9);
        object[0] = MAGIC_TAGGED_OBJECT_TAG;
        assert_eq!(unsafe { opaque_collection_mask(object.as_mut_ptr()) }, 0);
        assert_eq!(object[2], 9);
    }

    #[test]
    fn recursive_union_preserves_both_words_and_balances_nested_references() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::OPAQUE_COLLECTION_MASK, 0x1000) else {
            assert!(note_missing_u32_fixture("app/opaque_collection_mask"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            let root = slab.cast::<u32>();
            let child = slab.add(0x100).cast::<u32>();
            let entries = slab.add(0x200).cast::<u32>();
            let child_entries = slab.add(0x300).cast::<u32>();
            for (object, table, count) in [(root, entries, 4), (child, child_entries, 3)] {
                object.write(MAGIC_TAGGED_OBJECT_TAG);
                object.add(2).write(7);
                object.add(4).write(count);
                object.add(28).write(table as usize as u32);
            }
            entries.write(2);
            entries.add(5).write(24);
            entries.add(10).write(2); // duplicate: union, not addition
            entries.add(17).write(1); // nonzero byte +8 marks a child
            entries.add(19).write(child as usize as u32);
            child_entries.write(69);
            child_entries.add(5).write(13);
            child_entries.add(10).write(u32::MAX); // unmapped tag
            assert_eq!(opaque_collection_mask(root), 0x0080_0001_0000_0801);
            assert_eq!(root.add(2).read(), 7);
            assert_eq!(child.add(2).read(), 7);

            // Retain wraps MAX to zero; entry copy rejects zero refs, so the
            // traversal stops and release fails without changing that zero.
            // Retain still increments children; rejected release does not
            // undo that increment. Preserve this retail overflow behavior.
            root.add(2).write(u32::MAX);
            assert_eq!(opaque_collection_mask(root), 0);
            assert_eq!(root.add(2).read(), 0);
            assert_eq!(child.add(2).read(), 8);
        }
    }
}
