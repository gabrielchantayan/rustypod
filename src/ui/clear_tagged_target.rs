//! Clear a tagged link target — FUN_08048804 @ 0x08048804.
//!
//! True size: 208 bytes, [0x08048804, 0x080488d4); next body starts
//! with PUSH. Raw aligned decoding: two inbound plain BLs, no predicated;
//! nine outbound plain BLs, no predicated, plus a tail B to bzero.
//! Validate target, increment embedded list busy, scan one-based source
//! records with freshly loaded unsigned count. For each valid reciprocal,
//! remove its source record when idle, otherwise mark byte +4 deleted.
//! Increment source link_count even if the dispatch accessor returns null.
//! Decrement busy, destroy storage, and zero exactly 56 target bytes.
//!
//! Deliberate deviations: reuse ported callees and the existing injectable
//! storage destruction boundary. Host IndexedObject slots are native pointers;
//! record pointers remain u32 words. No algorithmic deviations.

use core::ptr;
use super::object_state::{indexed_object_element, indexed_object_offset, IndexedObject};
use super::tagged_object_link::{source_contains_target, TaggedLinkSource};
use super::tagged_link_source_is_valid::tagged_link_source_is_valid;
use super::tagged_link_target_is_valid::tagged_link_target_is_valid;
use super::clear_tagged_list::CLEAR_TAGGED_LIST_OPS;
use crate::util::object_counter_increment::object_counter_increment;
use crate::util::positive_counter_decrement::positive_counter_decrement;
use crate::util::dynamic_array_remove::dynamic_array_remove;
use crate::libc::bzero::bzero;

type DestroyStorage = unsafe extern "C" fn(*mut u8) -> u32;

/// # Safety
/// Null is accepted. Matching active targets must own a writable 56-byte
/// object and valid indexed storage. Source record words must point to
/// complete writable source objects with valid reciprocal indexed storage.
/// Storage destruction must be available or installed by the host caller.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clear_tagged_target(target: *mut u8) {
    let ops = ptr::read_volatile(ptr::addr_of!(CLEAR_TAGGED_LIST_OPS));
    clear_with(target, ops.destroy_storage);
}

unsafe fn clear_with(target: *mut u8, destroy: DestroyStorage) {
    if tagged_link_target_is_valid(target.cast()) == 0 { return; }
    let list = target.add(12);
    object_counter_increment(list);
    let mut index = 1u32;
    while index <= list.cast::<u32>().add(2).read_volatile() {
        let record = indexed_object_element(list.cast::<IndexedObject>(), index).cast::<u32>();
        if !record.is_null() {
            let source = record.read() as usize as *mut TaggedLinkSource;
            if tagged_link_source_is_valid(source) != 0 {
                let reciprocal = source_contains_target(source, target.cast());
                if reciprocal != 0 {
                    let source = record.read() as usize as *mut u32;
                    let entries = source.add(4);
                    if source.add(2).read() == 0 {
                        dynamic_array_remove(entries, 1, reciprocal);
                    } else {
                        let entry = indexed_object_offset(entries.cast(), reciprocal);
                        if !entry.is_null() { entry.add(4).write(1); }
                    }
                    // Reload the record after the callee, as stock does.
                    let source = record.read() as usize as *mut u32;
                    source.add(3).write(source.add(3).read().wrapping_add(1));
                }
            }
        }
        index = index.wrapping_add(1);
    }
    positive_counter_decrement(list);
    destroy(list);
    bzero(target, 56);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::object_state::INDEXED_OBJECT_TAG;
    use super::super::tagged_object_link::{LINK_SOURCE_TAG, LINK_TARGET_TAG};

    unsafe extern "C" fn destroy(list: *mut u8) -> u32 {
        assert_eq!(list.cast::<u32>().add(5).read(), 0);
        bzero(list, 36);
        0
    }
    unsafe extern "C" fn forbidden(_: *mut u8) -> u32 { panic!("invalid target reached destruction"); }

    #[test]
    fn rejects_null_wrong_tag_and_inactive_without_mutation() {
        unsafe { clear_with(ptr::null_mut(), forbidden); }
        for (tag, active) in [(0, 1), (LINK_TARGET_TAG, 0)] {
            let mut target = [0xaaaa_aaaau32; 16];
            target[0] = tag; target[12] = active;
            let before = target;
            unsafe { clear_with(target.as_mut_ptr().cast(), forbidden); }
            assert_eq!(target, before);
        }
    }

    #[test]
    fn dispatch_marks_only_reciprocal_records_and_wraps_counter() {
        unsafe {
            let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::CLEAR_TAGGED_TARGET, 4096) else { return; };
            let source = slab.cast::<u32>();
            ptr::write_bytes(source, 0, 64);
            source.write(LINK_SOURCE_TAG); source.add(2).write(1); source.add(3).write(u32::MAX);
            let entries = source.add(32);
            let mut source_base = entries.cast::<u8>();
            source.add(4).cast::<IndexedObject>().write(IndexedObject {
                type_tag: INDEXED_OBJECT_TAG, element_size: 8, element_count: 2,
                reserved: [0; 2], storage_ready: 0, storage_pointer_slot: &mut source_base,
            });
            // Offset target by a word so its +12 host header is aligned.
            let target = source.add(65);
            ptr::write_bytes(target, 0, 16);
            target.write(LINK_TARGET_TAG); target.add(12).write(1);
            entries.write(target as usize as u32); entries.add(1).write(0x1234_5600);
            entries.add(2).write(0); entries.add(3).write(0x9876_5400);
            let mut records = [0u32, source as usize as u32];
            let mut target_base = records.as_mut_ptr().cast::<u8>();
            target.add(3).cast::<IndexedObject>().write(IndexedObject {
                type_tag: INDEXED_OBJECT_TAG, element_size: 4, element_count: 2,
                reserved: [0; 2], storage_ready: 0, storage_pointer_slot: &mut target_base,
            });
            target.add(14).write(0xfeed_beef);
            clear_with(target.cast(), destroy);
            assert_eq!(core::slice::from_raw_parts(target, 14), &[0; 14]);
            assert_eq!(target.add(14).read(), 0xfeed_beef);
            assert_eq!(entries.add(1).read(), 0x1234_5601);
            assert_eq!(entries.add(3).read(), 0x9876_5400);
            assert_eq!(source.add(3).read(), 0);
        }
    }
}
