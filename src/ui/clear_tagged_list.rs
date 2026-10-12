//! Clear a tagged link source — FUN_080488d4 @ 0x080488d4.
//!
//! True extent: 192 bytes through 0x08048994 (188 instruction bytes and
//! event literal 0x64696564 at 0x08048990). Next body begins with PUSH.
//! Raw aligned BL decoding: two inbound plain BLs, zero predicated;
//! nine outbound plain BLs and one BLNE. Validate the source and reject
//! active dispatch (+8). Notify 'died', increment the embedded list's busy
//! counter, scan one-based records with a freshly loaded unsigned length,
//! and remove this source from each valid target's reciprocal list. Then
//! decrement busy, destroy embedded storage, and zero exactly 52 bytes.
//!
//! Deliberate deviations: existing Rust ports replace their stock calls;
//! three verified unported routines use injectable firmware boundaries.
//! Hosts retain IndexedObject's native storage slot; record pointers remain
//! u32 firmware words. No algorithmic deviations.

use core::ptr;
use super::object_state::{indexed_object_element, IndexedObject};
use super::tagged_object_link::{TaggedLinkSource, TaggedLinkTarget};
use super::tagged_link_source_is_valid::tagged_link_source_is_valid;
use super::tagged_link_target_is_valid::tagged_link_target_is_valid;
use crate::util::object_counter_increment::object_counter_increment;
use crate::util::positive_counter_decrement::positive_counter_decrement;
use crate::util::dynamic_array_remove::dynamic_array_remove;
use crate::libc::bzero::bzero;

type Notify = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32);
type FindSource = unsafe extern "C" fn(*mut TaggedLinkTarget, *mut TaggedLinkSource) -> u32;
type DestroyStorage = unsafe extern "C" fn(*mut u8) -> u32;
type Remove = unsafe extern "C" fn(*mut u32, u32, u32) -> u32;

#[derive(Clone, Copy)]
pub struct ClearTaggedListOps {
    pub notify: Notify,
    pub find_source: FindSource,
    pub destroy_storage: DestroyStorage,
}

unsafe extern "C" fn retail_notify(list: *mut u8, tag: u32, context: *mut u8, payload: u32, extra: u32) {
    #[cfg(target_os = "none")]
    { let call: Notify = core::mem::transmute(0x0806_6bb8usize); call(list, tag, context, payload, extra); }
    #[cfg(not(target_os = "none"))]
    { let _ = (list, tag, context, payload, extra); panic!("install tagged list notification boundary"); }
}
unsafe extern "C" fn retail_find_source(target: *mut TaggedLinkTarget, source: *mut TaggedLinkSource) -> u32 {
    #[cfg(target_os = "none")]
    { let call: FindSource = core::mem::transmute(0x080e_2dc8usize); call(target, source) }
    #[cfg(not(target_os = "none"))]
    { let _ = (target, source); panic!("install reciprocal source lookup boundary"); }
}
unsafe extern "C" fn retail_destroy_storage(list: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    { let call: DestroyStorage = core::mem::transmute(0x0804_8230usize); call(list) }
    #[cfg(not(target_os = "none"))]
    { let _ = list; panic!("install embedded storage destruction boundary"); }
}

pub const DEFAULT_CLEAR_TAGGED_LIST_OPS: ClearTaggedListOps = ClearTaggedListOps {
    notify: retail_notify, find_source: retail_find_source, destroy_storage: retail_destroy_storage,
};
pub static mut CLEAR_TAGGED_LIST_OPS: ClearTaggedListOps = DEFAULT_CLEAR_TAGGED_LIST_OPS;

/// # Safety
/// Null is accepted. Non-null sources must be aligned and readable; matching,
/// inactive sources must be writable for 52 bytes and own valid indexed list
/// storage. Non-null record pointer words must reference complete targets.
/// Firmware boundaries must be available or installed by the host caller.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clear_tagged_list(source: *mut u8) {
    clear_with(source, ptr::read_volatile(ptr::addr_of!(CLEAR_TAGGED_LIST_OPS)), dynamic_array_remove);
}

unsafe fn clear_with(source: *mut u8, ops: ClearTaggedListOps, remove: Remove) {
    if tagged_link_source_is_valid(source.cast()) == 0 || source.cast::<u32>().add(2).read() != 0 { return; }
    (ops.notify)(source, 0x6469_6564, source, 0, 0);
    let list = source.add(16);
    object_counter_increment(list);
    let mut index = 1u32;
    while index <= list.cast::<u32>().add(2).read_volatile() {
        let record = indexed_object_element(list.cast::<IndexedObject>(), index).cast::<u32>();
        if !record.is_null() {
            let target = record.read() as usize as *mut TaggedLinkTarget;
            if tagged_link_target_is_valid(target) != 0 {
                let reciprocal = (ops.find_source)(target, source.cast());
                if reciprocal != 0 {
                    // BLNE consumes the successful lookup result in r2.
                    remove(target.cast::<u32>().add(3), 1, reciprocal);
                }
            }
        }
        index = index.wrapping_add(1);
    }
    positive_counter_decrement(list);
    (ops.destroy_storage)(list);
    bzero(source, 52);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::object_state::INDEXED_OBJECT_TAG;
    use super::super::tagged_object_link::{LINK_SOURCE_TAG, LINK_TARGET_TAG};

    unsafe extern "C" fn notify(source: *mut u8, tag: u32, context: *mut u8, payload: u32, extra: u32) {
        assert_eq!((tag, context, payload, extra), (0x6469_6564, source, 0, 0));
        // Notification may change the list before iteration begins.
        source.cast::<u32>().add(6).write(4);
    }
    unsafe extern "C" fn find(target: *mut TaggedLinkTarget, source: *mut TaggedLinkSource) -> u32 {
        assert_eq!(source.cast::<u32>().add(9).read(), 1);
        target.cast::<u32>().add(1).read()
    }
    unsafe extern "C" fn remove(list: *mut u32, count: u32, index: u32) -> u32 {
        assert_eq!(count, 1);
        assert_eq!(index, 7);
        list.add(2).write(list.add(2).read() - count);
        0
    }
    unsafe extern "C" fn destroy(list: *mut u8) -> u32 {
        assert_eq!(list.cast::<u32>().add(5).read(), 0);
        bzero(list, 36);
        0
    }
    unsafe extern "C" fn forbidden_notify(_: *mut u8, _: u32, _: *mut u8, _: u32, _: u32) { panic!("rejected source dispatched"); }

    #[test]
    fn rejects_null_foreign_and_dispatching_sources_without_mutation() {
        let ops = ClearTaggedListOps { notify: forbidden_notify, find_source: find, destroy_storage: destroy };
        unsafe { clear_with(ptr::null_mut(), ops, remove); }
        for (tag, busy) in [(0, 0), (LINK_SOURCE_TAG, 1), (LINK_SOURCE_TAG, u32::MAX)] {
            let mut source = [0x5555_5555u32; 14];
            source[0] = tag; source[2] = busy;
            let before = source;
            unsafe { clear_with(source.as_mut_ptr().cast(), ops, remove); }
            assert_eq!(source, before);
        }
    }

    #[test]
    fn removes_only_valid_reciprocals_and_preserves_bytes_after_extent() {
        unsafe {
            let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::CLEAR_TAGGED_LIST, 4096) else { return; };
            let targets = slab.cast::<u32>();
            for i in 0..4 {
                let target = targets.add(i * 16);
                ptr::write_bytes(target, 0, 16);
                target.write(if i == 1 { 0 } else { LINK_TARGET_TAG });
                target.add(1).write(if i == 2 { 0 } else { 7 });
                target.add(5).write(3);
                target.add(12).write(1);
            }
            let mut records = [0u32; 4];
            for i in 0..4 { records[i] = targets.add(i * 16) as usize as u32; }
            let mut base = records.as_mut_ptr().cast::<u8>();
            let mut source = [0xaaaa_aaaau32; 14];
            source[0] = LINK_SOURCE_TAG; source[2] = 0;
            ptr::write(source.as_mut_ptr().add(4).cast::<IndexedObject>(), IndexedObject {
                type_tag: INDEXED_OBJECT_TAG, element_size: 4, element_count: 0,
                reserved: [0; 2], storage_ready: 0, storage_pointer_slot: &mut base,
            });
            let ops = ClearTaggedListOps { notify, find_source: find, destroy_storage: destroy };
            clear_with(source.as_mut_ptr().cast(), ops, remove);
            assert_eq!(&source[..13], &[0; 13]);
            assert_eq!(source[13], 0xaaaa_aaaa);
            assert_eq!((targets.add(5).read(), targets.add(21).read(), targets.add(37).read(), targets.add(53).read()), (2, 3, 3, 2));
        }
    }
}
