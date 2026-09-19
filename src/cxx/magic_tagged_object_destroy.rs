//! **0x0804939c** (140 bytes; two verified inbound plain `bl` sites and two
//! predicated inbound `blne` sites).
//!
//! Raw `osos.dec` establishes the exact extent 0x0804939c..0x08049428; the
//! separately entered function at 0x08049428 follows immediately. The body
//! has four plain `bl` calls (`magic_tagged_object_validate`, `free_tag4`,
//! `bzero`, and `free_tag4`) and one predicated recursive `blne`.
//!
//! # Algorithm
//!
//! Validates the object's magic tag, decrements its nonzero reference count at
//! `+0x04`, and returns unless it became zero. On final release it recursively
//! destroys active children from 0x14-byte entries at `+0x70`, frees that
//! entry table, clears the 0x74-byte tail beginning at `+0x18`, then frees the
//! object with the tag-4 heap veneer.
//!
//! Target pointers remain `u32` words, preserving ARM offsets on 64-bit hosts.
//! Deliberate deviations: Rust uses direct calls for the already-ported
//! validation, zeroing, heap veneer, and recursive target rather than retail
//! branch instructions; Rust does not guarantee the retail tail branch.

use crate::cxx::magic_tagged_object::{magic_tagged_object_validate, MagicTaggedObject};
use crate::heap::veneers::free_tag4;
use crate::libc::bzero::bzero;

const REFCOUNT_WORD: usize = 0x04 / 4;
const CHILD_COUNT_WORD: usize = 0x10 / 4;
const CHILDREN_WORD: usize = 0x70 / 4;
const ENTRY_WORDS: usize = 0x14 / 4;
const ENTRY_ACTIVE_WORD: usize = 0x08 / 4;
const ENTRY_CHILD_WORD: usize = 0x10 / 4;
const CLEAR_OFFSET: usize = 0x18;
const CLEAR_LEN: usize = 0x74;

/// Decrements an opaque object's reference count and destroys its final owner.
///
/// # Safety
///
/// `object` must be readable through its magic and reference-count words. A
/// valid final-release object must be writable through `+0x8b`; a nonzero
/// entry-table word and each active child word must name valid target-layout
/// storage accepted by this function and [`free_tag4`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn magic_tagged_object_destroy(object: *mut u32) {
    if unsafe { magic_tagged_object_validate(object.cast::<MagicTaggedObject>()) } != 0 {
        return;
    }

    let reference_count = unsafe { object.add(REFCOUNT_WORD).read_volatile() };
    if reference_count == 0 {
        return;
    }
    let remaining = reference_count.wrapping_sub(1);
    unsafe { object.add(REFCOUNT_WORD).write_volatile(remaining) };
    if remaining != 0 {
        return;
    }

    let entries = unsafe { object.add(CHILDREN_WORD).read_volatile() } as *mut u32;
    if !entries.is_null() {
        let mut index = 0usize;
        while index < unsafe { object.add(CHILD_COUNT_WORD).read_volatile() } as usize {
            let entry = unsafe { entries.add(index * ENTRY_WORDS) };
            if unsafe { entry.add(ENTRY_ACTIVE_WORD).read_volatile() } != 0 {
                let child = unsafe { entry.add(ENTRY_CHILD_WORD).read_volatile() } as *mut u32;
                unsafe { magic_tagged_object_destroy(child) };
            }
            index += 1;
        }
        unsafe { release_allocation(entries.cast()) };
    }

    unsafe { bzero(object.cast::<u8>().add(CLEAR_OFFSET), CLEAR_LEN as i32) };
    unsafe { release_allocation(object.cast()) };
}

#[cfg(test)]
static mut TEST_FREE: Option<unsafe extern "C" fn(*mut u8)> = None;

unsafe fn release_allocation(ptr: *mut u8) {
    #[cfg(test)]
    if let Some(free) = unsafe { TEST_FREE } {
        unsafe { free(ptr) };
        return;
    }
    unsafe { free_tag4(ptr) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::magic_tagged_object::MAGIC_TAGGED_OBJECT_TAG;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const CHILD_OFFSET: usize = 0x100;
    const ENTRIES_OFFSET: usize = 0x200;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MAGIC_TAGGED_OBJECT_DESTROY, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static mut FREES: [usize; 2] = [0; 2];
    static mut FREE_COUNT: usize = 0;
    unsafe extern "C" fn record_free(ptr: *mut u8) {
        unsafe { FREES[FREE_COUNT] = ptr as usize };
        unsafe { FREE_COUNT += 1 };
    }

    unsafe fn initialize_object(object: *mut u32, reference_count: u32) {
        unsafe { object.write_bytes(0, 0x90 / 4) };
        unsafe { object.write_volatile(MAGIC_TAGGED_OBJECT_TAG) };
        unsafe { object.add(REFCOUNT_WORD).write_volatile(reference_count) };
    }

    #[test]
    fn invalid_and_live_objects_are_unchanged_except_for_the_live_decrement() {
        let mut invalid = [0u32; 0x90 / 4];
        invalid[REFCOUNT_WORD] = 3;
        unsafe { magic_tagged_object_destroy(invalid.as_mut_ptr()) };
        assert_eq!(invalid[REFCOUNT_WORD], 3);

        let mut live = [0u32; 0x90 / 4];
        live[0] = MAGIC_TAGGED_OBJECT_TAG;
        live[REFCOUNT_WORD] = 2;
        unsafe { magic_tagged_object_destroy(live.as_mut_ptr()) };
        assert_eq!(live[REFCOUNT_WORD], 1);
    }

    #[test]
    fn final_release_destroys_active_children_then_frees_entries_and_owner() {
        let _lock = LOCK.lock();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/magic_tagged_object_destroy"));
            return;
        };
        let base = base as *mut u32;
        unsafe { base.cast::<u8>().write_bytes(0, SLAB_LEN) };
        let child = unsafe { base.cast::<u8>().add(CHILD_OFFSET).cast::<u32>() };
        let entries = unsafe { base.cast::<u8>().add(ENTRIES_OFFSET).cast::<u32>() };
        unsafe { initialize_object(base, 1) };
        unsafe { initialize_object(child, 2) };
        unsafe { base.add(CHILD_COUNT_WORD).write_volatile(2) };
        unsafe { base.add(CHILDREN_WORD).write_volatile(entries as u32) };
        unsafe { entries.add(ENTRY_ACTIVE_WORD).write_volatile(1) };
        unsafe { entries.add(ENTRY_CHILD_WORD).write_volatile(child as u32) };
        unsafe { entries.add(ENTRY_WORDS + ENTRY_ACTIVE_WORD).write_volatile(0) };
        unsafe { entries.add(ENTRY_WORDS + ENTRY_CHILD_WORD).write_volatile(base as u32) };
        unsafe { FREES = [0; 2] };
        unsafe { FREE_COUNT = 0 };

        unsafe { TEST_FREE = Some(record_free) };
        unsafe { magic_tagged_object_destroy(base) };
        unsafe { TEST_FREE = None };

        assert_eq!(unsafe { child.add(REFCOUNT_WORD).read_volatile() }, 1);
        assert_eq!(unsafe { FREE_COUNT }, 2);
        assert_eq!(unsafe { FREES }, [entries as usize, base as usize]);
        assert_eq!(unsafe { base.add(CHILDREN_WORD).read_volatile() }, 0);
    }
}
