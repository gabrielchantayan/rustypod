//! `magic_tagged_object_release` — original: `FUN_0806c044` @
//! **0x0806c044** (116 bytes; five verified inbound direct `bl` sites: four
//! plain and one predicated `blne`).
//!
//! Raw ARM establishes the extent 0x0806c044..0x0806c0b8; the separately
//! entered function at 0x0806c0b8 follows immediately. The body has three
//! static calls: `magic_tagged_object_validate`, a conditional `bleq` to
//! `tagged_counter_try_decrement`, and its own predicated recursive `blne`.
//! There are no tail branches.
//!
//! # Algorithm
//!
//! Validates the opaque first-word tag, then decrements the nonzero word at
//! `+0x08`. When that count reaches zero it attempts to decrement the tagged
//! counter rooted at `+0x18`. Finally, if an entry table exists at `+0x70`, it
//! recursively releases each active (`entry + 0x08 != 0`) child pointer at
//! `entry + 0x10`, for `count` entries of 0x14 bytes.
//!
//! Target pointers remain `u32` words rather than host pointers, preserving
//! ARM offsets on 64-bit hosts. Deliberate deviations: calls to the two
//! already-ported helpers and recursive target are direct Rust calls rather
//! than branches into stock code.

use crate::cxx::magic_tagged_object::{magic_tagged_object_validate, MagicTaggedObject};
use crate::util::tagged_counter::{tagged_counter_try_decrement, TaggedCounter};

const REFCOUNT_WORD: usize = 0x08 / 4;
const CHILD_COUNT_WORD: usize = 0x10 / 4;
const COUNTER_WORD: usize = 0x18 / 4;
const CHILDREN_WORD: usize = 0x70 / 4;
const ENTRY_WORDS: usize = 0x14 / 4;
const ENTRY_ACTIVE_WORD: usize = 0x08 / 4;
const ENTRY_CHILD_WORD: usize = 0x10 / 4;

/// Releases a valid opaque object and its active child objects.
///
/// # Safety
///
/// `object` must be readable through every raw target-layout word accessed by
/// the retail function. A non-null entry-table pointer and every active child
/// pointer must likewise satisfy this contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn magic_tagged_object_release(object: *mut u32) -> i32 {
    let validation = unsafe { magic_tagged_object_validate(object.cast::<MagicTaggedObject>()) };
    if validation != 0 {
        return validation;
    }

    let reference_count = unsafe { object.add(REFCOUNT_WORD).read_volatile() };
    if reference_count == 0 {
        return -0x32;
    }
    let remaining = reference_count.wrapping_sub(1);
    unsafe { object.add(REFCOUNT_WORD).write_volatile(remaining) };

    if remaining == 0 {
        let _ = unsafe {
            tagged_counter_try_decrement(object.add(COUNTER_WORD).cast::<TaggedCounter>())
        };
    }

    let entries = unsafe { object.add(CHILDREN_WORD).read_volatile() } as *mut u32;
    if entries.is_null() {
        return 0;
    }

    let mut index = 0usize;
    while index < unsafe { object.add(CHILD_COUNT_WORD).read_volatile() } as usize {
        let entry = unsafe { entries.add(index * ENTRY_WORDS) };
        if unsafe { entry.add(ENTRY_ACTIVE_WORD).read_volatile() } != 0 {
            let child = unsafe { entry.add(ENTRY_CHILD_WORD).read_volatile() } as *mut u32;
            let _ = unsafe { magic_tagged_object_release(child) };
        }
        index += 1;
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::magic_tagged_object::MAGIC_TAGGED_OBJECT_TAG;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::util::crts_tag::CRTS_TAG;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const CHILD_OFFSET: usize = 0x100;
    const ENTRIES_OFFSET: usize = 0x200;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MAGIC_TAGGED_OBJECT_RELEASE, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn initialize_object(object: *mut u32, reference_count: u32) {
        unsafe { object.write_bytes(0, 0x80 / 4) };
        unsafe { object.write_volatile(MAGIC_TAGGED_OBJECT_TAG) };
        unsafe { object.add(REFCOUNT_WORD).write_volatile(reference_count) };
        unsafe { object.add(COUNTER_WORD).write_volatile(CRTS_TAG) };
        unsafe { object.add(COUNTER_WORD + 0x30 / 4).write_volatile(1) };
    }

    #[test]
    fn rejects_invalid_and_zero_reference_objects_without_writes() {
        let mut invalid = [0u32; 32];
        invalid[REFCOUNT_WORD] = 3;
        assert_eq!(unsafe { magic_tagged_object_release(invalid.as_mut_ptr()) }, -0x32);
        assert_eq!(invalid[REFCOUNT_WORD], 3);

        let mut zero_reference = [0u32; 32];
        zero_reference[0] = MAGIC_TAGGED_OBJECT_TAG;
        assert_eq!(unsafe { magic_tagged_object_release(zero_reference.as_mut_ptr()) }, -0x32);
        assert_eq!(zero_reference[REFCOUNT_WORD], 0);
    }

    #[test]
    fn decrements_counter_at_zero_and_recursively_releases_active_children() {
        let _lock = LOCK.lock();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/magic_tagged_object_release"));
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

        assert_eq!(unsafe { magic_tagged_object_release(base) }, 0);
        assert_eq!(unsafe { base.add(REFCOUNT_WORD).read_volatile() }, 0);
        assert_eq!(unsafe { base.add(COUNTER_WORD + 0x30 / 4).read_volatile() }, 0);
        assert_eq!(unsafe { child.add(REFCOUNT_WORD).read_volatile() }, 1);
        assert_eq!(unsafe { child.add(COUNTER_WORD + 0x30 / 4).read_volatile() }, 1);
    }
}
