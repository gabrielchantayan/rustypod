//! `magic_tagged_object_retain` — original: `FUN_0805c1b4` @
//! **0x0805c1b4** (108 bytes; four verified inbound direct `bl` call sites,
//! all plain).
//!
//! Raw ARM establishes the extent 0x0805c1b4..0x0805c220; the separately
//! entered function at 0x0805c220 follows immediately. The body has three
//! static calls: a plain `bl` to `magic_tagged_object_validate` (0x080d8f64),
//! a conditional `bleq` to `tagged_counter_try_increment` (0x0808e16c), and
//! its own predicated recursive `blne`. There are no tail branches.
//!
//! # Algorithm
//!
//! Validates the opaque first-word tag, propagating the validator's error
//! unchanged. Otherwise increments the word at `+0x08` with ARM wrapping
//! arithmetic; when the count transitions to exactly one it attempts to
//! increment the tagged counter rooted at `+0x18`. Finally, if an entry
//! table exists at `+0x70`, it recursively retains each active
//! (`ldrb` at `entry + 0x08` != 0) child pointer at `entry + 0x10`, for
//! `count` (unsigned compare at `+0x10`) entries of 0x14 bytes. Returns 0.
//!
//! Target pointers remain `u32` words rather than host pointers, preserving
//! ARM offsets on 64-bit hosts. Deliberate deviations: calls to the two
//! already-ported helpers and the recursive target are direct Rust calls
//! rather than branches into stock code.

use crate::cxx::magic_tagged_object::{magic_tagged_object_validate, MagicTaggedObject};
use crate::util::tagged_counter::{tagged_counter_try_increment, TaggedCounter};

const REFCOUNT_WORD: usize = 0x08 / 4;
const CHILD_COUNT_WORD: usize = 0x10 / 4;
const COUNTER_WORD: usize = 0x18 / 4;
const CHILDREN_WORD: usize = 0x70 / 4;
const ENTRY_WORDS: usize = 0x14 / 4;
const ENTRY_ACTIVE_BYTE: usize = 0x08;
const ENTRY_CHILD_WORD: usize = 0x10 / 4;

/// Retains a valid opaque object and its active child objects.
///
/// # Safety
///
/// `object` must be readable and writable through every raw target-layout
/// word accessed by the retail function. A non-null entry-table pointer and
/// every active child pointer must likewise satisfy this contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn magic_tagged_object_retain(object: *mut u32) -> i32 {
    let validation = unsafe { magic_tagged_object_validate(object.cast::<MagicTaggedObject>()) };
    if validation != 0 {
        return validation;
    }

    let reference_count = unsafe { object.add(REFCOUNT_WORD).read_volatile() };
    let retained = reference_count.wrapping_add(1);
    unsafe { object.add(REFCOUNT_WORD).write_volatile(retained) };

    if retained == 1 {
        let _ = unsafe {
            tagged_counter_try_increment(object.add(COUNTER_WORD).cast::<TaggedCounter>())
        };
    }

    let entries = unsafe { object.add(CHILDREN_WORD).read_volatile() } as *mut u32;
    if entries.is_null() {
        return 0;
    }

    let mut index = 0usize;
    while index < unsafe { object.add(CHILD_COUNT_WORD).read_volatile() } as usize {
        let entry = unsafe { entries.add(index * ENTRY_WORDS) };
        if unsafe { entry.cast::<u8>().add(ENTRY_ACTIVE_BYTE).read_volatile() } != 0 {
            let child = unsafe { entry.add(ENTRY_CHILD_WORD).read_volatile() } as *mut u32;
            let _ = unsafe { magic_tagged_object_retain(child) };
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
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const ENTRIES_OFFSET: usize = 0x200;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MAGIC_TAGGED_OBJECT_RETAIN, SLAB_LEN).map(|pointer| pointer as usize)
    });

    unsafe fn initialize_object(object: *mut u32, reference_count: u32) {
        unsafe { object.write_bytes(0, 0x80 / 4) };
        unsafe { object.write_volatile(MAGIC_TAGGED_OBJECT_TAG) };
        unsafe { object.add(REFCOUNT_WORD).write_volatile(reference_count) };
        unsafe { object.add(COUNTER_WORD).write_volatile(CRTS_TAG) };
        unsafe { object.add(COUNTER_WORD + 0x30 / 4).write_volatile(0) };
    }

    #[test]
    fn propagates_validation_errors_without_writes() {
        let mut invalid = [0u32; 32];
        invalid[REFCOUNT_WORD] = 7;
        assert_eq!(unsafe { magic_tagged_object_retain(invalid.as_mut_ptr()) }, -0x32);
        assert_eq!(invalid[REFCOUNT_WORD], 7);
        assert_eq!(unsafe { magic_tagged_object_retain(core::ptr::null_mut()) }, -0x32);
    }

    #[test]
    fn first_retain_increments_the_tagged_counter() {
        let mut object = [0u32; 32];
        object[0] = MAGIC_TAGGED_OBJECT_TAG;
        object[REFCOUNT_WORD] = 0;
        object[COUNTER_WORD] = CRTS_TAG;
        object[COUNTER_WORD + 0x30 / 4] = 5;
        assert_eq!(unsafe { magic_tagged_object_retain(object.as_mut_ptr()) }, 0);
        assert_eq!(object[REFCOUNT_WORD], 1);
        assert_eq!(object[COUNTER_WORD + 0x30 / 4], 6);
    }

    #[test]
    fn later_retains_leave_the_tagged_counter_alone() {
        let mut object = [0u32; 32];
        object[0] = MAGIC_TAGGED_OBJECT_TAG;
        object[REFCOUNT_WORD] = 1;
        object[COUNTER_WORD] = CRTS_TAG;
        object[COUNTER_WORD + 0x30 / 4] = 5;
        assert_eq!(unsafe { magic_tagged_object_retain(object.as_mut_ptr()) }, 0);
        assert_eq!(object[REFCOUNT_WORD], 2);
        assert_eq!(object[COUNTER_WORD + 0x30 / 4], 5);

        // u32::MAX -> 0 wraps like ARM and is not the first retain.
        object[REFCOUNT_WORD] = u32::MAX;
        assert_eq!(unsafe { magic_tagged_object_retain(object.as_mut_ptr()) }, 0);
        assert_eq!(object[REFCOUNT_WORD], 0);
        assert_eq!(object[COUNTER_WORD + 0x30 / 4], 5);
    }

    #[test]
    fn retains_only_active_children_and_null_tables() {
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/magic_tagged_object_retain"));
            return;
        };
        unsafe {
            let object = base as *mut u32;
            let child = (base + 0x100) as *mut u32;
            let inactive_child = (base + 0x180) as *mut u32;
            let entries = (base + ENTRIES_OFFSET) as *mut u32;

            initialize_object(object, 4);
            initialize_object(child, 9);
            initialize_object(inactive_child, 9);
            entries.write_bytes(0, (ENTRY_WORDS * 2) as usize);
            // Entry 0: active, points at child.
            (entries.cast::<u8>()).add(ENTRY_ACTIVE_BYTE).write_volatile(1);
            entries.add(ENTRY_CHILD_WORD).write_volatile(child as u32);
            // Entry 1: inactive byte, pointer must be ignored.
            entries.add(ENTRY_WORDS + ENTRY_CHILD_WORD).write_volatile(inactive_child as u32);
            object.add(CHILDREN_WORD).write_volatile(entries as u32);
            object.add(CHILD_COUNT_WORD).write_volatile(2);

            assert_eq!(magic_tagged_object_retain(object), 0);
            assert_eq!(object.add(REFCOUNT_WORD).read_volatile(), 5);
            assert_eq!(child.add(REFCOUNT_WORD).read_volatile(), 10);
            assert_eq!(inactive_child.add(REFCOUNT_WORD).read_volatile(), 9);

            // Null entry table skips the walk entirely.
            object.add(CHILDREN_WORD).write_volatile(0);
            object.add(CHILD_COUNT_WORD).write_volatile(2);
            assert_eq!(magic_tagged_object_retain(object), 0);
            assert_eq!(object.add(REFCOUNT_WORD).read_volatile(), 6);
        }
    }
}
