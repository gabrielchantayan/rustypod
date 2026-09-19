//! Opaque collection entry copy @ `0x08054ba4`.
//!
//! Raw `osos.dec` establishes the 196-byte extent `0x08054ba4..0x08054c68`:
//! the next `push {r2,r3,r4,lr}` at `0x08054c68` starts another function.
//! There are four verified inbound unconditional plain `bl` call sites
//! (`0x08054b4c`, `0x0805cf70`, `0x080df3f0`, and `0x080e5b60`) and no
//! predicated `bl` forms. The body makes three unconditional calls: object
//! validation, `bzero`, and indexed-payload lookup.
//!
//! # Algorithm
//!
//! Validate the opaque collection, reject an out-of-range index or a zero word
//! at target offset `+0x08`, then copy selected fields from its 20-byte entry
//! table at `+0x70` into a zeroed 20-byte result. A nonzero entry byte `+0x08`
//! marks a direct payload at `+0x10`; otherwise a nonzero word `+0x0c` selects
//! an indexed-payload lookup through collection offset `+0x18`; with neither,
//! the result points at the entry's own `+0x10` field.
//!
//! # Deliberate deviations
//!
//! Target pointers remain `u32` words so all field offsets remain retailOS
//! offsets on 64-bit hosts. The host indexed-lookup path uses a native-pointer
//! temporary before narrowing it into the target-width result field.

use core::ptr;

use crate::app::indexed_payload_lookup::indexed_payload_lookup;
use crate::cxx::magic_tagged_object::{magic_tagged_object_validate, MagicTaggedObject};
use crate::libc::bzero::bzero;

/// Copies opaque collection entry `entry_index` into a target-layout 20-byte
/// result.
///
/// # Safety
/// `collection` must be readable through target word 28 and, after validation,
/// word 28 must be a readable target pointer to `entry_count * 20` bytes.
/// `result` must be writable for five target words. The indexed backend owns
/// the validity requirements for the collection's `+0x18` index and entry ID.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_collection_copy_entry")]
#[inline(never)]
pub unsafe extern "C" fn opaque_collection_copy_entry(
    collection: *const u32,
    entry_index: u32,
    result: *mut u32,
) -> i32 {
    let status = unsafe { magic_tagged_object_validate(collection.cast::<MagicTaggedObject>()) };
    if status != 0 {
        return status;
    }

    if unsafe { ptr::read(collection.add(4)) } <= entry_index || unsafe { ptr::read(collection.add(2)) } == 0 {
        return -0x32;
    }

    let entries = unsafe { ptr::read(collection.add(28)) as usize as *const u32 };
    let entry = unsafe { entries.add(entry_index as usize * 5) };
    unsafe { bzero(result.cast::<u8>(), 20) };
    unsafe {
        ptr::write(result.add(1), ptr::read(entry.add(1)));
        ptr::write(result.add(4), ptr::read(entry.add(3)));
        ptr::write(result, ptr::read(entry));
        result.cast::<u8>().add(9).write(entry.cast::<u8>().add(10).read());
    }

    if unsafe { entry.cast::<u8>().add(8).read() } != 0 {
        unsafe {
            result.cast::<u8>().add(8).write(1);
            ptr::write(result.add(3), ptr::read(entry.add(4)));
        }
        return 0;
    }

    let payload_entry = unsafe { ptr::read(entry.add(3)) };
    if payload_entry == 0 {
        unsafe { ptr::write(result.add(3), entry.add(4) as usize as u32) };
        return 0;
    }

    #[cfg(target_os = "none")]
    unsafe {
        indexed_payload_lookup(
            collection.cast_mut().cast::<u8>().add(0x18),
            ptr::read(entry.add(4)),
            result.add(3).cast::<*mut u8>(),
            ptr::null_mut(),
        ) as i32
    }

    #[cfg(not(target_os = "none"))]
    {
        let mut payload = ptr::null_mut();
        let status = unsafe {
            indexed_payload_lookup(
                collection.cast_mut().cast::<u8>().add(0x18),
                ptr::read(entry.add(4)),
                &mut payload,
                ptr::null_mut(),
            )
        };
        unsafe { ptr::write(result.add(3), payload as usize as u32) };
        status as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::magic_tagged_object::MAGIC_TAGGED_OBJECT_TAG;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const COLLECTION_WORDS: usize = 29;
    const ENTRY_OFFSET: usize = 0x100;

    unsafe fn fixture() -> Option<(*mut u32, *mut u32)> {
        let slab = try_map_u32_slab(hints::OPAQUE_COLLECTION_COPY_ENTRY, 0x1000)?;
        let collection = slab.cast::<u32>();
        let entries = slab.add(ENTRY_OFFSET).cast::<u32>();
        ptr::write(collection, MAGIC_TAGGED_OBJECT_TAG);
        ptr::write(collection.add(2), 1);
        ptr::write(collection.add(4), 1);
        ptr::write(collection.add(28), entries as usize as u32);
        Some((collection, entries))
    }

    #[test]
    fn rejects_invalid_collections_and_indexes_without_mutating_result() {
        let mut result = [0xfeed_face_u32; 5];
        assert_eq!(unsafe { opaque_collection_copy_entry(ptr::null(), 0, result.as_mut_ptr()) }, -0x32);

        let Some((collection, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("app/opaque_collection_copy_entry"));
            return;
        };
        assert_eq!(unsafe { opaque_collection_copy_entry(collection, 1, result.as_mut_ptr()) }, -0x32);
        assert_eq!(result, [0xfeed_face; 5]);
    }

    #[test]
    fn copies_direct_entry_and_preserves_target_word_offsets() {
        let Some((collection, entry)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("app/opaque_collection_copy_entry"));
            return;
        };
        unsafe {
            ptr::write(entry, 0x1122_3344);
            ptr::write(entry.add(1), 0x5566_7788);
            entry.cast::<u8>().add(8).write(7);
            entry.cast::<u8>().add(10).write(0xa5);
            ptr::write(entry.add(3), 0x99aa_bbcc);
            ptr::write(entry.add(4), 0xddee_ff00);
        }
        let mut result = [0_u32; 5];
        assert_eq!(unsafe { opaque_collection_copy_entry(collection, 0, result.as_mut_ptr()) }, 0);
        assert_eq!(result, [0x1122_3344, 0x5566_7788, 0x0000_a501, 0xddee_ff00, 0x99aa_bbcc]);
        assert_eq!(unsafe { result.as_ptr().cast::<u8>().add(9).read() }, 0xa5);
    }

    #[test]
    fn zero_payload_kind_returns_address_of_entry_payload_word() {
        let Some((collection, entry)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("app/opaque_collection_copy_entry"));
            return;
        };
        unsafe { ptr::write(entry.add(4), 0x0102_0304) };
        let mut result = [u32::MAX; 5];
        assert_eq!(unsafe { opaque_collection_copy_entry(collection, 0, result.as_mut_ptr()) }, 0);
        assert_eq!(result[3], unsafe { entry.add(4) as usize as u32 });
    }
}
