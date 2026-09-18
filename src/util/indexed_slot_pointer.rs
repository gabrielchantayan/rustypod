//! `indexed_slot_pointer` — original: `FUN_0811f270` @ `0x0811f270` (36 bytes).
//!
//! The next real function begins at `0x0811f294`. Raw A32 decoding finds one
//! internal unconditional `bl` (to `0x081d5fe0`) and no predicated calls. Full
//! image decoding finds four inbound plain `bl` calls and no predicated calls:
//! `0x081fcbac`, `0x08208858`, `0x082088e0`, and `0x0821b0c0`.
//!
//! # Algorithm
//!
//! Given an opaque object and an index, the function reads the object's table
//! pointer at +0x14. For indices below 18, it loads that table's word at
//! `+0x24 + index * 0x24`; all other indices resolve to -1. A -1 result maps
//! to null; otherwise it is scaled by four and added to the object's +0x04
//! base pointer. This inlines the verified 16-byte `FUN_081d5fe0` helper,
//! avoiding an unrecovered callee seam. Deviation: none.

const TABLE_INDEX_LIMIT: u32 = 18;
const TABLE_FIRST_SLOT_WORD: usize = 9;
const TABLE_SLOT_STRIDE_WORDS: usize = 9;

#[inline]
unsafe fn resolve_slot(table: *const u32, index: u32) -> u32 {
    if index < TABLE_INDEX_LIMIT {
        unsafe { table.add(TABLE_FIRST_SLOT_WORD + index as usize * TABLE_SLOT_STRIDE_WORDS).read() }
    } else {
        u32::MAX
    }
}

/// Resolves `index` to an object's four-byte slot pointer, or null if its
/// table has no slot for that index.
///
/// # Safety
///
/// `object` must point to readable target-width words at +0x04 and +0x14. For
/// indices below 18, its +0x14 word must be a readable table through
/// `+0x24 + index * 0x24`. The retail code has no null or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_slot_pointer(object: *const u32, index: u32) -> *mut u32 {
    let table = unsafe { object.add(5).read() as *const u32 };
    let slot = unsafe { resolve_slot(table, index) };

    if slot == u32::MAX {
        core::ptr::null_mut()
    } else {
        unsafe { object.add(1).read().wrapping_add(slot.wrapping_mul(4)) as *mut u32 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_first_and_last_table_entries() {
        let mut table = [0u32; TABLE_FIRST_SLOT_WORD + TABLE_SLOT_STRIDE_WORDS * TABLE_INDEX_LIMIT as usize];
        table[TABLE_FIRST_SLOT_WORD] = 3;
        table[TABLE_FIRST_SLOT_WORD + 17 * TABLE_SLOT_STRIDE_WORDS] = 0x20;

        assert_eq!(unsafe { resolve_slot(table.as_ptr(), 0) }, 3);
        assert_eq!(unsafe { resolve_slot(table.as_ptr(), 17) }, 0x20);
    }

    #[test]
    fn rejects_index_eighteen_without_reading_the_table() {
        assert_eq!(unsafe { resolve_slot(core::ptr::null(), 18) }, u32::MAX);
        assert_eq!(unsafe { resolve_slot(core::ptr::null(), u32::MAX) }, u32::MAX);
    }

    #[test]
    fn returns_the_object_slot_address_and_null_sentinel() {
        use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

        let Some(slab) = try_map_u32_slab(hints::INDEXED_SLOT_POINTER, 0x1000) else {
            assert!(note_missing_u32_fixture("util/indexed_slot_pointer"));
            return;
        };
        let object = slab.cast::<u32>();
        let table = unsafe { slab.add(0x100).cast::<u32>() };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x1000);
            object.add(1).write(0x1000);
            object.add(5).write(table as usize as u32);
            table.add(TABLE_FIRST_SLOT_WORD).write(3);
            table.add(TABLE_FIRST_SLOT_WORD + 17 * TABLE_SLOT_STRIDE_WORDS).write(u32::MAX);
        }

        assert_eq!(unsafe { indexed_slot_pointer(object, 0) } as usize, 0x100c);
        assert!(unsafe { indexed_slot_pointer(object, 17) }.is_null());
        assert!(unsafe { indexed_slot_pointer(object, 18) }.is_null());
    }

    #[test]
    fn sentinel_slot_maps_to_null() {
        let table = [u32::MAX; TABLE_FIRST_SLOT_WORD + TABLE_SLOT_STRIDE_WORDS * TABLE_INDEX_LIMIT as usize];

        assert_eq!(unsafe { resolve_slot(table.as_ptr(), 0) }, u32::MAX);
    }

    #[test]
    fn slot_address_arithmetic_wraps_like_arm() {
        assert_eq!(0xffff_fffcu32.wrapping_add(2u32.wrapping_mul(4)), 4);
    }
}
