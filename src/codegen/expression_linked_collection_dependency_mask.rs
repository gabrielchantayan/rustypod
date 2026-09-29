//! `cg_expression_linked_collection_dependency_mask` — original: `FUN_082cd9b4`
//! @ `0x082cd9b4` (148 bytes, all code; 2 direct `bl` call sites).
//!
//! Raw `osos.dec` runs from `push {r4-r8,lr}` at `0x082cd9b4` through `pop
//! {r4-r8,pc}` at `0x082cda44`; the next real function starts at `0x082cda48`.
//! The body has five plain unconditional `bl` instructions (three to
//! `cg_expression_collection_dependency_mask`, two to
//! `cg_expression_dependency_mask`) and no predicated `bl`. Raw-image
//! disassembly finds two inbound plain `bl` call sites and no predicated calls.
//!
//! ## Algorithm
//!
//! Walks a NULL-terminated chain of nine-word records. For each record, ORs
//! dependency masks from collection words 0, 5, and 7, then expression words 4
//! and 6, preserving the retailOS call order. The next record is word 8.
//!
//! ## Deliberate deviations
//!
//! None. Links are read as 32-bit target words, rather than host pointers.

/// `cg_expression_linked_collection_dependency_mask` — original:
/// `FUN_082cd9b4` @ `0x082cd9b4`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_expression_linked_collection_dependency_mask(
    context: *const u32,
    mut record: *const u8,
) -> u64 {
    let mut mask = 0;
    while !record.is_null() {
        let words = record.cast::<u32>();
        mask |= super::expression_collection_dependency_mask::cg_expression_collection_dependency_mask(
            context,
            words.read() as usize as *const u8,
        );
        mask |= super::expression_collection_dependency_mask::cg_expression_collection_dependency_mask(
            context,
            words.add(5).read() as usize as *const u8,
        );
        mask |= super::expression_collection_dependency_mask::cg_expression_collection_dependency_mask(
            context,
            words.add(7).read() as usize as *const u8,
        );
        mask |= super::expression_dependency_mask::cg_expression_dependency_mask(
            context,
            words.add(4).read() as usize as *const u8,
        );
        mask |= super::expression_dependency_mask::cg_expression_dependency_mask(
            context,
            words.add(6).read() as usize as *const u8,
        );
        record = words.add(8).read() as usize as *const u8;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use core::ptr;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CG_EXPRESSION_LINKED_COLLECTION_DEPENDENCY_MASK, SLAB_LEN)
            .map(|p| p as usize)
    });

    fn target_word(pointer: *const u8) -> u32 {
        u32::try_from(pointer as usize).expect("fixture must be target-addressable")
    }

    unsafe fn write_word(at: *mut u8, offset: usize, value: u32) {
        at.add(offset).cast::<u32>().write(value);
    }

    #[test]
    fn null_record_returns_zero() {
        assert_eq!(unsafe { cg_expression_linked_collection_dependency_mask(ptr::null(), ptr::null()) }, 0);
    }

    #[test]
    fn combines_all_fields_and_follows_next_record() {
        let Some(base) = (*SLAB).map(|base| base as *mut u8) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        unsafe {
            ptr::write_bytes(base, 0, SLAB_LEN);
            let context = base.add(0x800).cast::<u32>();
            context.write(5);
            for index in 0..5 {
                context.add(index + 1).write(0x100 + index as u32);
            }

            let records = [base.add(0x100), base.add(0x140)];
            let leaves = [base.add(0x200), base.add(0x240), base.add(0x280), base.add(0x2c0), base.add(0x300)];
            for (index, leaf) in leaves.into_iter().enumerate() {
                leaf.write(0x95);
                write_word(leaf, 0x24, 0x100 + index as u32);
            }
            let collections = [base.add(0x400), base.add(0x420), base.add(0x440)];
            for (index, collection) in collections.into_iter().enumerate() {
                collection.cast::<i32>().write(1);
                write_word(collection, 0x0c, target_word(base.add(0x500 + index * 0x0c)));
                write_word(base.add(0x500 + index * 0x0c), 0, target_word(leaves[index]));
            }

            write_word(records[0], 0x00, target_word(collections[0]));
            write_word(records[0], 0x14, target_word(collections[1]));
            write_word(records[0], 0x1c, target_word(collections[2]));
            write_word(records[0], 0x10, target_word(leaves[3]));
            write_word(records[0], 0x18, target_word(leaves[4]));
            write_word(records[0], 0x20, target_word(records[1]));

            assert_eq!(cg_expression_linked_collection_dependency_mask(context, records[0]), 0x1f);
        }
    }
}
