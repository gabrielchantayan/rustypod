//! `cg_expression_collection_dependency_mask` — original: `FUN_082cd8c4` @
//! `0x082cd8c4` (88 bytes, all code; 5 direct `bl` call sites).
//!
//! Raw `osos.dec` runs from `push {r4-r8,lr}` at `0x082cd8c4` through `pop
//! {r4-r8,pc}` at `0x082cd918`; the next real function starts at
//! `0x082cd91c`. Decoding the function finds one unconditional `bl` to
//! [`super::expression_dependency_mask::cg_expression_dependency_mask`];
//! decoding the whole image finds five direct callers, all plain unconditional
//! `bl` and zero predicated `bl` forms.
//!
//! ## Algorithm
//!
//! A non-NULL collection starts with a signed entry count and has a target-word
//! pointer at `+0x0c` to 12-byte entries. For every index less than that count,
//! it resolves the entry's first target word as an expression node and ORs its
//! 64-bit dependency mask into the result. NULL and non-positive counts return
//! zero without reading the entry array.
//!
//! ## Deliberate deviations
//!
//! None. Target pointers remain 32-bit words; this representation avoids host
//! pointer-width layout assumptions.

/// `cg_expression_collection_dependency_mask` — original: `FUN_082cd8c4` @
/// `0x082cd8c4`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_expression_collection_dependency_mask(
    context: *const u32,
    collection: *const u8,
) -> u64 {
    if collection.is_null() {
        return 0;
    }

    let entry_count = collection.cast::<i32>().read();
    
    let mut mask = 0;
    let mut index = 0;
    while index < entry_count {
        let entries = collection.cast::<u32>().add(3).read() as usize as *const u32;
        let node = entries.add(index as usize * 3).read() as usize as *const u8;
        mask |= super::expression_dependency_mask::cg_expression_dependency_mask(context, node);
        index += 1;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    extern crate std;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CG_EXPRESSION_COLLECTION_DEPENDENCY_MASK, SLAB_LEN)
            .map(|p| p as usize)
    });

    fn slab() -> Option<*mut u8> {
        (*SLAB).map(|base| base as *mut u8)
    }

    fn target_word(pointer: *const u8) -> u32 {
        u32::try_from(pointer as usize).expect("fixture must be target-addressable")
    }

    unsafe fn write_word(at: *mut u8, offset: usize, value: u32) {
        at.add(offset).cast::<u32>().write(value);
    }

    #[test]
    fn null_and_non_positive_collections_do_not_read_entries() {
        assert_eq!(unsafe { cg_expression_collection_dependency_mask(ptr::null(), ptr::null()) }, 0);
        let Some(base) = slab() else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        unsafe {
            ptr::write_bytes(base, 0, SLAB_LEN);
            for count in [0, -1] {
                base.cast::<i32>().write(count);
                assert_eq!(cg_expression_collection_dependency_mask(ptr::null(), base), 0);
            }
        }
    }

    #[test]
    fn ors_each_twelve_byte_entry_mask() {
        let Some(base) = slab() else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        unsafe {
            ptr::write_bytes(base, 0, SLAB_LEN);
            let collection = base.add(0x100);
            let entries = base.add(0x200);
            let first = base.add(0x300);
            let second = base.add(0x400);
            collection.cast::<i32>().write(2);
            write_word(collection, 0x0c, target_word(entries));
            write_word(entries, 0, target_word(first));
            write_word(entries, 12, target_word(second));
            first.write(0x95);
            write_word(first, 0x24, 0x1111_2222);
            second.write(0x95);
            write_word(second, 0x24, 0x3333_4444);
            let context = base.add(0x500).cast::<u32>();
            context.write(2);
            context.add(1).write(0x1111_2222);
            context.add(2).write(0x3333_4444);
            assert_eq!(cg_expression_collection_dependency_mask(context, collection), 3);
        }
    }
}
