//! `cg_expression_dependency_mask` — original: `FUN_082cda48` @
//! `0x082cda48` (128 bytes, all code; 11 direct `bl` call sites).
//!
//! Raw `osos.dec` runs from the prologue at `0x082cda48` through `pop
//! {r4-r8,pc}` at `0x082cdac4`; the next separately linked function starts
//! at `0x082cdac8`. Decoding every ARM `B`/`BL` word finds eleven calls to
//! this entry, all unconditional `bl` (zero predicated forms): two recursive
//! calls in this body, eight uses in its 0x082ccf94..0x082cd9b4 sibling
//! walkers, and one H.264-side use at `0x08367324`.
//!
//! ## Algorithm
//!
//! Builds a 64-bit dependency mask for an opaque expression node. A NULL node
//! returns zero. Tag `0x95` is a leaf: its target-width word at `+0x24` is
//! resolved through [`cg_dependency_mask_lookup`]. Every other tag recursively
//! collects `+0x0c`, then `+0x08`, and ORs those masks with the two sibling
//! collection helpers over `+0x10` and `+0x38`, in that exact order.
//!
//! ## Deliberate deviations
//!
//! None. Node links are raw 32-bit target words, so accesses use word indices
//! rather than host-width pointer fields.


/// Reads one aligned target word from an opaque expression node.
#[inline(always)]
unsafe fn node_word(node: *const u8, word_index: usize) -> u32 {
    node.cast::<u32>().add(word_index).read()
}

/// `cg_expression_dependency_mask` — original: `FUN_082cda48` @ `0x082cda48`.
///
/// Returns the 64-bit dependency mask of `node`; node links are 32-bit words
/// in the dependency lookup table.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_expression_dependency_mask(
    context: *const u32,
    node: *const u8,
) -> u64 {
    if node.is_null() {
        return 0;
    }

    if node.read() == 0x95 {
        return super::dependency_mask_lookup::cg_dependency_mask_lookup(context, node_word(node, 9));
    }

    let mut mask = cg_expression_dependency_mask(context, node_word(node, 3) as usize as *const u8);
    mask |= cg_expression_dependency_mask(context, node_word(node, 2) as usize as *const u8);
    mask |= super::expression_collection_dependency_mask::cg_expression_collection_dependency_mask(
        context,
        node_word(node, 4) as usize as *const u8,
    );
    mask |= super::expression_linked_collection_dependency_mask::cg_expression_linked_collection_dependency_mask(
        context,
        node_word(node, 14) as usize as *const u8,
    );
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
        try_map_u32_slab(hints::CG_EXPRESSION_DEPENDENCY_MASK, SLAB_LEN).map(|p| p as usize)
    });

    fn slab() -> Option<*mut u8> {
        (*SLAB).map(|base| base as *mut u8)
    }

    unsafe fn write_word(at: *mut u8, offset: usize, value: u32) {
        at.add(offset).cast::<u32>().write(value);
    }

    fn target_word(pointer: *const u8) -> u32 {
        u32::try_from(pointer as usize).expect("fixture must be target-addressable")
    }

    #[test]
    fn null_node_returns_zero() {
        assert_eq!(unsafe { cg_expression_dependency_mask(ptr::null(), ptr::null()) }, 0);
    }

    #[test]
    fn non_leaf_recurses_then_ors_both_collection_masks() {
        let Some(base) = slab() else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        unsafe {
            ptr::write_bytes(base, 0, SLAB_LEN);
            let root = base.add(0x100);
            let first = base.add(0x200);
            let second = base.add(0x300);
            root.write(0x40);
            write_word(root, 0x0c, target_word(first));
            write_word(root, 0x08, target_word(second));
            first.write(0x95);
            write_word(first, 0x24, 0x1111_2222);
            second.write(0x95);
            write_word(second, 0x24, 0x3333_4444);

            let context = base.add(0x700).cast::<u32>();
            context.write(2);
            context.add(1).write(0x1111_2222);
            context.add(2).write(0x3333_4444);
            assert_eq!(cg_expression_dependency_mask(context, root), 3);
        }
    }
}
