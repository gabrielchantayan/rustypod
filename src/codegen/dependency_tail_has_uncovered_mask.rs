//! `cg_dependency_tail_has_uncovered_mask` — original: `FUN_083672e4` @
//! `0x083672e4` (116 bytes, all code; three direct plain `bl` call sites and
//! zero predicated forms).
//!
//! Raw `osos.dec` establishes the exact extent from `0x083672e4` through the
//! return at `0x08367354`; the next independently entered function begins at
//! `0x08367358`.
//!
//! ## Algorithm
//!
//! Builds the dependency mask for `identifier`, then walks the 12-byte
//! expression entries in `rules` from `start_index`. It returns one when any
//! expression mask has a bit absent from the identifier's mask, otherwise zero.
//!
//! ## Deliberate deviations
//!
//! None. Rule and expression links remain 32-bit target words, so the code
//! uses target-word indices rather than host pointer-width fields.

/// Reports whether a rule-tail expression depends on an identifier outside its
/// own dependency mask.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_dependency_tail_has_uncovered_mask(
    rules: *const u32,
    context: *const u32,
    start_index: i32,
    identifier: u32,
) -> i32 {
    let identifier_mask =
        super::dependency_mask_lookup::cg_dependency_mask_lookup(context, identifier);
    let mut index = start_index;

    while (rules.read() as i32) > index {
        let entries = rules.add(3).read() as usize as *const u32;
        let expression = entries.add(index as usize * 3).read() as usize as *const u8;
        let expression_mask = super::expression_dependency_mask::cg_expression_dependency_mask(
            context,
            expression,
        );
        if expression_mask & !identifier_mask != 0 {
            return 1;
        }
        index += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CG_DEPENDENCY_TAIL_HAS_UNCOVERED_MASK, SLAB_LEN)
            .map(|pointer| pointer as usize)
    });

    fn slab() -> Option<*mut u8> {
        (*SLAB).map(|base| base as *mut u8)
    }

    unsafe fn target_word(pointer: *const u8) -> u32 {
        u32::try_from(pointer as usize).expect("fixture must be target-addressable")
    }

    unsafe fn leaf(node: *mut u8, identifier: u32) {
        core::ptr::write_bytes(node, 0, 0x28);
        node.write(0x95);
        node.add(0x24).cast::<u32>().write(identifier);
    }

    #[test]
    fn skips_covered_dependencies_and_detects_an_uncovered_tail_dependency() {
        let Some(base) = slab() else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let mut context = [0u32; 65];
        context[0] = 64;
        context[1] = 0x10;
        context[64] = 0x40;

        unsafe {
            let entries = base.add(0x40).cast::<u32>();
            let covered = base.add(0x100);
            let uncovered = base.add(0x140);
            leaf(covered, 0x10);
            leaf(uncovered, 0x40);
            entries.write(target_word(covered));
            entries.add(3).write(target_word(uncovered));
            base.cast::<u32>().write(2);
            base.add(12).cast::<u32>().write(target_word(entries.cast()));

            assert_eq!(cg_dependency_tail_has_uncovered_mask(base.cast(), context.as_ptr(), 0, 0x10), 1);
            assert_eq!(cg_dependency_tail_has_uncovered_mask(base.cast(), context.as_ptr(), 0, 0x40), 1);
        }
    }

    #[test]
    fn honors_start_index_and_empty_or_negative_rule_counts() {
        let Some(base) = slab() else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let context = [1, 0x10];

        unsafe {
            let entries = base.add(0x40).cast::<u32>();
            let uncovered = base.add(0x100);
            leaf(uncovered, 0x20);
            entries.write(target_word(uncovered));
            base.cast::<u32>().write(1);
            base.add(12).cast::<u32>().write(target_word(entries.cast()));

            assert_eq!(cg_dependency_tail_has_uncovered_mask(base.cast(), context.as_ptr(), 1, 0x10), 0);
            base.cast::<i32>().write(0);
            assert_eq!(cg_dependency_tail_has_uncovered_mask(base.cast(), context.as_ptr(), 0, 0x10), 0);
            base.cast::<i32>().write(-1);
            assert_eq!(cg_dependency_tail_has_uncovered_mask(base.cast(), context.as_ptr(), 0, 0x10), 0);
        }
    }
}
