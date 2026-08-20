//! Single-word shared-cell handle comparison from retailOS.
//!
//! The neighboring helper family establishes the slot's meaning: constructor
//! `FUN_083b5090` allocates an eight-byte `{ value, refcount }` cell and puts
//! its pointer in a slot; copy and destruction helpers `FUN_083b50e4` /
//! `FUN_083b524c` retain and release that cell. This leaf compares only the
//! slot values, without dereferencing either cell.

/// A 32-bit retailOS slot holding the pointer to a shared `{ value, refcount }`
/// cell. The cell's payload type is not recovered, but its ownership protocol
/// is established by the adjacent constructor, copy, and release helpers.
#[repr(transparent)]
pub struct SharedCellSlot(pub u32);

/// shared_cell_slot_ne — original: `FUN_083b5120` @ `0x083b5120` (20 bytes;
/// source: `ipod-decomp/decomp/c/035/083b5120_FUN_083b5120.c`).
///
/// Loads the 32-bit shared-cell pointer from each slot and returns true exactly
/// when those words differ. It neither dereferences the cells nor writes either
/// slot. Retail call sites compare the temporary and member slots that the
/// neighboring shared-cell retain/release family manages.
///
/// # Safety
/// `left` and `right` must each point to a readable, aligned retailOS
/// [`SharedCellSlot`]. As in the original, neither slot pointer is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_cell_slot_ne(
    left: *const SharedCellSlot,
    right: *const SharedCellSlot,
) -> bool {
    left.read().0 != right.read().0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_shared_cell_words_are_not_unequal() {
        let left = SharedCellSlot(0x1234_5678);
        let right = SharedCellSlot(0x1234_5678);

        assert!(!unsafe { shared_cell_slot_ne(&left, &right) });
    }

    #[test]
    fn unequal_shared_cell_words_are_unequal() {
        let left = SharedCellSlot(0x1234_5678);
        let right = SharedCellSlot(0x8765_4321);

        assert!(unsafe { shared_cell_slot_ne(&left, &right) });
    }

    #[test]
    fn the_same_slot_may_be_passed_for_both_inputs() {
        let slot = SharedCellSlot(0x89ab_cdef);

        assert!(!unsafe { shared_cell_slot_ne(&slot, &slot) });
    }

    #[test]
    fn extreme_slot_words_compare_without_mutation() {
        let left = SharedCellSlot(0);
        let right = SharedCellSlot(u32::MAX);
        let before = (left.0, right.0);

        assert!(unsafe { shared_cell_slot_ne(&left, &right) });
        assert_eq!((left.0, right.0), before);
    }
}
