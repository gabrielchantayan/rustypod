//! Equality predicate for opaque 32-bit C++ value slots.

/// `word_slot_equal` — original: `FUN_083d7338` @ `0x083d7338` (24 bytes;
/// source: `ipod-decomp/decomp/c/037/083d7338_FUN_083d7338.c`).
///
/// Raw `osos.dec` establishes the complete body from `0x083d7338` through
/// `0x083d734f`; `push {lr}` at `0x083d7350` starts the next real function.
/// It has no outgoing `bl` instructions. A full raw ARM B/BL decode finds
/// three inbound plain `bl` calls and no predicated direct `bl` calls.
///
/// Loads one 32-bit word from each opaque slot and returns whether they are
/// equal. It does not dereference the loaded values or mutate either slot.
///
/// Deliberate deviations: none.
///
/// # Safety
/// `left` and `right` must each be readable, aligned pointers to a 32-bit
/// retailOS slot. As in the original, neither pointer is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_slot_equal(left: *const u32, right: *const u32) -> bool {
    left.read() == right.read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_words_compare_equal() {
        let left = 0x1234_5678;
        let right = 0x1234_5678;

        assert!(unsafe { word_slot_equal(&left, &right) });
    }

    #[test]
    fn distinct_words_compare_unequal() {
        let left = 0;
        let right = u32::MAX;

        assert!(!unsafe { word_slot_equal(&left, &right) });
    }

    #[test]
    fn the_same_slot_compares_equal_without_mutation() {
        let slot = 0x89ab_cdef;

        assert!(unsafe { word_slot_equal(&slot, &slot) });
        assert_eq!(slot, 0x89ab_cdef);
    }
}
