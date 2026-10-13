//! Three-word swap — retailOS `FUN_083e6c9c` @ 0x083e6c9c.
//! True size: 52 bytes; BX LR at 0x083e6ccc precedes the next function's
//! PUSH at 0x083e6cd0. Raw whole-image A32 decoding finds one incoming
//! plain BL at 0x0816f378, zero predicated incoming BLs, and zero outgoing
//! plain or predicated BLs.
//!
//! Swap words at offsets 0, 4, and 8 in that order, reading both words
//! before either store at each offset. The caller exchanges a temporary
//! three-word record with its object's member at +0x68. No callee seams.
//! Deliberate deviations: none in behavior; LLVM may choose different
//! registers and instructions. Raw pointers retain the fixed four-byte
//! word stride on both ARM and the host, including overlapping records.

/// Exchanges three words sequentially, rather than snapshotting records.
///
/// # Safety
/// Both pointers must address three readable and writable aligned `u32`
/// words. They may be equal or overlap; neither may be null.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn three_word_swap(left: *mut u32, right: *mut u32) {
    for offset in 0..3 {
        let right_word = right.add(offset).read();
        let left_word = left.add(offset).read();
        left.add(offset).write(right_word);
        right.add(offset).write(left_word);
    }
}

/// Exchanges three words — retailOS `FUN_083e0990` @ 0x083e0990.
///
/// True extent 0x083e0990..0x083e09c4: 52 bytes, ending in BX LR
/// before the next independent PUSH. Whole-image raw A32 decoding finds
/// one incoming plain BL at 0x0815f530, zero predicated incoming BLs,
/// and zero outgoing plain or predicated BLs. The caller exchanges a
/// temporary vector head with its object's member at +0x0c.
/// Swap offsets 0, 4, 8 sequentially, loading right then left before
/// each pair of stores; overlapping heads retain this ordering.
/// Deliberate deviations: none in behavior. LLVM may fold this identical
/// body with `three_word_swap`; both exports implement the same word ABI.
///
/// # Safety
/// Both pointers must address three readable and writable aligned `u32`
/// words. Equal and overlapping pointers are valid; null pointers are not.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_head_swap(left: *mut u32, right: *mut u32) {
    for offset in 0..3 {
        let right_word = right.add(offset).read();
        let left_word = left.add(offset).read();
        left.add(offset).write(right_word);
        right.add(offset).write(left_word);
    }
}

#[cfg(test)]
mod tests {
    use super::{three_word_swap, vector_head_swap};

    #[test]
    fn disjoint_records_exchange_all_bits_and_preserve_guards() {
        for swap in [three_word_swap, vector_head_swap] {
        let mut left = [0xdead_beef, 0, 0x8000_0000, 0xffff_ffff, 0xcafe_babe];
        let mut right = [0x1234_5678, 7, 0x7654_3210, 0x5555_aaaa, 0x8765_4321];
        unsafe { swap(left.as_mut_ptr().add(1), right.as_mut_ptr().add(1)); }
        assert_eq!(left, [0xdead_beef, 7, 0x7654_3210, 0x5555_aaaa, 0xcafe_babe]);
        assert_eq!(right, [0x1234_5678, 0, 0x8000_0000, 0xffff_ffff, 0x8765_4321]);
        }
    }

    #[test]
    fn all_alias_offsets_match_sequential_reference() {
        for left in 1..=5 {
        for swap in [three_word_swap, vector_head_swap] {
            for right in 1..=5 {
                let mut actual = [0xdead_beef, 0, 1, 0x8000_0000,
                    0xffff_ffff, 0x1234_5678, 0xaaaa_5555, 7, 0xcafe_babe];
                let mut expected = actual;
                for offset in 0..3 {
                    expected.swap(left + offset, right + offset);
                }
                unsafe {
                    let base = actual.as_mut_ptr();
                    swap(base.add(left), base.add(right));
                }
                assert_eq!(actual, expected, "left {left}, right {right}");
            }
        }
        }
    }
}
