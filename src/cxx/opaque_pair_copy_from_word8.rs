//! `opaque_pair_copy_from_word8` — retailOS `FUN_082a1dd4` at `0x082a1dd4`.
//!
//! Raw ARM establishes the true extent as `0x082a1dd4..0x082a1de4`: four
//! instructions ending in `bx lr`; the distinct next function begins at
//! `0x082a1de4`. Decoding every ARM B/BL-immediate word in `osos.dec` finds
//! five direct inbound calls, all unconditional plain `bl`; there are no
//! predicated `bl` or direct-tail `b` callers.
//!
//! Algorithm: load both opaque words at source offsets +0x20 and +0x24 before
//! storing either into `out`. The concrete record type is unrecovered, so this
//! module names only the observed pair and target-word offset.
//!
//! Deliberate deviations: none. Volatile accesses preserve the ARM's two loads
//! before either store and prevent LLVM from replacing this with a copy intrinsic.

/// opaque_pair_copy_from_word8 — retailOS `FUN_082a1dd4` at `0x082a1dd4`
/// (16 bytes; five unconditional plain-`bl` call sites, binary-verified).
///
/// Copies the opaque pair at source word indices 8 and 9 into `out`. Source
/// and destination may overlap: both source words are read before the first
/// destination store, exactly as the original `ldr`, `ldr`, `stmia` sequence.
///
/// # Safety
///
/// `source` must be readable through word index 9 and `out` must be writable
/// through word index 1. Both pointers must be four-byte aligned; neither is
/// NULL-checked by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_pair_copy_from_word8(out: *mut u32, source: *const u32) {
    let second = core::ptr::read_volatile(source.add(9));
    let first = core::ptr::read_volatile(source.add(8));
    core::ptr::write_volatile(out, first);
    core::ptr::write_volatile(out.add(1), second);
}

#[cfg(test)]
mod tests {
    use super::opaque_pair_copy_from_word8;

    #[test]
    fn copies_the_pair_at_words_eight_and_nine() {
        let source = [0u32, 1, 2, 3, 4, 5, 6, 7, 0x1122_3344, 0x5566_7788];
        let mut out = [0xdead_beef; 2];

        unsafe { opaque_pair_copy_from_word8(out.as_mut_ptr(), source.as_ptr()) };

        assert_eq!(out, [0x1122_3344, 0x5566_7788]);
    }

    #[test]
    fn reads_both_words_before_storing_an_overlapping_destination() {
        let mut words = [0u32, 1, 2, 3, 4, 5, 6, 7, 0x1122_3344, 0x5566_7788, 10];

        unsafe { opaque_pair_copy_from_word8(words.as_mut_ptr().add(9), words.as_ptr()) };

        assert_eq!(&words[8..], &[0x1122_3344, 0x1122_3344, 0x5566_7788]);
    }
}
