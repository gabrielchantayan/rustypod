//! `opaque_four_word_copy_from_word7` — retailOS `FUN_0829b854` at
//! **0x0829b854** (16 bytes, `0x0829b854..0x0829b864`; the next separately
//! linked function begins at `0x0829b864`).
//!
//! Raw ARM decodes to `add r1,#0x1c; ldmia r1,{r1,r2,r3,ip}; stmia r0,{r1,r2,r3,ip};
//! bx lr`. Decoding every aligned A32 B/BL-immediate word in `osos.dec` finds
//! four inbound direct calls, all unconditional plain `bl` at 0x081098d4,
//! 0x081dcb7c, 0x081e8684, and 0x082711d4; no predicated `bl` reaches it.
//!
//! Algorithm: load the four opaque words at source word indices 7 through 10,
//! then store them to `out` in order. The wider record and value types are not
//! recovered, so the name records only the verified word range. Deliberate
//! deviations: none. Volatile accesses retain the all-loads-before-stores
//! overlap behavior of the ARM `ldm`/`stm` pair and prevent a copy intrinsic.

/// Copies the opaque four-word value at source word indices 7 through 10 into
/// `out`, matching retailOS `FUN_0829b854` at 0x0829b854.
///
/// # Safety
///
/// `source` must be readable through word index 10 and `out` must be writable
/// through word index 3. Both pointers must be four-byte aligned and are not
/// NULL-checked by retailOS. They may overlap because all four source words
/// are read before the first destination store.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_four_word_copy_from_word7(out: *mut u32, source: *const u32) {
    let word7 = core::ptr::read_volatile(source.add(7));
    let word8 = core::ptr::read_volatile(source.add(8));
    let word9 = core::ptr::read_volatile(source.add(9));
    let word10 = core::ptr::read_volatile(source.add(10));

    core::ptr::write_volatile(out, word7);
    core::ptr::write_volatile(out.add(1), word8);
    core::ptr::write_volatile(out.add(2), word9);
    core::ptr::write_volatile(out.add(3), word10);
}

#[cfg(test)]
mod tests {
    use super::opaque_four_word_copy_from_word7;

    #[test]
    fn copies_exactly_the_four_words_at_word_seven() {
        let source = [
            0xfeed_face, 1, 2, 3, 4, 5, 6, 0x1122_3344, 0x5566_7788,
            0x99aa_bbcc, 0xddee_ff00, 0xc001_d00d,
        ];
        let mut out = [0xdead_beef; 5];

        unsafe { opaque_four_word_copy_from_word7(out.as_mut_ptr(), source.as_ptr()) };

        assert_eq!(out, [0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00, 0xdead_beef]);
    }

    #[test]
    fn reads_the_complete_source_value_before_overlapping_stores() {
        let mut words = [0, 1, 2, 3, 4, 5, 6, 0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00];

        unsafe {
            opaque_four_word_copy_from_word7(words.as_mut_ptr().add(8), words.as_ptr());
        }

        assert_eq!(
            &words[7..],
            &[0x1122_3344, 0x1122_3344, 0x5566_7788, 0x99aa_bbcc]
        );
    }
}
