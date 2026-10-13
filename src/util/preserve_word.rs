//! Word-preserving no-op — retailOS `FUN_08028534` at `0x08028534`.
//!
//! Executed size: 4 bytes, raw A32 `e12fff1e` (`bx lr`). The extent to
//! the next known real function at `0x08028548` is 20 bytes; the remaining
//! four words are also `bx lr`, unreachable from this entry. Ghidra reports
//! only the executed word. Whole-image aligned raw decoding finds two incoming
//! plain BLs (0x082ea294, 0x082ea47c), zero predicated BLs, zero outgoing
//! calls, and no literal words equal to this entry address.
//!
//! Return the incoming r0 word without accessing memory. Both known callers
//! load r0 from stack +0x144 and overwrite it after return; neither establishes
//! an object type or destructor role. No callee seam is needed.
//! Deliberate deviations: expose the preserved register as a u32 result rather
//! than Ghidra's void signature; omit unreachable trailing words. LLVM may
//! add its normal frame but must retain a callable, non-inlined target.

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn preserve_word(word: u32) -> u32 {
    word
}

#[cfg(test)]
mod tests {
    use super::preserve_word;

    #[test]
    fn preserves_all_word_bits_without_interpreting_them_as_a_pointer() {
        let call: extern "C" fn(u32) -> u32 = preserve_word;
        for word in [0, 1, 0x0800_0000, 0x8000_0000, 0xdead_beef, u32::MAX] {
            assert_eq!(call(word), word);
        }
        for bit in 0..32 {
            let word = 1u32 << bit;
            assert_eq!(call(word), word);
            assert_eq!(call(!word), !word);
        }
    }
}
