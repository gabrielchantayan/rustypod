//! `obfuscated_word_noop` — `FUN_080276a8` @ **0x080276a8**, 4 bytes.
//!
//! Raw word `0xe12fff1e` decodes to `bx lr`. True extent: [0x080276a8,
//! 0x080276ac); the next entry is independently called at 0x08343cf0 and
//! 0x08348354. Whole-image aligned A32 decoding finds two plain inbound BLs
//! (0x082fa92c, 0x08312ed0), zero predicated inbound BLs, zero outgoing
//! calls, and no aligned address-word references.
//!
//! Obfuscated state-machine callers FUN_082fa514 and FUN_08312b70 load r0
//! from sp+0x14c and sp+0x148 respectively and do not consume the result.
//! Algorithm: return immediately, preserving the opaque input word and
//! accessing no memory. Its concrete type and destructor identity are unknown.
//! Deliberate deviations: expose preserved r0 as a u32 return despite Ghidra's
//! void prototype. A dedicated text section prevents identical-body folding;
//! LLVM may emit a balanced frame rather than the original single instruction.

/// Preserve an opaque firmware word without interpreting or dereferencing it.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_word_noop")]
#[inline(never)]
pub extern "C" fn obfuscated_word_noop(word: u32) -> u32 {
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_zero_unaligned_addresses_and_all_bits() {
        for word in [0, 1, 3, 0x0800_0000, 0x8000_0001, 0xffff_ffff,
                     0xaaaa_aaaa, 0x5555_5555] {
            assert_eq!(obfuscated_word_noop(word), word);
        }
        for bit in 0..32 {
            let word = 1u32 << bit;
            assert_eq!(obfuscated_word_noop(word), word);
            assert_eq!(obfuscated_word_noop(!word), !word);
        }
    }
}
