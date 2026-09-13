//! Cache-entry transient-field reset.
//!
//! `cache_entry_reset` is retailOS `FUN_082e4b84` at `0x082e4b84` (24 bytes;
//! the next independently entered function starts at `0x082e4b9c`). Six direct
//! ARM `B`/`BL` words target it, verified by decoding every such word in
//! `osos.dec`: five are plain `bl` and one is `blne` at `0x082e12cc`.
//!
//! The function clears cache-entry words 0, 1, 3, and 4, in that exact store
//! order. It deliberately preserves word 2, the entry's cache-context link.
//! The predicated caller only invokes this reset when its preceding comparison
//! succeeds; the reset itself has no NULL guard and no conditional behavior.
//!
//! Deliberate deviations: none.

/// Target word index of the cache-entry context link retained by reset.
const CACHE_ENTRY_CONTEXT_WORD: usize = 2;

/// Resets cache-entry state while preserving its cache-context link.
///
/// Original: `FUN_082e4b84` at `0x082e4b84`, 24 bytes; six binary-verified
/// direct call sites (five `bl`, one `blne`).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cache_entry_reset")]
#[inline(never)]
pub unsafe extern "C" fn cache_entry_reset(entry: *mut u8) {
    let words = entry.cast::<u32>();
    words.write_volatile(0);
    words.add(1).write_volatile(0);
    words.add(CACHE_ENTRY_CONTEXT_WORD + 2).write_volatile(0);
    words.add(CACHE_ENTRY_CONTEXT_WORD + 1).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_transient_words_and_preserves_context_link() {
        let mut entry = [0x1111_1111u32, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0x5555_5555];

        unsafe {
            cache_entry_reset(entry.as_mut_ptr().cast());
        }

        assert_eq!(entry, [0, 0, 0x3333_3333, 0, 0]);
    }
}
