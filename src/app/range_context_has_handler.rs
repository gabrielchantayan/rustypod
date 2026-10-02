//! `range_context_has_handler` — retailOS `FUN_0829b86c` at `0x0829b86c`.
//!
//! True extent: 16 bytes (`0x0829b86c..0x0829b87c`). Raw words are
//! `e5900030 e3500000 13a00001 e12fff1e`: load word +0x30, compare with
//! zero, conditionally return one, then `bx lr`. The next function begins
//! with `push {r4,r5,lr}` at `0x0829b87c`. Whole-image aligned A32 decoding
//! finds two incoming plain BLs (0x08140550, 0x08284720), zero incoming
//! predicated BLs, and zero outgoing BLs of either kind.
//!
//! Reads the range context's handler word and returns exactly zero or one;
//! it neither dereferences the handler nor validates the context. The object
//! type is unrecovered, so offsets use target-width u32 words even on hosts.
//! Deliberate deviations: none.

/// Reports whether the range context contains a nonzero handler word.
///
/// # Safety
/// `context` must address a readable, aligned word at index 12 (+0x30).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.range_context_has_handler")]
#[inline(never)]
pub unsafe extern "C" fn range_context_has_handler(context: *const u32) -> u32 {
    u32::from(unsafe { context.add(12).read() } != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_every_handler_bit_without_dereferencing_it() {
        let mut context = [0u32; 13];
        for handler in core::iter::once(0).chain((0..32).map(|bit| 1u32 << bit)).chain([u32::MAX, 0x1234_5678]) {
            context[12] = handler;
            assert_eq!(unsafe { range_context_has_handler(context.as_ptr()) }, u32::from(handler != 0));
        }
    }

    #[test]
    fn ignores_neighbor_words_and_leaves_context_unchanged() {
        let mut context = [u32::MAX; 14];
        for handler in [0, 0x8000_0000] {
            context[12] = handler;
            let before = context;
            assert_eq!(unsafe { range_context_has_handler(context.as_ptr()) }, u32::from(handler != 0));
            assert_eq!(context, before);
        }
    }
}
