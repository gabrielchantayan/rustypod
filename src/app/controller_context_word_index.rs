//! Controller context word-table index — FUN_08051bf4 @ 0x08051bf4.
//! True extent: 40 bytes, [0x08051bf4, 0x08051c1c), followed by a new
//! push {r4,lr}. Raw A32 decoding: two plain inbound BLs (0x08172fa8,
//! 0x08172fbc), zero predicated inbound BLs; one plain outbound BL to
//! retail_word_index at 0x080c6294, zero predicated outbound BLs.
//! Load the target-width context pointer at controller+0xf00, zero-extend
//! its halfword at +0xb64, and look it up in the existing retail word table.
//! Return the index on success, or zero for any nonzero lookup status.
//! The notification caller caches this word; no finer table identity is known.
//! Deviations: no target behavior changes. Host tests inject the existing
//! lookup algorithm with a fixture table. Saved r3 is merely stack storage:
//! the callee always writes it, so it is not an input argument.

#[inline(always)]
unsafe fn context_word_index_with(
    controller: *const u32,
    lookup: impl FnOnce(u32, *mut u32) -> i32,
) -> u32 {
    let context = controller.add(0xf00 / 4).read() as usize as *const u16;
    let identifier = context.add(0xb64 / 2).read() as u32;
    let mut index = 0;
    if lookup(identifier, &mut index) == 0 { index } else { 0 }
}

/// # Safety
/// Controller must be aligned and readable at +0xf00, containing a valid
/// target-width context pointer readable as an aligned halfword at +0xb64.
/// The retail table at 0x083e2568 must contain 23 readable aligned words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_context_word_index(controller: *const u32) -> u32 {
    context_word_index_with(controller, |value, output| {
        super::retail_word_index::retail_word_index(value, output)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halfword_lookup_first_match_miss_and_current_context() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONTROLLER_CONTEXT_WORD_INDEX, 8192,
        ) else {
            crate::testing::note_missing_u32_fixture("app::controller_context_word_index");
            return;
        };
        let mut controller = [0xa5a5_a5a5u32; 0xf08 / 4];
        let mut table: [u32; 23] = core::array::from_fn(|i| 0x100 + i as u32);
        table[0] = 0;
        table[21] = 0x8000;
        table[22] = 0xffff;
        unsafe {
            let contexts = core::slice::from_raw_parts_mut(slab.cast::<u32>(), 8192 / 4);
            contexts.fill(0x5a5a_5a5a);
            for (iteration, identifier) in [0u16, 0x101, 0x114, 0x8000, 0xffff, 0x1234].into_iter().enumerate() {
                let offset = (iteration % 2) * 4096;
                // The high halfword must not participate in the lookup.
                contexts[(offset + 0xb64) / 4] = 0xbeef_0000 | identifier as u32;
                controller[0xf00 / 4] = slab.add(offset) as usize as u32;
                let before = contexts.to_vec();
                let owner_before = controller;
                let expected = table.iter().position(|&word| word == identifier as u32)
                    .map_or(0, |index| index as u32);
                let actual = context_word_index_with(controller.as_ptr(), |value, output| {
                    super::super::retail_word_index::find_word(value, output, table.as_ptr())
                });
                assert_eq!(actual, expected);
                assert_eq!(contexts, before.as_slice());
                assert_eq!(controller, owner_before);
            }
            table[3] = 0xffff;
            assert_eq!(context_word_index_with(controller.as_ptr(), |value, output| {
                super::super::retail_word_index::find_word(value, output, table.as_ptr())
            }), 0); // Miss sentinel must not escape as UINT32_MAX.
            controller[0xf00 / 4] = slab as usize as u32;
            contexts[0xb64 / 4] = 0xbeef_ffff;
            assert_eq!(context_word_index_with(controller.as_ptr(), |value, output| {
                super::super::retail_word_index::find_word(value, output, table.as_ptr())
            }), 3);
        }
    }
}
