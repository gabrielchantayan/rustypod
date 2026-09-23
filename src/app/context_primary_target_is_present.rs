//! `context_primary_target_is_present` — original: `FUN_08168330` @
//! `0x08168330` (16 bytes; true extent `0x08168330..0x0816833f`, followed by
//! the separately entered `FUN_08168340` at `0x08168340`).
//!
//! Raw A32 words are `ldr r0,[r0,#0x20]; cmp r0,#0; movne r0,#1; bx lr`.
//! A full-image aligned A32 branch-immediate decode finds three inbound plain
//! `bl` sites (`0x081683d4`, `0x08168488`, and `0x081684bc`) and no predicated
//! inbound `bl` forms; the leaf has no outgoing calls.
//!
//! Algorithm: read the target-width primary target word at `context+0x20` and
//! return whether it is nonzero, normalized to zero or one.
//!
//! Deliberate deviations: none.

const CONTEXT_PRIMARY_TARGET_WORD: usize = 0x20 / 4;

/// Returns whether the context has a primary target.
///
/// # Safety
/// `context` must be valid to read an aligned `u32` at byte offset `0x20`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_primary_target_is_present(context: *const u32) -> u32 {
    u32::from(context.add(CONTEXT_PRIMARY_TARGET_WORD).read() != 0)
}

#[cfg(test)]
mod tests {
    use super::context_primary_target_is_present;

    #[test]
    fn normalizes_primary_target_word_without_touching_neighbors() {
        for target in [0, 1, 0x8000_0000, u32::MAX] {
            let mut context = [0xa5a5_a5a5u32; 10];
            context[8] = target;

            assert_eq!(
                unsafe { context_primary_target_is_present(context.as_ptr()) },
                u32::from(target != 0)
            );
            assert!(context[..8].iter().all(|&word| word == 0xa5a5_a5a5));
            assert_eq!(context[9], 0xa5a5_a5a5);
        }
    }
}
