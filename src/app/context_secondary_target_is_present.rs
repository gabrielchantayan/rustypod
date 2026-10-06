//! `context_secondary_target_is_present` — original: `FUN_08168340` @
//! `0x08168340` (16 bytes; true extent `[0x08168340,0x08168350)`, followed
//! by the independently entered secondary-target setter at `0x08168350`).
//!
//! Raw A32 words: `e5900024 e3500000 13a00001 e12fff1e`, decoding to
//! `ldr r0,[r0,#0x24]; cmp r0,#0; movne r0,#1; bx lr`.
//! Full-image aligned A32 decoding finds two inbound plain BL sites
//! (`0x08168498`, `0x081684dc`), zero predicated BL sites, and no outgoing calls.
//!
//! Algorithm: read the target-width secondary target word at `context+0x24`
//! and return whether it is nonzero, normalized to zero or one. The target
//! is not dereferenced. Deliberate deviations: none.

const CONTEXT_SECONDARY_TARGET_WORD: usize = 0x24 / 4;

/// Returns whether the context has a secondary target.
///
/// # Safety
/// `context` must be valid to read an aligned `u32` at byte offset `0x24`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_secondary_target_is_present(context: *const u32) -> u32 {
    u32::from(context.add(CONTEXT_SECONDARY_TARGET_WORD).read() != 0)
}

#[cfg(test)]
mod tests {
    use super::context_secondary_target_is_present;

    #[test]
    fn distinguishes_secondary_target_from_primary_and_normalizes_all_bits() {
        for primary in [0, u32::MAX] {
            for secondary in [0, 1, 2, 0x8000_0000, u32::MAX] {
                let mut context = [0xa5a5_a5a5u32; 11];
                context[8] = primary;
                context[9] = secondary;
                let original = context;

                assert_eq!(
                    unsafe { context_secondary_target_is_present(context.as_ptr()) },
                    u32::from(secondary != 0)
                );
                assert_eq!(context, original);
            }
        }
    }
}
