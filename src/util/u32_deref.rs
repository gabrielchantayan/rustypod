//! Aligned u32 dereference — `FUN_08298848` @ 0x08298848 (8 bytes; 3 plain
//! inbound `bl` call sites, no predicated inbound calls).
//!
//! Raw osos.dec words establish the exact two-instruction A32 body
//! `ldr r0,[r0]; bx lr` at 0x08298848..0x0829884f. The next independently
//! entered function begins at 0x08298850 with `push {r4,lr}`. This leaf loads
//! and returns the aligned u32 at its sole input address. Deliberate
//! deviations: none.

/// Loads and returns the u32 stored at `word`.
///
/// `word` must be a valid, word-aligned address readable as `u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.u32_deref")]
#[inline(never)]
pub unsafe extern "C" fn u32_deref(word: *const u32) -> u32 {
    word.read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_zero_word() {
        let word = 0;

        assert_eq!(unsafe { u32_deref(&word) }, 0);
    }

    #[test]
    fn loads_high_bit_word() {
        let word = 0x8000_0001;

        assert_eq!(unsafe { u32_deref(&word) }, 0x8000_0001);
    }
}
