//! Nullable aligned u32 load — `FUN_08053b94` @ 0x08053b94 (12 bytes; 3 plain
//! inbound `bl` call sites, no predicated inbound calls).
//!
//! Raw osos.dec words establish the exact three-instruction A32 body
//! `cmp r0,#0; ldrne r0,[r0]; bx lr` at 0x08053b94..0x08053b9f. The next
//! independently entered function begins at 0x08053ba0 with `mov r2,r0`.
//! This leaf returns zero for a null input and otherwise loads and returns the
//! aligned u32 at its sole input address. Deliberate deviations: none.

/// Returns zero for null, otherwise loads the u32 stored at `word`.
///
/// A non-null `word` must be a valid, word-aligned address readable as `u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.nullable_u32_deref_or_zero")]
#[inline(never)]
pub unsafe extern "C" fn nullable_u32_deref_or_zero(word: *const u32) -> u32 {
    if word.is_null() {
        0
    } else {
        word.read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_returns_zero_without_loading() {
        assert_eq!(unsafe { nullable_u32_deref_or_zero(core::ptr::null()) }, 0);
    }

    #[test]
    fn loads_zero_word() {
        let word = 0;

        assert_eq!(unsafe { nullable_u32_deref_or_zero(&word) }, 0);
    }

    #[test]
    fn loads_high_bit_word() {
        let word = 0x8000_0001;

        assert_eq!(unsafe { nullable_u32_deref_or_zero(&word) }, 0x8000_0001);
    }
}
