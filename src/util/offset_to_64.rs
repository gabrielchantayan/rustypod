//! Complements an unsigned offset against 64.

/// `offset_to_64` — original: `FUN_080cdd64` @ `0x080cdd64`
/// (8 bytes; source: `ipod-decomp/decomp/c/007/080cdd64_FUN_080cdd64.c`).
///
/// Raw `osos.dec` words establish the complete body as `rsb r0,r0,#0x40;
/// bx lr` at `0x080cdd64..0x080cdd6b`; the `push {r0,r6,r7,lr}` at
/// `0x080cdd6c` starts the next independently linked function. Decoding
/// call sites finds three plain unconditional `bl` calls and zero predicated
/// `bl` calls.
///
/// Returns the A32 wrapping subtraction `64 - offset`. This is used by the
/// callers as the remaining distance to the 64-unit boundary.
///
/// Deliberate deviations: none.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.offset_to_64")]
#[inline(never)]
pub extern "C" fn offset_to_64(offset: u32) -> u32 {
    0x40u32.wrapping_sub(offset)
}

#[cfg(test)]
mod tests {
    use super::offset_to_64;

    #[test]
    fn complements_offsets_at_and_inside_the_boundary() {
        assert_eq!(offset_to_64(0), 0x40);
        assert_eq!(offset_to_64(0x31), 0x0f);
        assert_eq!(offset_to_64(0x40), 0);
    }

    #[test]
    fn preserves_a32_wrapping_subtraction_beyond_the_boundary() {
        assert_eq!(offset_to_64(0x41), u32::MAX);
        assert_eq!(offset_to_64(u32::MAX), 0x41);
    }
}
