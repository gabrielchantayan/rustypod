//! `ft_too_many_hints` — original: `FUN_082d33fc` @ `0x082d33fc` (8 bytes;
//! true extent `0x082d33fc..0x082d3404`, followed by the distinct
//! `FUN_082d3404`).
//!
//! Raw ARM is `mov r0, #0x16; bx lr`. Decoding every ARM B/BL word in
//! `work/firmware/osos.dec` finds four direct plain unconditional `bl` call
//! sites (`0x08051984`, `0x080519e0`, `0x0805a088`, and `0x0805a0e4`) and no
//! predicated `bl` forms. The preceding function also tail-branches here from
//! `0x082d33f8`. This leaf neither reads arguments nor changes memory; it
//! returns FreeType's `FT_Err_Too_Many_Hints`. Deliberate deviations: none.

/// Returns FreeType's fixed `FT_Err_Too_Many_Hints` failure.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn ft_too_many_hints() -> i32 {
    super::error::FT_ERR_TOO_MANY_HINTS
}

#[cfg(test)]
mod tests {
    use super::ft_too_many_hints;
    use crate::ft::error::FT_ERR_TOO_MANY_HINTS;

    #[test]
    fn returns_the_stock_too_many_hints_error() {
        assert_eq!(ft_too_many_hints(), FT_ERR_TOO_MANY_HINTS);
        assert_eq!(ft_too_many_hints(), 0x16);
    }
}
