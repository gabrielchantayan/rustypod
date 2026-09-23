//! Selects the MOV atom-header read width from parser byte zero.
//!
//! `mov_atom_header_read_width` — original: `FUN_081f3d44` at load address
//! `0x081f3d44` (**36 bytes**, `0x081f3d44..0x081f3d67`; the next real
//! function begins at `0x081f3d68`). Complete-image A32 decoding finds three
//! incoming direct plain `bl` call sites (`0x081f3e44`, `0x081f3e6c`, and
//! `0x081f3f28`) and no predicated `bl` call sites. The body has no calls.
//!
//! Algorithm: load parser byte zero; return 8 for values 0 and 1, 6 for value
//! 2, and 10 for every other value. No deliberate deviations.

/// Returns the reader width selected by `parser` byte zero.
///
/// # Safety
///
/// `parser` must be readable. The retail function has no null or bounds guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_atom_header_read_width(parser: *const u8) -> u32 {
    let kind = unsafe { *parser };
    if kind > 1 {
        if kind == 2 {
            6
        } else {
            10
        }
    } else {
        8
    }
}

#[cfg(test)]
mod tests {
    use super::mov_atom_header_read_width;

    #[test]
    fn selects_the_retail_width_for_every_parser_kind() {
        for kind in 0..=u8::MAX {
            let expected = match kind {
                0 | 1 => 8,
                2 => 6,
                _ => 10,
            };
            assert_eq!(unsafe { mov_atom_header_read_width(&kind) }, expected);
        }
    }
}
