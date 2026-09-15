//! Returns the optional byte following a high-bit field flag.
//!
//! `optional_flagged_byte` — original: `FUN_08164c80` at load address
//! `0x08164c80` (**24 bytes**, `0x08164c80..0x08164c97`; all code). Raw
//! `osos.dec` words establish the next separately linked function at
//! `0x08164c98`. Decoding every aligned ARM B/BL immediate in the complete
//! image finds **five direct `bl` call sites**, all unconditional/plain, at
//! `0x08163f00`, `0x08164a50`, `0x08164dbc`, `0x08164dec`, and `0x08164e68`;
//! there are no predicated `bl` call sites.
//!
//! The function reads byte zero and returns zero when its high bit is clear.
//! Otherwise it returns byte one. No deliberate deviations.

/// Returns the byte following `flagged_field` only when its high bit is set.
///
/// # Safety
///
/// `flagged_field` must be readable. When its high bit is set,
/// `flagged_field.add(1)` must also be readable. The original has no null,
/// bounds, or alignment guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn optional_flagged_byte(flagged_field: *const u8) -> u8 {
    if *flagged_field & 0x80 != 0 {
        *flagged_field.add(1)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::optional_flagged_byte;

    #[test]
    fn clear_flag_returns_zero_regardless_of_following_byte() {
        for second_byte in 0..=u8::MAX {
            let field = [0x7f, second_byte];
            assert_eq!(unsafe { optional_flagged_byte(field.as_ptr()) }, 0);
        }
    }

    #[test]
    fn set_flag_returns_every_possible_optional_byte() {
        for second_byte in 0..=u8::MAX {
            let field = [0x80, second_byte];
            assert_eq!(unsafe { optional_flagged_byte(field.as_ptr()) }, second_byte);
        }
    }
}
