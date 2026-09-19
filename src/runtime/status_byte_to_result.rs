//! Status-byte conversion — `FUN_080865bc` @ 0x080865bc (36 bytes).
//!
//! The raw words are four comparisons/conditional returns followed by `mov r0,
//! #0; bx lr`; the next independent function begins at 0x080865e0 with `mov
//! r0, #23`. It maps the three observed status-byte encodings `0`, `1`, and
//! `0xff` to their ABI result words `0`, `1`, and `u32::MAX`; all other values
//! map to zero. Four plain direct `bl` instructions target this address; no
//! predicated direct `bl` instructions do.
//!
//! Deliberate deviation: Rust expresses the four ARM conditional-return paths
//! as one `match`; both preserve the exact returned `r0` word.

/// Converts a one-byte status encoding to its signed-result ABI word.
///
/// Original: `FUN_080865bc` @ 0x080865bc (36 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn status_byte_to_result(status: u32) -> u32 {
    match status {
        1 => 1,
        0xff => u32::MAX,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_defined_success_statuses() {
        assert_eq!(status_byte_to_result(0), 0);
        assert_eq!(status_byte_to_result(1), 1);
    }

    #[test]
    fn sign_extends_the_ff_status_encoding() {
        assert_eq!(status_byte_to_result(0xff), u32::MAX);
    }

    #[test]
    fn rejects_other_values_including_wider_words() {
        assert_eq!(status_byte_to_result(2), 0);
        assert_eq!(status_byte_to_result(0xfe), 0);
        assert_eq!(status_byte_to_result(0x100), 0);
        assert_eq!(status_byte_to_result(u32::MAX), 0);
    }
}
