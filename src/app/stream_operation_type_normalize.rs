//! Normalizes retail stream-operation type codes.
//!
//! `stream_operation_type_normalize` — original: `FUN_0804af30` @
//! `0x0804af30` (80 bytes, `0x0804af30..0x0804af7f`; `push {r4-r8,lr}` at
//! `0x0804af80` begins the next real function). Raw A32 decoding finds no
//! outbound plain or predicated `bl` instructions. Whole-image decoding finds
//! three inbound plain `bl` calls and no predicated inbound calls.
//!
//! # Algorithm
//!
//! Codes 6 and 0x13 normalize to 6; 0x1c remains 0x1c; codes 0x42, 0x43,
//! 0x46, 0x71, and 0x74 normalize to 0x74. Every other input maps to zero.
//! Deliberate deviation: Rust expresses the original comparison tree as a
//! `match`; it has no side effects or calls.

/// Maps a retail stream-operation code to its normalized type.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn stream_operation_type_normalize(code: u32) -> u32 {
    match code {
        6 | 0x13 => 6,
        0x1c => 0x1c,
        0x42 | 0x43 | 0x46 | 0x71 | 0x74 => 0x74,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(code: u32) -> u32 {
        if code == 0x43 {
            0x74
        } else if code < 0x44 {
            if code == 6 || code == 0x13 {
                6
            } else if code == 0x1c {
                0x1c
            } else if code == 0x42 {
                0x74
            } else {
                0
            }
        } else if code == 0x46 || code == 0x71 || code == 0x74 {
            0x74
        } else {
            0
        }
    }

    #[test]
    fn normalizes_every_recognized_code() {
        for (code, expected) in [(6, 6), (0x13, 6), (0x1c, 0x1c), (0x42, 0x74), (0x43, 0x74), (0x46, 0x74), (0x71, 0x74), (0x74, 0x74)] {
            assert_eq!(stream_operation_type_normalize(code), expected);
        }
    }

    #[test]
    fn rejects_boundaries_and_unrelated_codes() {
        for code in [0, 5, 7, 0x12, 0x14, 0x1b, 0x1d, 0x41, 0x44, 0x45, 0x47, 0x70, 0x72, 0x73, 0x75, u32::MAX] {
            assert_eq!(stream_operation_type_normalize(code), reference(code));
        }
    }
}
