//! DOS wildcard matcher including deleted directory entries — `FUN_082e38b4` @
//! 0x082e38b4 (320 bytes; three inbound plain `bl` call sites, zero predicated).
//!
//! The two-word entry stub sets the shared matcher’s fourth argument to one,
//! so this entry matches candidates whose first byte is the FAT deleted-entry
//! marker (`0xe5`). It folds ASCII lowercase bytes to uppercase, treats `?` as
//! one byte and `*` as any sequence when wildcards are enabled, and normalizes
//! the mutable DOS `*.*` pattern to `*`. The raw ARM body is
//! 0x082e38b4..0x082e39f4; `push {r3-r11,lr}` at 0x082e39f4 starts the next
//! real function. The body contains four direct plain `bl` instructions (two
//! recursive calls and two ASCII-fold calls), with zero predicated `bl` forms.
//! Deliberate deviation: ASCII folding is inlined instead of calling the
//! unported `FUN_082e0180`; this preserves its verified byte transformation.

/// Matches a mutable DOS wildcard pattern against a NUL-terminated candidate,
/// including candidates beginning with the FAT deleted-entry marker.
///
/// Returns one for a match and zero otherwise.
///
/// # Safety
///
/// `pattern` must be writable and NUL-terminated; `candidate` must be readable
/// and NUL-terminated. Both are traversed without NULL guards, as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dos_wildcard_match_including_deleted(
    pattern: *mut u8,
    candidate: *const u8,
    wildcards_enabled: u32,
) -> u32 {
    if pattern.read() == b'*'
        && pattern.add(1).read() == b'.'
        && pattern.add(2).read() == b'*'
        && pattern.add(3).read() == 0
    {
        pattern.add(1).write(0);
    }

    dos_wildcard_match(pattern, candidate, wildcards_enabled)
}

unsafe fn dos_wildcard_match(pattern: *mut u8, candidate: *const u8, wildcards_enabled: u32) -> u32 {
    let mut pattern_index = 0usize;
    let mut candidate_index = 0usize;

    while pattern.add(pattern_index).read() != 0 {
        let pattern_byte = pattern.add(pattern_index).read();
        if pattern_byte == b'*' && wildcards_enabled != 0 {
            let mut matched = 0;
            while candidate.add(candidate_index).read() != 0 {
                matched |= dos_wildcard_match_including_deleted(
                    pattern.add(pattern_index + 1),
                    candidate.add(candidate_index),
                    wildcards_enabled,
                );
                candidate_index += 1;
            }
            return matched
                | dos_wildcard_match_including_deleted(
                    pattern.add(pattern_index + 1),
                    candidate.add(candidate_index),
                    wildcards_enabled,
                );
        }

        if candidate.add(candidate_index).read() == 0 {
            if pattern_byte == b'*'
                && pattern.add(pattern_index + 1).read() == 0
                && wildcards_enabled != 0
            {
                return 1;
            }
            return 0;
        }

        if pattern_byte != b'?' || wildcards_enabled == 0 {
            if ascii_upper(pattern_byte) != ascii_upper(candidate.add(candidate_index).read()) {
                return 0;
            }
        }
        pattern_index += 1;
        candidate_index += 1;
    }

    u32::from(candidate.add(candidate_index).read() == 0)
}

#[inline]
fn ascii_upper(byte: u8) -> u8 {
    if byte.is_ascii_lowercase() { byte - (b'a' - b'A') } else { byte }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches<const N: usize>(mut pattern: [u8; N], candidate: &[u8], wildcards_enabled: u32) -> u32 {
        unsafe {
            dos_wildcard_match_including_deleted(pattern.as_mut_ptr(), candidate.as_ptr(), wildcards_enabled)
        }
    }

    #[test]
    fn matches_case_insensitively_and_includes_deleted_entries() {
        assert_eq!(matches(*b"song.mp3\0", b"SoNg.Mp3\0", 1), 1);
        assert_eq!(matches(*b"*\0", b"\xe5deleted\0", 1), 1);
    }

    #[test]
    fn wildcard_enablement_controls_question_and_star() {
        assert_eq!(matches(*b"a?c\0", b"abc\0", 1), 1);
        assert_eq!(matches(*b"a?c\0", b"abc\0", 0), 0);
        assert_eq!(matches(*b"a*c\0", b"abbbc\0", 1), 1);
        assert_eq!(matches(*b"a*c\0", b"abbbc\0", 0), 0);
    }

    #[test]
    fn normalizes_star_dot_star_and_checks_empty_candidates() {
        let mut pattern = *b"*.*\0";
        assert_eq!(unsafe { dos_wildcard_match_including_deleted(pattern.as_mut_ptr(), b"anything\0".as_ptr(), 1) }, 1);
        assert_eq!(&pattern, b"*\0*\0");
        assert_eq!(matches(*b"*\0", b"\0", 1), 1);
        assert_eq!(matches(*b"?\0", b"\0", 1), 0);
    }
}
