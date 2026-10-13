//! Equality search over an aligned half-open firmware word range.

/// retailOS `thunk_FUN_083ea6dc` at **0x083ea6d4**.
/// Entry veneer: 4 bytes (`ea000000`, B 0x083ea6dc). True reachable extent:
/// **32 bytes**, [0x083ea6d4, 0x083ea6f4); the next entry starts with PUSH.
/// Whole-image aligned A32 decoding finds one incoming plain BL at
/// 0x08257b00, zero predicated BLs, and zero outgoing plain/predicated BLs.
///
/// Compare each aligned word in [begin, end) with the word at key, returning
/// the first matching address or end. The original reloads key on each comparison; empty
/// ranges read neither begin nor key. The initial branch skips the increment
/// at 0x083ea6d8; the loop returns its cursor in r0, not void as Ghidra says.
/// Deliberate deviation: implement the veneer and shared loop as one Rust
/// function rather than preserving the separate interior entry and branch.
/// LLVM hoists the key load after the empty check, valid under the safety contract.
///
/// # Safety
/// For a nonempty range, begin and end must bound one readable aligned u32
/// allocation, and key must point to a readable aligned u32. End must be
/// reachable by forward word steps. Equal bounds need not be readable.
/// Memory must not be MMIO or concurrently mutated.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn find_word_range(
    mut begin: *const u32,
    end: *const u32,
    key: *const u32,
) -> *const u32 {
    while begin != end {
        if begin.read() == key.read() {
            break;
        }
        begin = begin.add(1);
    }
    begin
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_subranges_match_reference_first_position() {
        let words = [0, u32::MAX, 7, 0x8000_0000, 7, 0];
        for start in 0..=words.len() {
            for end in start..=words.len() {
                for key in [0, u32::MAX, 7, 0x8000_0000, 42] {
                    let expected = words[start..end].iter().position(|word| *word == key)
                        .map(|offset| start + offset).unwrap_or(end);
                    unsafe {
                        assert_eq!(find_word_range(words.as_ptr().add(start),
                            words.as_ptr().add(end), &key), words.as_ptr().add(expected));
                    }
                }
            }
        }
    }

    #[test]
    fn empty_unreadable_bounds_and_key_are_not_loaded() {
        for bound in [core::ptr::null(), 1usize as *const u32] {
            unsafe { assert_eq!(find_word_range(bound, bound, core::ptr::null()), bound); }
        }
    }

    #[test]
    fn key_may_alias_range_and_end_is_excluded() {
        let words = [3, 9, 9, 17];
        unsafe {
            assert_eq!(find_word_range(words.as_ptr(), words.as_ptr().add(3),
                words.as_ptr().add(2)), words.as_ptr().add(1));
            assert_eq!(find_word_range(words.as_ptr(), words.as_ptr().add(3),
                words.as_ptr().add(3)), words.as_ptr().add(3));
        }
    }
}
