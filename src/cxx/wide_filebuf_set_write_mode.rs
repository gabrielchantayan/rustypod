//! Wide file-buffer write-mode flag setter.
//!
//! Original: 0x083da7cc, 24 bytes, extent [0x083da7cc, 0x083da7e4).
//! Verified whole-image raw A32 calls: one incoming plain BL (0x083d9d4c),
//! zero predicated BLs and zero outgoing BLs. The next function independently
//! sets bit 2. MOVS r2,r1; LDR r1,[r0,#16]; BICEQ/ORRNE r1,r1,#2;
//! STR r1,[r0,#16]; MOV pc,lr.
//!
//! Set bit 1 of object word 4 for any nonzero mode, clear it for zero,
//! preserving every other bit. Caller 0x083d9b20 enables this flag after
//! wide-character output. No deliberate behavioral deviations or callee
//! seams; aligned word indexing retains +0x10 on hosts without widening
//! the object's preceding target pointer words.

/// `buffer` must address at least five aligned, readable/writable u32 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wide_filebuf_set_write_mode(buffer: *mut u32, enabled: i32) {
    let flags = buffer.add(4);
    let previous = flags.read();
    flags.write(if enabled == 0 { previous & !2 } else { previous | 2 });
}

#[cfg(test)]
mod tests {
    use super::wide_filebuf_set_write_mode;

    #[test]
    fn full_word_truthiness_preserves_other_flags_and_storage() {
        for initial in [0, 2, 0xffff_ffff, 0xffff_fffd, 0x8000_0000, 0x1234_5678] {
            for mode in [0, 1, 2, 256, -1, i32::MIN, i32::MAX] {
                let mut words = [0xdead_beef; 9];
                words[4] = initial;
                unsafe { wide_filebuf_set_write_mode(words.as_mut_ptr(), mode); }
                let expected = (initial & !2) | if mode != 0 { 2 } else { 0 };
                assert_eq!(words[4], expected);
                for (index, word) in words.iter().enumerate() {
                    if index != 4 { assert_eq!(*word, 0xdead_beef); }
                }
            }
        }
    }

    #[test]
    fn repeated_modes_and_transitions_are_idempotent() {
        let mut words = [0, 0, 0, 0, 0xa5a5_5a5c];
        for (mode, expected) in [(1, 0xa5a5_5a5e), (-7, 0xa5a5_5a5e),
                                 (0, 0xa5a5_5a5c), (0, 0xa5a5_5a5c),
                                 (i32::MIN, 0xa5a5_5a5e)] {
            unsafe { wide_filebuf_set_write_mode(words.as_mut_ptr(), mode); }
            assert_eq!(words[4], expected);
        }
    }
}
