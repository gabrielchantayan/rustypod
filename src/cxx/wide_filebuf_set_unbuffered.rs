//! Wide file-buffer unbuffered-mode flag setter.
//!
//! Original: 0x083da7e4, 24 bytes, extent [0x083da7e4, 0x083da7fc).
//! Verified raw A32 calls: one incoming plain BL (0x083d9af8), zero
//! predicated BLs; zero outgoing BLs. The next function starts with PUSH.
//! MOVS r2,r1; LDR r1,[r0,#16]; BICEQ/ORRNE r1,r1,#4;
//! STR r1,[r0,#16]; MOV pc,lr.
//!
//! Set bit 2 of object word 4 for any nonzero mode, clear it for zero,
//! preserving all other flags. Caller 0x083d9a64 sets this mode when
//! configuring a null buffer with a nonpositive capacity. No deliberate
//! behavioral deviations; word indexing preserves the +0x10 target offset
//! on hosts without assuming host pointer fields are four bytes wide.

/// `buffer` must address at least five aligned, readable/writable u32 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wide_filebuf_set_unbuffered(buffer: *mut u32, enabled: i32) {
    let flags = buffer.add(4);
    let previous = flags.read();
    flags.write(if enabled == 0 { previous & !4 } else { previous | 4 });
}

#[cfg(test)]
mod tests {
    use super::wide_filebuf_set_unbuffered;

    #[test]
    fn mode_truthiness_preserves_other_bits_and_neighboring_words() {
        for initial in [0, 4, 0xffff_ffff, 0xffff_fffb, 0x8000_0000, 0x1234_5678] {
            for mode in [0, 1, -1, i32::MIN, i32::MAX, 4] {
                let mut words = [0xdead_beef; 11];
                words[4] = initial;
                unsafe { wide_filebuf_set_unbuffered(words.as_mut_ptr(), mode); }
                let expected = (initial & !4) | if mode != 0 { 4 } else { 0 };
                assert_eq!(words[4], expected);
                for (index, word) in words.iter().enumerate() {
                    if index != 4 { assert_eq!(*word, 0xdead_beef); }
                }
            }
        }
    }

    #[test]
    fn repeated_modes_and_transitions_are_idempotent() {
        let mut words = [0, 0, 0, 0, 0xa5a5_5a5a];
        for (mode, expected) in [(1, 0xa5a5_5a5e), (-7, 0xa5a5_5a5e),
                                 (0, 0xa5a5_5a5a), (0, 0xa5a5_5a5a),
                                 (i32::MIN, 0xa5a5_5a5e)] {
            unsafe { wide_filebuf_set_unbuffered(words.as_mut_ptr(), mode); }
            assert_eq!(words[4], expected);
        }
    }
}
