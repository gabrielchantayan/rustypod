//! Wide file-buffer ownership flag setter.
//!
//! Original: 0x083da7b4, 24 bytes, extent [0x083da7b4, 0x083da7cc).
//! Verified whole-image raw A32 calls: one incoming plain BL (0x083d9ac0),
//! zero predicated BLs and zero outgoing BLs. The next independent function
//! sets bit 1. MOVS r2,r1; LDR r1,[r0,#16]; BICEQ/ORRNE r1,r1,#1;
//! STR r1,[r0,#16]; MOV pc,lr.
//!
//! Set bit 0 of object word 4 for any nonzero enabled value, clear it for
//! zero, preserving every other bit. Caller 0x083d9a64 sets ownership when
//! allocating a wide-character buffer and frees the previous buffer only
//! when its old ownership bit was set. No deliberate behavioral deviations
//! or callee seams; aligned word indexing preserves +0x10 on hosts without
//! widening the object's preceding target pointer words.

/// `buffer` must address at least five aligned, readable/writable u32 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wide_filebuf_set_owned(buffer: *mut u32, enabled: i32) {
    let flags = buffer.add(4);
    let previous = flags.read();
    flags.write(if enabled == 0 { previous & !1 } else { previous | 1 });
}

#[cfg(test)]
mod tests {
    use super::wide_filebuf_set_owned;

    #[test]
    fn full_word_truthiness_preserves_other_flags_and_storage() {
        for initial in [0, 1, 0xffff_ffff, 0xffff_fffe, 0x8000_0000, 0x1234_5678] {
            for enabled in [0, 1, 2, 256, -1, i32::MIN, i32::MAX] {
                let mut words = [0xdead_beef; 9];
                words[4] = initial;
                unsafe { wide_filebuf_set_owned(words.as_mut_ptr(), enabled); }
                let expected = (initial & !1) | u32::from(enabled != 0);
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
        for (enabled, expected) in [(1, 0xa5a5_5a5d), (-7, 0xa5a5_5a5d),
                                    (0, 0xa5a5_5a5c), (0, 0xa5a5_5a5c),
                                    (i32::MIN, 0xa5a5_5a5d)] {
            unsafe { wide_filebuf_set_owned(words.as_mut_ptr(), enabled); }
            assert_eq!(words[4], expected);
        }
    }
}
