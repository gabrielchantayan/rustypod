//! byte_range_is_spaces — original: `thunk_FUN_082b3334` @ 0x082b332c.
//!
//! True extent: 56 bytes, 0x082b332c..0x082b3364 (next push prologue).
//! Two plain inbound BLs (0x082b7844, 0x082b7858), zero predicated inbound
//! BLs, and no outbound calls. The entry branches to the signed length test
//! at 0x082b3334; the decrement at 0x082b3330 belongs to the shared loop.
//! Scan backward for ASCII space (0x20), returning zero on the first other
//! byte. Zero length returns one; negative length returns zero without reads.
//! The caller compares common prefixes, then checks space-padded suffixes.
//! Deliberate deviation: volatile byte reads prevent libc loop substitution
//! and preserve backward early-exit access order; LLVM need not retain the
//! entry branch or the shared interior entry as a separately exported symbol.

/// Returns one exactly when `len` is nonnegative and all bytes are ASCII spaces.
///
/// For positive `len`, `bytes` must identify at least `len` readable bytes.
/// Nonpositive lengths do not access `bytes`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn byte_range_is_spaces(bytes: *const u8, len: i32) -> u32 {
    let mut remaining = len;
    while remaining > 0 {
        if core::ptr::read_volatile(bytes.add(remaining as usize - 1)) != b' ' {
            return 0;
        }
        remaining -= 1;
    }
    (remaining == 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonpositive_lengths_do_not_read() {
        for len in [i32::MIN, -1, 0] {
            assert_eq!(unsafe { byte_range_is_spaces(core::ptr::null(), len) },
                       (len == 0) as u32);
        }
    }

    #[test]
    fn lengths_alignments_and_every_mismatch_position() {
        let mut storage = [0xa5; 72];
        for alignment in 0..4 {
            for len in 0..=64 {
                storage.fill(0xa5);
                storage[alignment..alignment + len].fill(b' ');
                let bytes = unsafe { storage.as_ptr().add(alignment) };
                let reference = storage[alignment..alignment + len].iter().all(|&b| b == b' ');
                assert_eq!(unsafe { byte_range_is_spaces(bytes, len as i32) }, reference as u32);
                for mismatch in 0..len {
                    storage[alignment + mismatch] = 0;
                    assert_eq!(unsafe { byte_range_is_spaces(bytes, len as i32) }, 0);
                    storage[alignment + mismatch] = b' ';
                }
            }
        }
    }

    #[test]
    fn only_ascii_space_qualifies() {
        for byte in 0..=255u8 {
            let bytes = [b' ', byte, b' '];
            assert_eq!(unsafe { byte_range_is_spaces(bytes.as_ptr(), 3) },
                       (byte == b' ') as u32);
        }
    }
}
