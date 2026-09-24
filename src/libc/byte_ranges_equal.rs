//! byte_ranges_equal — original: `thunk_FUN_0805d018` @ 0x0805d000 (40 bytes).
//!
//! Raw words establish a four-byte entry thunk (`b 0x0805d018`) followed by the
//! shared comparison loop at 0x0805d004..0x0805d024; 0x0805d028 is the next
//! independently linked function. Three unconditional `bl` callers and no
//! predicated `bl` callers target the thunk. The loop returns one when all
//! `len` bytes match and zero at the first mismatch; a zero length succeeds
//! without dereferencing either pointer. Deliberate deviation: volatile byte
//! reads prevent LLVM from replacing the loop with a libc comparison builtin.

/// Returns one if the two byte ranges are equal for exactly `len` bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn byte_ranges_equal(first: *const u8, second: *const u8, len: u32) -> u32 {
    let mut first = first;
    let mut second = second;
    let mut remaining = len;

    while remaining != 0 {
        if core::ptr::read_volatile(first) != core::ptr::read_volatile(second) {
            return 0;
        }
        first = first.add(1);
        second = second.add(1);
        remaining -= 1;
    }

    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|index| (index as u8).wrapping_mul(seed).wrapping_add(13)).collect()
    }

    #[test]
    fn matches_every_length_alignment_and_mismatch_position() {
        for len in 0..=64 {
            for first_alignment in 0..4 {
                for second_alignment in 0..4 {
                    let bytes = pattern(len, 17);
                    let mut first = Vec::new();
                    first.resize(len + first_alignment + 4, 0);
                    first[first_alignment..first_alignment + len].copy_from_slice(&bytes);
                    let mut second = Vec::new();
                    second.resize(len + second_alignment + 4, 0);
                    second[second_alignment..second_alignment + len].copy_from_slice(&bytes);
                    let first_range = unsafe { first.as_ptr().add(first_alignment) };
                    let second_range = unsafe { second.as_ptr().add(second_alignment) };

                    assert_eq!(unsafe { byte_ranges_equal(first_range, second_range, len as u32) }, 1);
                    for mismatch in 0..len {
                        second[second_alignment + mismatch] ^= 0xff;
                        assert_eq!(unsafe { byte_ranges_equal(first_range, second_range, len as u32) }, 0);
                        second[second_alignment + mismatch] ^= 0xff;
                    }
                }
            }
        }
    }

    #[test]
    fn zero_length_does_not_dereference_pointers() {
        assert_eq!(unsafe { byte_ranges_equal(core::ptr::null(), core::ptr::null(), 0) }, 1);
    }

    #[test]
    fn stops_at_the_first_mismatch() {
        let first = [1, 2, 3, 4];
        let second = [1, 9, 0, 4];
        assert_eq!(unsafe { byte_ranges_equal(first.as_ptr(), second.as_ptr(), 4) }, 0);
    }
}
