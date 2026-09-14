//! swap_byte_ranges — original: `FUN_0809f728` @ 0x0809f728 (28 bytes).
//!
//! Raw osos.dec establishes the exact body from 0x0809f728 through `bx lr` at
//! 0x0809f740; the separately linked next function begins at 0x0809f744.
//! Decoding every aligned ARM B/BL-immediate word in osos.dec finds six direct
//! inbound calls: four unconditional `bl` at 0x080e8920, 0x080e89cc,
//! 0x080e89d8, and 0x080e8a14, plus two `blgt` calls at 0x080e8948 and
//! 0x080e8968. All occur in the partitioning sort at 0x080e88d0, which passes
//! a positive element width in r2; the predicated calls are gated by its
//! comparator result.
//!
//! Each iteration reads `*second` then `*first`, writes the saved second byte
//! to `*first`, writes the saved first byte to `*second`, and advances both
//! pointers. The bottom-tested ARM loop has no zero-length guard: `len == 0`
//! swaps one byte then wraps through 2^32 iterations. The port retains that
//! contract with wrapping subtraction, so callers must pass a nonzero length
//! and valid ranges for the complete execution. Volatile accesses prevent LLVM
//! from recognizing the loop as a bulk-memory intrinsic and preserve the
//! observed read/write order. Deliberate deviations: none.

/// Swaps `len` byte pairs in ascending-address order.
///
/// # Safety
/// `first` and `second` must each be valid for every access performed by the
/// hardware loop. In particular, `len` must be nonzero; zero executes 2^32
/// iterations after its initial byte swap. Ranges may overlap, with the exact
/// forward-order behavior retained.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.swap_byte_ranges"]
pub unsafe extern "C" fn swap_byte_ranges(mut first: *mut u8, mut second: *mut u8, mut len: u32) {
    loop {
        let second_byte = second.read_volatile();
        let first_byte = first.read_volatile();
        first.write_volatile(second_byte);
        second.write_volatile(first_byte);
        first = first.add(1);
        second = second.add(1);
        len = len.wrapping_sub(1);
        if len == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent model of the ordered byte loads and stores in the ARM loop.
    fn reference(bytes: &mut [u8], first: usize, second: usize, len: usize) {
        for index in 0..len {
            let second_byte = bytes[second + index];
            let first_byte = bytes[first + index];
            bytes[first + index] = second_byte;
            bytes[second + index] = first_byte;
        }
    }

    #[test]
    fn swaps_every_positive_length_without_touching_guards() {
        const MAX_LEN: usize = 64;
        for len in 1..=MAX_LEN {
            let mut bytes = [0xa5u8; MAX_LEN * 2 + 12];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
            }
            let mut expected = bytes;
            reference(&mut expected, 3, MAX_LEN + 6, len);

            unsafe { swap_byte_ranges(bytes.as_mut_ptr().add(3), bytes.as_mut_ptr().add(MAX_LEN + 6), len as u32) };

            assert_eq!(bytes, expected, "len={len}");
        }
    }

    #[test]
    fn overlap_keeps_hardware_read_write_order() {
        let mut bytes = [0u8, 1, 2, 3, 4, 5, 6, 7, 8];
        let mut expected = bytes;
        reference(&mut expected, 1, 3, 5);

        unsafe { swap_byte_ranges(bytes.as_mut_ptr().add(1), bytes.as_mut_ptr().add(3), 5) };

        assert_eq!(bytes, expected);
        assert_eq!(bytes, [0, 3, 4, 5, 6, 7, 2, 1, 8]);
    }

    #[test]
    fn identical_ranges_remain_unchanged() {
        let mut bytes = [0x3cu8, 0x20, 0x00, 0xff, 0x91];
        let expected = bytes;

        unsafe { swap_byte_ranges(bytes.as_mut_ptr(), bytes.as_mut_ptr(), bytes.len() as u32) };

        assert_eq!(bytes, expected);
    }
}
