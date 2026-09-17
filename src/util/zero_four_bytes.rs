//! A fixed-width four-byte zeroing helper.

/// `zero_four_bytes` — original: `FUN_0824bf74` @ **0x0824bf74** (**24 bytes
/// exactly**, `0x0824bf74..0x0824bf8b`; `0x0824bf8c` opens the distinct
/// four-byte-copy sibling).
///
/// Decoding the raw words in `osos.dec` establishes the six-instruction body:
/// `mov r1,#0`, then ordered `strb` stores at `dst + 3`, `+2`, `+1`, and `+0`,
/// followed by `bx lr`. Decoding all A32 branch-with-link words verifies four
/// direct inbound plain unconditional `bl` calls and no predicated BL calls.
/// The helper clears four bytes in descending offset order and preserves the
/// destination in r0.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `dst` must be valid and writable for four `u8`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn zero_four_bytes(dst: *mut u8) -> *mut u8 {
    dst.add(3).write(0);
    dst.add(2).write(0);
    dst.add(1).write(0);
    dst.write(0);
    dst
}

#[cfg(test)]
mod tests {
    use super::zero_four_bytes;

    #[test]
    fn zeroes_only_four_adjacent_bytes_and_returns_destination() {
        let mut bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let dst = unsafe { bytes.as_mut_ptr().add(1) };

        let returned = unsafe { zero_four_bytes(dst) };

        assert_eq!(returned, dst);
        assert_eq!(bytes, [0x11, 0, 0, 0, 0, 0x66]);
    }

    #[test]
    fn accepts_an_unaligned_destination() {
        let mut bytes = [0xff; 9];

        unsafe { zero_four_bytes(bytes.as_mut_ptr().add(3)) };

        assert_eq!(bytes, [0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff]);
    }
}
