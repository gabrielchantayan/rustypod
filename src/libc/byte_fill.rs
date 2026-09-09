//! byte_fill — original: `FUN_082e2ef0` at load address `0x082e2ef0`
//! (20 bytes).
//!
//! Raw bytes establish the exact extent: the next distinct function begins
//! at `0x082e2f04` with `push {r4, r5, r6, lr}`. Decoding every ARM B/BL word
//! in `osos.dec` finds 13 direct `bl` callers, all unconditional; there are
//! zero predicated `bl` callers. The `bne` at `0x082e2efc` is this function's
//! loop back-edge, not a call site.
//!
//! The leaf pre-decrements its 32-bit length, stops when it reaches -1, and
//! otherwise stores `value` as a byte through post-incremented `dst`. Thus a
//! zero length does not dereference `dst`, and the r0 result is the end
//! pointer (`dst + len`). Ghidra declares the function `void`, but raw ARM
//! leaves that advanced pointer in r0; the port exposes it.
//!
//! Deliberate deviations: none. Volatile stores only prevent LLVM from
//! replacing the byte loop with an unavailable freestanding memset libcall.

/// Fill `len` bytes at `dst` with the low byte of `value`, returning `dst + len`.
///
/// # Safety
/// `dst` must be valid and writable for `len` bytes unless `len` is zero.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.byte_fill")]
pub unsafe extern "C" fn byte_fill(mut dst: *mut u8, mut len: u32, value: u8) -> *mut u8 {
    while len != 0 {
        dst.write_volatile(value);
        dst = dst.add(1);
        len -= 1;
    }
    dst
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_fill(bytes: &mut [u8], value: u8, len: usize) {
        for byte in &mut bytes[..len] {
            *byte = value;
        }
    }

    #[test]
    fn fills_every_alignment_and_length_without_overwriting_guards() {
        const MAX_LEN: usize = 64;
        for value in [0, 1, 0x7f, 0x80, 0xff] {
            for offset in 0..4 {
                for len in 0..=MAX_LEN {
                    let mut actual = [0xa5u8; MAX_LEN + 8];
                    let mut expected = actual;
                    let dst = unsafe { actual.as_mut_ptr().add(offset) };
                    let end = unsafe { byte_fill(dst, len as u32, value) };
                    reference_fill(&mut expected[offset..], value, len);
                    assert_eq!(actual, expected, "value={value:#x}, offset={offset}, len={len}");
                    assert_eq!(end, unsafe { dst.add(len) }, "end pointer, len={len}");
                }
            }
        }
    }

    #[test]
    fn zero_length_dereferences_neither_pointer_nor_writes() {
        assert_eq!(unsafe { byte_fill(core::ptr::null_mut(), 0, 0x42) }, core::ptr::null_mut());
    }
}
