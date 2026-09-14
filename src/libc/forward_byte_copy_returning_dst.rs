//! forward_byte_copy_returning_dst — original: `FUN_080571ec` @ 0x080571ec (36 bytes).
//!
//! Raw `osos.dec` extent is exactly nine ARM words from 0x080571ec through
//! 0x0805720c (`pop {pc}`); the separately linked next function starts at
//! 0x08057210. Decoding every ARM `B`/`BL` immediate finds six direct `BL`
//! sites: four unconditional (`0x08056b9c`, `0x08056c14`, `0x080e6f54`, and
//! `0x080e7048`) plus `blne` at `0x08056bb0` and `blgt` at `0x08056c28`.
//! There are no direct `B` sites.
//!
//! The ARM body preserves `r0` as its return value, uses `r3` as the advancing
//! destination cursor, and copies `len` bytes in ascending address order.
//! Thus zero length dereferences neither pointer and overlap deliberately has
//! forward propagation rather than `memmove` behavior.
//!
//! Deviation: volatile byte accesses prevent LLVM's loop-idiom pass from
//! replacing this separately linked retail leaf with a memcpy intrinsic. The
//! target-only unique text section prevents identical-code folding with other
//! forward byte-copy ports.

/// Copies `len` bytes from `src` to `dst` in ascending address order, returning `dst`.
///
/// # Safety
/// For nonzero `len`, both ranges must be valid for `len` bytes. The ranges may
/// overlap, with the original's forward-copy semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.forward_byte_copy_returning_dst_080571ec")]
#[inline(never)]
pub unsafe extern "C" fn forward_byte_copy_returning_dst(
    mut dst: *mut u8,
    mut src: *const u8,
    mut len: u32,
) -> *mut u8 {
    let returned_dst = dst;
    while len != 0 {
        dst.write_volatile(src.read_volatile());
        dst = dst.add(1);
        src = src.add(1);
        len -= 1;
    }
    returned_dst
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_all_lengths_and_alignments_and_returns_destination() {
        const LEN: usize = 64;
        let mut src = [0u8; LEN + 8];
        for (index, byte) in src.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }

        for src_offset in 0..4 {
            for dst_offset in 0..4 {
                for len in 0..=LEN {
                    let mut dst = [0xa5u8; LEN + 8];
                    let destination = unsafe { dst.as_mut_ptr().add(4 + dst_offset) };
                    let source = unsafe { src.as_ptr().add(4 + src_offset) };
                    let returned = unsafe {
                        forward_byte_copy_returning_dst(destination, source, len as u32)
                    };

                    assert_eq!(returned, destination, "return, src={src_offset}, dst={dst_offset}, len={len}");
                    assert_eq!(
                        &dst[4 + dst_offset..4 + dst_offset + len],
                        &src[4 + src_offset..4 + src_offset + len],
                        "copied bytes, src={src_offset}, dst={dst_offset}, len={len}"
                    );
                    assert!(
                        dst[..4 + dst_offset].iter().all(|&byte| byte == 0xa5)
                            && dst[4 + dst_offset + len..].iter().all(|&byte| byte == 0xa5),
                        "guards, src={src_offset}, dst={dst_offset}, len={len}"
                    );
                }
            }
        }
    }

    #[test]
    fn overlap_retains_forward_propagation_and_returns_destination() {
        let mut bytes = [1u8, 2, 3, 4, 5, 6, 7];
        let destination = unsafe { bytes.as_mut_ptr().add(2) };
        let returned = unsafe { forward_byte_copy_returning_dst(destination, bytes.as_ptr(), 5) };
        assert_eq!(returned, destination);
        assert_eq!(bytes, [1, 2, 1, 2, 1, 2, 1]);
    }

    #[test]
    fn zero_length_returns_destination_without_dereferencing_pointers() {
        let returned = unsafe {
            forward_byte_copy_returning_dst(core::ptr::null_mut(), core::ptr::null(), 0)
        };
        assert!(returned.is_null());
    }
}
