//! Forward XOR-22 lookup-table decoding.
//!
//! `xor_22_copy` — `FUN_0800f17c` @ 0x0800f17c, 48 executable bytes
//! [0x0800f17c, 0x0800f1ac). Two plain inbound BLs (0x0800c9a8,
//! 0x0800cee0), zero predicated inbound BLs, zero outgoing calls, verified
//! by scanning aligned raw A32 words. The next independently called entry is
//! 0x0800f1b4; the intervening words 0xa7ae8400 and 0x6d85d450 are not
//! executed by this function.
//!
//! Copy bytes in increasing index order, XORing each with 0x22, while the
//! signed index is less than `len`. Non-positive lengths access no memory.
//! Both callers decode 256-byte lookup tables before marking them initialized.
//! Raw code always returns zero in r0, although Ghidra declares it void.
//! Deliberate deviations: none in behavior; volatile byte accesses retain
//! immediate load/store ordering for overlapping ranges and avoid widening.

/// # Safety
/// For positive `len`, `src` and `dst` must be valid for `len` readable and
/// writable bytes respectively. Overlap is allowed and processed forwards.
/// For non-positive `len`, neither pointer needs to be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.xor_22_copy"]
pub unsafe extern "C" fn xor_22_copy(src: *const u8, dst: *mut u8, len: i32) -> u32 {
    let mut index = 0i32;
    while index < len {
        let byte = src.add(index as usize).read_volatile();
        dst.add(index as usize).write_volatile(byte ^ 0x22);
        index += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::xor_22_copy;

    #[test]
    fn copies_all_byte_values_and_preserves_range_boundaries() {
        let mut src = [0u8; 264];
        for (index, byte) in src.iter_mut().enumerate() {
            *byte = index as u8;
        }
        for src_offset in 0..4 {
            for dst_offset in 0..4 {
                for len in [0usize, 1, 2, 3, 4, 63, 64, 255, 256] {
                    let mut actual = [0xa5u8; 264];
                    let mut expected = actual;
                    for index in 0..len {
                        expected[dst_offset + index] = src[src_offset + index] ^ 0x22;
                    }
                    let result = unsafe {
                        xor_22_copy(src.as_ptr().add(src_offset),
                                    actual.as_mut_ptr().add(dst_offset), len as i32)
                    };
                    assert_eq!(result, 0);
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn overlap_observes_prior_forward_writes() {
        for (src_offset, dst_offset) in [(0, 0), (0, 1), (0, 3), (1, 0), (3, 0)] {
            for len in 1..=64 {
                let mut actual = [0u8; 72];
                for (index, byte) in actual.iter_mut().enumerate() {
                    *byte = (index as u8).wrapping_mul(37);
                }
                let mut expected = actual;
                for index in 0..len {
                    expected[dst_offset + index] = expected[src_offset + index] ^ 0x22;
                }
                unsafe {
                    let ptr = actual.as_mut_ptr();
                    assert_eq!(xor_22_copy(ptr.add(src_offset), ptr.add(dst_offset), len as i32), 0);
                }
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn non_positive_lengths_do_not_access_pointers() {
        for len in [i32::MIN, -256, -1, 0] {
            assert_eq!(unsafe { xor_22_copy(core::ptr::null(), core::ptr::null_mut(), len) }, 0);
            let mut byte = 0x7bu8;
            assert_eq!(unsafe { xor_22_copy(&byte, &mut byte, len) }, 0);
            assert_eq!(byte, 0x7b);
        }
    }
}
