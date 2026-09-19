/// xor_index_key — original: `FUN_08093440` @ `0x08093440`
/// (40 bytes: 10 ARM words, `0x08093440..0x08093468`).
///
/// Raw words establish the next real function boundary at `0x08093468`
/// (`push {r3,r4,r5,r6,r7,r8,r9,lr}`). The body has zero outbound plain or
/// predicated `bl` instructions. A whole-image A32 decode finds four inbound
/// plain `bl` calls at `0x080af0e8`, `0x080af1fc`, `0x082d40c0`, and
/// `0x082d461c`; it finds no predicated `bl` forms targeting this address.
/// For each byte from zero through `len - 1`, it writes `src[index] ^
/// (index + 0x11)` to `dst[index]`, with the key reduced to a byte. Deliberate
/// deviation: none; this retains the stock forward traversal, including its
/// observable behavior for overlapping ranges.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xor_index_key(mut dst: *mut u8, mut src: *const u8, len: i32) {
    let mut index = 0i32;
    while index < len {
        dst.write(src.read() ^ (index as u8).wrapping_add(0x11));
        dst = dst.add(1);
        src = src.add(1);
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::xor_index_key;

    #[test]
    fn transforms_separate_ranges_across_byte_key_wrap() {
        let mut src = [0u8; 300];
        let mut dst = [0xffu8; 300];
        for (index, byte) in src.iter_mut().enumerate() {
            *byte = index as u8;
        }

        unsafe { xor_index_key(dst.as_mut_ptr(), src.as_ptr(), src.len() as i32) };

        for (index, byte) in dst.into_iter().enumerate() {
            assert_eq!(byte, (index as u8) ^ (index as u8).wrapping_add(0x11));
        }
    }

    #[test]
    fn zero_length_does_not_access_either_range() {
        unsafe { xor_index_key(core::ptr::null_mut(), core::ptr::null(), 0) };
    }

    #[test]
    fn negative_length_does_not_access_either_range() {
        unsafe { xor_index_key(core::ptr::null_mut(), core::ptr::null(), -1) };
    }

    #[test]
    fn overlapping_ranges_retain_forward_stock_traversal() {
        let mut actual = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut expected = actual;
        for index in 0..8 {
            expected[index + 2] = expected[index] ^ (index as u8).wrapping_add(0x11);
        }

        unsafe { xor_index_key(actual.as_mut_ptr().add(2), actual.as_ptr(), 8) };

        assert_eq!(actual, expected);
    }
}
