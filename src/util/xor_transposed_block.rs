//! A fixed-width transposed 4×4 byte-block XOR helper.

/// xor_transposed_4x4 — original: `FUN_0802e54c` @ 0x0802e54c (32 bytes).
///
/// For every row `i` and column `j` of a 4×4 byte block, XORs
/// `dst[4 * i + j]` with the transposed source element `src[i + 4 * j]`.
/// The source byte is read before the destination byte and each result is
/// stored immediately, preserving the retail function's ordered load/store
/// behavior when the two 16-byte ranges overlap (including in-place use).
///
/// Deviations: none.
///
/// # Safety
/// `dst` must be valid for 16 `u8` writes and `src` for 16 `u8` reads. Their
/// ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xor_transposed_4x4(dst: *mut u8, src: *const u8) {
    for row in 0..4 {
        for column in 0..4 {
            let source = src.add(row + 4 * column).read();
            let destination = dst.add(4 * row + column);
            destination.write(destination.read() ^ source);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::xor_transposed_4x4;

    /// Model the original's per-element source load, destination load, then
    /// destination store sequence, including its effects on overlapping spans.
    fn reference_xor_transposed_4x4(bytes: &mut [u8], dst: usize, src: usize) {
        for row in 0..4 {
            for column in 0..4 {
                let source = bytes[src + row + 4 * column];
                let destination = dst + 4 * row + column;
                bytes[destination] ^= source;
            }
        }
    }

    #[test]
    fn xors_each_destination_matrix_cell_with_its_transposed_source_cell_only() {
        let source = [
            0x10, 0x21, 0x32, 0x43, // source row 0
            0x54, 0x65, 0x76, 0x87, // source row 1
            0x98, 0xa9, 0xba, 0xcb, // source row 2
            0xdc, 0xed, 0xfe, 0x0f, // source row 3
        ];
        let original_destination = [
            0x01, 0x02, 0x04, 0x08, 0x11, 0x12, 0x14, 0x18, 0x21, 0x22, 0x24, 0x28, 0x31,
            0x32, 0x34, 0x38,
        ];
        let mut destination = [0xa5; 24];
        destination[4..20].copy_from_slice(&original_destination);

        unsafe { xor_transposed_4x4(destination[4..20].as_mut_ptr(), source.as_ptr()) };

        for row in 0..4 {
            for column in 0..4 {
                let index = 4 * row + column;
                assert_eq!(
                    destination[4 + index],
                    original_destination[index] ^ source[row + 4 * column],
                    "destination[{index}] must use source[{}]",
                    row + 4 * column
                );
            }
        }
        assert_eq!(&destination[..4], &[0xa5; 4], "leading guard unchanged");
        assert_eq!(&destination[20..], &[0xa5; 4], "trailing guard unchanged");
        assert_eq!(source, [0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f]);
    }

    #[test]
    fn in_place_operation_observes_each_prior_store_in_row_major_order() {
        let initial = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98,
            0xba, 0xdc, 0xfe,
        ];
        let mut expected = [0; 16];
        let mut actual = initial;
        expected.copy_from_slice(&initial);
        reference_xor_transposed_4x4(&mut expected, 0, 0);

        unsafe { xor_transposed_4x4(actual.as_mut_ptr(), actual.as_ptr()) };

        assert_eq!(actual, expected);
    }
}
