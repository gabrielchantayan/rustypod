//! Forward row permutation for the proprietary AES-like block cipher.
//!
//! FUN_0802e190 @ 0x0802e190; true extent [0x0802e190, 0x0802e1f4),
//! 100 bytes (25 A32 instructions), ending in BX LR before InvShiftRows.
//! Full-image raw decoding verifies two incoming plain BLs at 0x0802e5f8
//! and 0x0802e630, zero incoming predicated BLs, and zero outgoing calls.
//! The encrypt-block caller transposes its input into four contiguous rows.
//! Leave row zero unchanged; rotate rows one, two, and three left by
//! one, two, and three bytes respectively, in place.
//!
//! Deviations: none in the memory permutation or C ABI. LLVM may reorder
//! ordinary byte accesses; this is writable RAM, not an MMIO operation.

/// Rotate the cipher's rows on a contiguous 16-byte state.
///
/// # Safety
/// `state` must point to 16 initialized, writable bytes. No alignment beyond
/// byte alignment is required; no bytes outside that state are accessed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn block_shift_rows(state: *mut u8) {
    let s = |i: usize| state.add(i);
    let b4 = s(4).read();
    s(4).write(s(5).read());
    s(5).write(s(6).read());
    s(6).write(s(7).read());
    s(7).write(b4);
    let b8 = s(8).read();
    s(8).write(s(10).read());
    s(10).write(b8);
    let b9 = s(9).read();
    s(9).write(s(11).read());
    s(11).write(b9);
    let b12 = s(12).read();
    s(12).write(s(15).read());
    let b14 = s(14).read();
    s(15).write(b14);
    s(14).write(s(13).read());
    s(13).write(b12);
}

#[cfg(test)]
mod tests {
    use super::block_shift_rows;
    use crate::crypto::block_inv_shift_rows::block_inv_shift_rows;

    #[test]
    fn forward_permutation_all_byte_values_and_alignments() {
        for offset in 0..4 {
            for seed in 0..=255u8 {
                let mut storage = [0xa5u8; 24];
                let start = 4 + offset;
                let input: [u8; 16] = core::array::from_fn(|i| seed.wrapping_add(i as u8));
                storage[start..start + 16].copy_from_slice(&input);
                let mut expected = storage;
                for row in 0..4 {
                    for column in 0..4 {
                        expected[start + row * 4 + column] = input[row * 4 + (column + row) % 4];
                    }
                }
                unsafe { block_shift_rows(storage.as_mut_ptr().add(start)) };
                assert_eq!(storage, expected, "offset={offset}, seed={seed}");
            }
        }
    }

    #[test]
    fn isolated_byte_permutation_and_inverse_roundtrips() {
        for position in 0..16 {
            let mut input = [0u8; 16];
            input[position] = 0xff;
            let mut state = input;
            unsafe { block_shift_rows(state.as_mut_ptr()) };
            let row = position / 4;
            let destination = row * 4 + (position % 4 + 4 - row) % 4;
            let mut expected = [0u8; 16];
            expected[destination] = 0xff;
            assert_eq!(state, expected);
            unsafe { block_inv_shift_rows(state.as_mut_ptr()) };
            assert_eq!(state, input);
            unsafe {
                block_inv_shift_rows(state.as_mut_ptr());
                block_shift_rows(state.as_mut_ptr());
            }
            assert_eq!(state, input);
        }
    }
}
