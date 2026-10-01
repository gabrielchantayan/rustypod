//! Optional four-word record equality — `FUN_0829fd50` @ `0x0829fd50`.
//! True extent: 92 bytes, through `bx lr` at `0x0829fda8`; the next real
//! function begins with `push {r4, r5, r6, lr}` at `0x0829fdac`.
//! Raw aligned ARM-word decoding verifies two unconditional incoming BLs
//! (0x0829fcb8, 0x0829ff00), zero predicated incoming BLs, and zero outgoing
//! plain or predicated BLs. Ghidra's additional caller at 0x0829fefc is an
//! interior fragment of the caller beginning at 0x0829fea0.
//!
//! Compares the byte at +0, returning 0 on mismatch and 1 when both are zero.
//! Otherwise compares the four u32 fields at +4, +8, +12, +16 in order,
//! stopping at the first mismatch. Bytes +1..+3 are padding, not compared.
//! Callers pass embedded records at object +0x68; domain identity is unproven.
//! Deliberate deviations: none. Volatile reads preserve conditional access;
//! aligned u32 loads preserve target word layout on both ARM and the host.

/// # Safety
/// Both pointers must be readable for the first byte. If that byte is equal
/// and nonzero, both must be four-byte aligned and readable through the first
/// mismatching word, or all 20 bytes when equal. No NULL guard is provided.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn optional_four_word_record_equal(left: *const u8, right: *const u8) -> u32 {
    let left_present = left.read_volatile();
    let right_present = right.read_volatile();
    if left_present != right_present {
        return 0;
    }
    if left_present == 0 {
        return 1;
    }
    for index in 1..=4 {
        let left_word = left.cast::<u32>().add(index).read_volatile();
        let right_word = right.cast::<u32>().add(index).read_volatile();
        if left_word != right_word {
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::optional_four_word_record_equal;
    extern crate std;

    fn compare(left: &[u32], right: &[u32]) -> u32 {
        unsafe { optional_four_word_record_equal(left.as_ptr().cast(), right.as_ptr().cast()) }
    }

    #[test]
    fn presence_byte_is_exact_and_absent_payload_is_ignored() {
        for left in [0u8, 1, 0x80, 0xff] {
            for right in [0u8, 1, 0x80, 0xff] {
                if left == right && left != 0 { continue; }
                assert_eq!(unsafe { optional_four_word_record_equal(&left, &right) },
                    u32::from(left == right));
            }
        }
        assert_eq!(compare(&[0xffff_ff00, 1, 2, 3, 4], &[0, 5, 6, 7, 8]), 1);
    }

    #[test]
    fn compares_all_payload_bits_but_ignores_padding_and_trailing_words() {
        for present in [1u32, 0x80, 0xff] {
            let left = [present | 0xa5a5_a500, 0, 0x8000_0000, 0xffff_ffff, 0x1234_5678, 1];
            let mut right = left;
            right[0] = present | 0x5a5a_5a00;
            right[5] = 2;
            assert_eq!(compare(&left, &right), 1);
            assert_eq!(compare(&left, &left), 1);
            for index in 1..=4 {
                for bit in 0..32 {
                    right[index] ^= 1 << bit;
                    assert_eq!(compare(&left, &right), 0);
                    assert_eq!(compare(&right, &left), 0);
                    right[index] ^= 1 << bit;
                }
            }
        }
    }

    #[test]
    fn stops_before_unreadable_payload_suffix() {
        for index in 1..=4 {
            let left = std::vec![1u32; index + 1];
            let mut right = left.clone();
            right[index] = 2;
            assert_eq!(compare(&left, &right), 0);
        }
    }
}
