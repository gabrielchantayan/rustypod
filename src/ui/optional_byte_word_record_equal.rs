//! Optional byte/word record equality — `FUN_0829f8b8` @ `0x0829f8b8`.
//! True extent: 68 bytes through `bx lr` at 0x0829f8f8; the next real
//! function begins at 0x0829f8fc with independent presence-byte loads.
//! Raw aligned ARM-word decoding verifies two plain incoming BLs
//! (0x0829fc90, 0x0829fe38), zero predicated incoming BLs, and zero
//! outgoing BLs of either kind.
//!
//! Compare presence bytes exactly; unequal bytes return 0 and equal zero
//! bytes return 1 without reading payload. Otherwise compare signed byte
//! +1, then the aligned u32 at +4 only if +1 matches. Padding +2/+3 is
//! ignored. Both callers pass record +0x84; domain identity is unproven.
//! Deliberate deviation: volatile reads preserve conditional access rather
//! than allowing speculative or wider loads. The +4 value is not dereferenced.

/// # Safety
/// Both pointers must be readable at +0. Equal nonzero presence bytes
/// require readable +1 bytes; matching +1 bytes additionally require a
/// readable, four-byte-aligned u32 at +4. No NULL guard is provided.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn optional_byte_word_record_equal(left: *const u8, right: *const u8) -> u32 {
    let left_present = left.read_volatile();
    let right_present = right.read_volatile();
    if left_present != right_present {
        return 0;
    }
    if left_present == 0 {
        return 1;
    }
    if (left.add(1).read_volatile() as i8) != (right.add(1).read_volatile() as i8) {
        return 0;
    }
    u32::from(left.add(4).cast::<u32>().read_volatile()
        == right.add(4).cast::<u32>().read_volatile())
}

#[cfg(test)]
mod tests {
    use super::optional_byte_word_record_equal;

    fn compare(left: &[u32], right: &[u32]) -> u32 {
        unsafe { optional_byte_word_record_equal(left.as_ptr().cast(), right.as_ptr().cast()) }
    }

    #[test]
    fn exact_presence_gates_payload_access() {
        for left in 0..=255u8 {
            for right in 0..=255u8 {
                if left == right && left != 0 { continue; }
                assert_eq!(unsafe { optional_byte_word_record_equal(&left, &right) },
                    u32::from(left == right));
            }
        }
        assert_eq!(compare(&[0xffff_ff00, 0], &[0, 0xffff_ffff]), 1);
    }

    #[test]
    fn signed_byte_mismatch_does_not_require_word() {
        for left in 0..=255u8 {
            for right in 0..=255u8 {
                if left == right { continue; }
                assert_eq!(unsafe { optional_byte_word_record_equal(
                    [0xff, left].as_ptr(), [0xff, right].as_ptr()) }, 0);
            }
        }
    }

    #[test]
    fn compares_payload_and_ignores_padding_and_suffix() {
        for present in [1u32, 0x80, 0xff] {
            for byte in 0..=255u32 {
                for word in [0, 1, 0x8000_0000, 0xffff_ffff] {
                    let left = [present | (byte << 8), word, 0];
                    let right = [left[0] | 0xffff_0000, word, 0xffff_ffff];
                    assert_eq!(compare(&left, &right), 1);
                    assert_eq!(compare(&left, &left), 1);
                    for bit in 0..32 {
                        let different = [right[0], word ^ (1 << bit), right[2]];
                        assert_eq!(compare(&left, &different), 0);
                        assert_eq!(compare(&different, &left), 0);
                    }
                }
            }
        }
    }
}
