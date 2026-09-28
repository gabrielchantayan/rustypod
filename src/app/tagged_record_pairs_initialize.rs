//! `tagged_record_pairs_initialize` — original: `FUN_08391d3c` @ `0x08391d3c`.
//!
//! The raw 36-byte A32 body (`0x08391d3c..0x08391d60`) loads the fixed tag
//! `0x5da35da3`, then writes it and a zero word to each complete eight-byte
//! record in the supplied byte span. The next real function starts at
//! `0x08391d64`; `0x08391d60` is the tag literal, not code.
//!
//! **2 direct `bl` call sites, both unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `osos.dec`: 0x08393c08 and
//! 0x08393ccc. The function has no outbound calls. Deliberate deviation: none;
//! `byte_len >> 3` and the two aligned word stores per complete record are
//! preserved exactly.

/// Initializes each complete eight-byte record in a byte span with the retailOS tag
/// and a cleared trailing word.
///
/// # Safety
///
/// `records` must be valid and aligned for `(byte_len >> 3) * 2` `u32` writes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_record_pairs_initialize(records: *mut u32, byte_len: u32) {
    const TAG: u32 = 0x5da3_5da3;

    for index in 0..(byte_len >> 3) as usize {
        let record = records.add(index * 2);
        record.write(TAG);
        record.add(1).write(0);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::tagged_record_pairs_initialize;

    #[test]
    fn ignores_spans_shorter_than_one_complete_record() {
        for byte_len in 0..8 {
            let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];

            unsafe { tagged_record_pairs_initialize(words.as_mut_ptr(), byte_len) };

            assert_eq!(words, [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444]);
        }
    }

    #[test]
    fn initializes_complete_pairs_without_touching_adjacent_words() {
        let mut words = [0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc, 0xdddd_dddd, 0xeeee_eeee, 0xffff_ffff];

        unsafe { tagged_record_pairs_initialize(words.as_mut_ptr().add(1), 23) };

        assert_eq!(
            words,
            [0xaaaa_aaaa, 0x5da3_5da3, 0, 0x5da3_5da3, 0, 0xffff_ffff]
        );
    }
}
