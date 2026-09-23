//! `record_kind_is_six_or_seven` — original: `FUN_08132658` @ 0x08132658
//! (24 bytes).
//!
//! Raw A32 establishes the exact extent 0x08132658..0x0813266f: `ldrb
//! r0,[r0,#0x1a]`, compare against 7 and, if unequal, 6, then return one or
//! zero. The next independently linked body begins at 0x08132670. The body
//! contains no BL instructions; whole-image branch-immediate decoding finds
//! three inbound plain BL calls (0x081323d8, 0x08132a84, 0x08132da8) and zero
//! predicated BL calls. The meaning of the containing record and its kind
//! values is unrecovered, so the name deliberately preserves only the tested
//! field and values. Deliberate deviation: LLVM lowers the equivalent
//! membership test to a mask/subtract/CLZ sequence rather than the firmware's
//! conditional compares.

/// Returns one when the byte at `record + 0x1a` is kind 6 or 7, otherwise zero.
///
/// # Safety
///
/// `record` must point to at least 27 readable bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_kind_is_six_or_seven(record: *const u8) -> u32 {
    (matches!(*record.add(0x1a), 6 | 7)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_six_and_seven_at_the_target_offset() {
        for (kind, expected) in [(0u8, 0), (5, 0), (6, 1), (7, 1), (8, 0), (u8::MAX, 0)] {
            let mut record = [0xa5u8; 0x1b];
            record[0x1a] = kind;
            assert_eq!(unsafe { record_kind_is_six_or_seven(record.as_ptr()) }, expected, "{kind}");
        }
    }

    #[test]
    fn ignores_bytes_outside_the_kind_field() {
        let mut record = [0u8; 0x1b];
        record[0x1a] = 6;
        record[0] = 7;
        record[0x19] = 7;
        assert_eq!(unsafe { record_kind_is_six_or_seven(record.as_ptr()) }, 1);
        record[0x1a] = 0;
        assert_eq!(unsafe { record_kind_is_six_or_seven(record.as_ptr()) }, 0);
    }
}
