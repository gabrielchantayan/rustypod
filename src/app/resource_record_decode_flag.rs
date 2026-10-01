//! `resource_record_decode_flag` — original `FUN_082a1eac` at
//! `0x082a1eac` (8 bytes, `0x082a1eac..0x082a1eb4`; the next real
//! function starts at `0x082a1eb4`). Raw words are `e5d00018` (`ldrb
//! r0,[r0,#0x18]`) and `e12fff1e` (`bx lr`). Whole-image aligned ARM
//! decoding verifies two inbound plain BLs (`0x081043d8`, `0x08104850`),
//! zero predicated inbound BLs, and no outbound calls.
//!
//! Return the unsigned byte at resource record offset +0x18 unchanged.
//! Callers `FUN_08104294` and `FUN_0810453c` test zero/nonzero to gate
//! payload decoding through `FUN_082d74c0`, using the record's decode
//! parameter at +0x0c. The precise format and flag encoding are unknown.
//!
//! Deliberate deviations: none. No boolean normalization, null guard,
//! or callee seams.

const DECODE_FLAG_OFFSET: usize = 0x18;

/// Returns the resource record's raw payload-decoding flag.
///
/// # Safety
/// `record` must be non-null and readable through byte offset +0x18.
/// No alignment beyond byte alignment is required.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_record_decode_flag")]
pub unsafe extern "C" fn resource_record_decode_flag(record: *const u8) -> u32 {
    record.add(DECODE_FLAG_OFFSET).read() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_every_unsigned_flag_and_ignores_neighbor_bytes() {
        for alignment in 0..4 {
            let mut storage = [0xa5u8; 32];
            for flag in 0..=255u32 {
                storage[alignment + DECODE_FLAG_OFFSET - 1] = !(flag as u8);
                storage[alignment + DECODE_FLAG_OFFSET] = flag as u8;
                storage[alignment + DECODE_FLAG_OFFSET + 1] = (flag as u8).wrapping_add(1);
                let before = storage;
                let actual = unsafe { resource_record_decode_flag(storage.as_ptr().add(alignment)) };
                assert_eq!(actual, flag);
                assert_eq!(storage, before);
            }
        }
    }

    #[test]
    fn reads_last_byte_of_minimum_sized_record() {
        let mut record = [0u8; DECODE_FLAG_OFFSET + 1];
        record[DECODE_FLAG_OFFSET] = 0xff;
        assert_eq!(unsafe { resource_record_decode_flag(record.as_ptr()) }, 255);
    }
}
