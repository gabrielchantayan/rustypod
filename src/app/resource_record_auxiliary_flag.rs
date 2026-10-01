//! `resource_record_auxiliary_flag` — original `FUN_082a1eb4` at
//! `0x082a1eb4` (8 bytes, `0x082a1eb4..0x082a1ebc`; the next real
//! function starts at `0x082a1ebc`). Raw words are `e5d00019` (`ldrb
//! r0,[r0,#0x19]`) and `e12fff1e` (`bx lr`). Whole-image aligned ARM
//! decoding verifies two inbound plain BLs (`0x081046e4`, `0x081048a8`),
//! zero predicated inbound BLs, and no outbound calls.
//!
//! Return the unsigned byte at resource record offset +0x19 unchanged.
//! Both callers in `FUN_0810453c` test zero/nonzero: the first gates an
//! auxiliary-file read and the second gates subsequent processing through
//! `FUN_0806e0e0`. The precise file format and flag encoding are not known;
//! this accessor imposes no boolean normalization or validation.
//!
//! Deliberate deviations: none. There are no callee seams.

const AUXILIARY_FLAG_OFFSET: usize = 0x19;

/// Returns the resource record's raw auxiliary-processing flag.
///
/// # Safety
/// `record` must be non-null and readable through byte offset +0x19.
/// No alignment beyond byte alignment is required.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_record_auxiliary_flag")]
pub unsafe extern "C" fn resource_record_auxiliary_flag(record: *const u8) -> u32 {
    record.add(AUXILIARY_FLAG_OFFSET).read() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_every_unsigned_flag_and_ignores_neighbor_bytes() {
        for alignment in 0..4 {
            let mut storage = [0xa5u8; 32];
            for flag in 0..=255u32 {
                storage[alignment + AUXILIARY_FLAG_OFFSET - 1] = !(flag as u8);
                storage[alignment + AUXILIARY_FLAG_OFFSET] = flag as u8;
                storage[alignment + AUXILIARY_FLAG_OFFSET + 1] = (flag as u8).wrapping_add(1);
                let before = storage;
                let actual = unsafe { resource_record_auxiliary_flag(storage.as_ptr().add(alignment)) };
                assert_eq!(actual, flag);
                assert_eq!(storage, before);
            }
        }
    }

    #[test]
    fn reads_last_byte_of_minimum_sized_record() {
        let mut record = [0u8; AUXILIARY_FLAG_OFFSET + 1];
        record[AUXILIARY_FLAG_OFFSET] = 0x80;
        assert_eq!(unsafe { resource_record_auxiliary_flag(record.as_ptr()) }, 0x80);
    }
}
