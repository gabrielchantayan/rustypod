//! Record field configuration — `configure_record_fields` @ 0x0800f1b4.
//!
//! Both recovered image-processing callers pass a record-like object plus a
//! computed primary value and the constant secondary value `8`. The object
//! type is not recovered, but the callers retain and later consume the
//! primary value through its `+0xf4` word. This 40-byte leaf writes that
//! primary word, writes the secondary word at `+0xf0`, and clears the byte at
//! `+0xf8`. Byte-addressed `u32` fields preserve the retailOS layout on the
//! 32-bit target and 64-bit test host.

const SECONDARY_VALUE_OFFSET: usize = 0xf0;
const PRIMARY_VALUE_OFFSET: usize = 0xf4;
const READY_OFFSET: usize = 0xf8;

/// configure_record_fields — original: `FUN_0800f1b4` @ 0x0800f1b4
/// (40 bytes).
///
/// Stores `primary_value` at `record + 0xf4`, stores `secondary_value` at
/// `record + 0xf0`, then clears the record's byte flag at `+0xf8`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn configure_record_fields(
    record: *mut u8,
    primary_value: u32,
    secondary_value: u32,
) {
    record
        .add(PRIMARY_VALUE_OFFSET)
        .cast::<u32>()
        .write_volatile(primary_value);
    record
        .add(SECONDARY_VALUE_OFFSET)
        .cast::<u32>()
        .write_volatile(secondary_value);
    record.add(READY_OFFSET).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct Record([u8; 0x100]);

    impl Record {
        fn patterned() -> Self {
            Self([0xa5; 0x100])
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }

        fn word_at(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
        }
    }

    #[test]
    fn stores_both_words_and_clears_the_ready_byte() {
        let mut record = Record::patterned();

        unsafe { configure_record_fields(record.ptr(), 0x1234_5678, 8) };

        assert_eq!(record.word_at(PRIMARY_VALUE_OFFSET), 0x1234_5678);
        assert_eq!(record.word_at(SECONDARY_VALUE_OFFSET), 8);
        assert_eq!(record.0[READY_OFFSET], 0);
    }

    #[test]
    fn preserves_every_byte_outside_the_three_fields() {
        let mut record = Record::patterned();

        unsafe { configure_record_fields(record.ptr(), 0xffff_ffff, 0) };

        for offset in 0..record.0.len() {
            if (SECONDARY_VALUE_OFFSET..SECONDARY_VALUE_OFFSET + 4).contains(&offset)
                || (PRIMARY_VALUE_OFFSET..PRIMARY_VALUE_OFFSET + 4).contains(&offset)
                || offset == READY_OFFSET
            {
                continue;
            }
            assert_eq!(record.0[offset], 0xa5, "byte +{offset:#x}");
        }
    }

    #[test]
    fn each_call_replaces_prior_words_and_reclears_the_flag() {
        let mut record = Record::patterned();

        unsafe { configure_record_fields(record.ptr(), 1, 8) };
        record.0[READY_OFFSET] = 0xff;
        unsafe { configure_record_fields(record.ptr(), 2, 16) };

        assert_eq!(record.word_at(PRIMARY_VALUE_OFFSET), 2);
        assert_eq!(record.word_at(SECONDARY_VALUE_OFFSET), 16);
        assert_eq!(record.0[READY_OFFSET], 0);
    }
}
