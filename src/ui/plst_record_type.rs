//! Port of the PLST record type accessor at `0x08160cf0`.

/// `plst_record_type` — original: `FUN_08160cf0` @ `0x08160cf0` (12 bytes).
///
/// Raw ARM establishes the exact extent `0x08160cf0..0x08160cfc`:
/// `ldrb r0,[r0,#0xe] / and r0,r0,#0x1f / bx lr`; the next independent
/// accessor starts at `0x08160cfc`. Three direct plain `bl` callers
/// (`0x081608b4`, `0x08160904`, and `0x08160918`) are all unconditional;
/// there are no predicated `bl` callers. It reads the PLST record header byte
/// at `+0x0e` and returns its low five-bit type field. Deliberate deviations:
/// none.
///
/// # Safety
///
/// `record` must point to at least 15 readable bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn plst_record_type(record: *const u8) -> u32 {
    record.add(0x0e).read() as u32 & 0x1f
}

#[cfg(test)]
mod tests {
    use super::*;

    const TYPE_OFFSET: usize = 0x0e;

    #[test]
    fn returns_the_low_five_bits_of_every_header_value() {
        for header in 0u8..=u8::MAX {
            let mut record = [0xa5u8; 15];
            record[TYPE_OFFSET] = header;
            assert_eq!(unsafe { plst_record_type(record.as_ptr()) }, (header & 0x1f) as u32);
        }
    }

    #[test]
    fn ignores_every_other_record_byte() {
        for offset in 0..TYPE_OFFSET {
            let mut record = [0u8; 15];
            record[TYPE_OFFSET] = 0x15;
            record[offset] = 0xff;
            assert_eq!(unsafe { plst_record_type(record.as_ptr()) }, 0x15);
        }
    }
}
