//! Accessor for the code byte in retailOS's four-byte parser result record.

/// parse_result_code — original: `FUN_0828312c` @ `0x0828312c` (8 bytes;
/// source: `ipod-decomp/decomp/c/027/0828312c_FUN_0828312c.c`).
///
/// Returns the unsigned `code` byte at `record + 0x01` without modifying the
/// four-byte `{ status: u8, code: u8, detail: u16 }` parser result. The ARM
/// leaf is exactly `ldrb r0,[r0,#1]; bx lr`: it accepts the record in `r0`,
/// zero-extends the load into the unsigned-byte return ABI, and has no NULL
/// guard. The direct caller at `0x080fb68c` passes its embedded result at
/// `+0x5c` and serializes this value as the third byte of its output record;
/// the adjacent result-record constructors prove this field is the error code.
///
/// # Safety
///
/// `record` must designate at least two readable bytes. It is not
/// null-checked, matching the retail `ldrb`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_result_code(record: *const u8) -> u8 {
    record.add(1).read_volatile()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_every_unsigned_code_value() {
        let mut record = [0u8; 4];
        for code in 0u8..=u8::MAX {
            record[1] = code;
            assert_eq!(unsafe { parse_result_code(record.as_ptr()) }, code);
        }
    }

    #[test]
    fn reads_offset_one_and_preserves_surrounding_bytes() {
        let mut storage = [0x7e, 0x11, 0xa5, 0x34, 0x12, 0xe7];
        let before = storage;
        let record = unsafe { storage.as_ptr().add(1) };

        assert_eq!(unsafe { parse_result_code(record) }, 0xa5);
        assert_eq!(storage, before);
    }

    #[test]
    fn read_only_access_is_safe_through_an_alias_of_mutable_storage() {
        let mut record = [0x02, 0xfe, 0x00, 0x20];
        let before = record;
        let mutable_alias = record.as_mut_ptr();

        assert_eq!(unsafe { parse_result_code(mutable_alias.cast_const()) }, 0xfe);
        assert_eq!(record, before);
    }
}
