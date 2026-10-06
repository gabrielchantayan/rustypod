//! `transfer_kind_set` — original: `FUN_081890e8` @ 0x081890e8
//! (8 bytes; **2 incoming plain BLs, 0 predicated BLs**; no outbound calls).
//!
//! Raw words `e5c01004 e12fff1e` decode to `strb r1,[r0,#4]; bx lr`.
//! The next real function, transfer_kind_invalidate, starts at 0x081890f0
//! with `mov r1,#0xff`. No veneer or literal pool belongs to this extent.
//! Store the low byte of the supplied kind at record +4 without touching
//! other fields. Both callers supply kinds 2, 3, or 4 before the transfer
//! operation; its tag selection reads this byte. Preserve r0 as the returned
//! record pointer, matching the canonical invalidator. Deliberate deviations:
//! none; a u32 kind preserves the raw full-register input and byte truncation.

/// Sets an opaque transfer record's kind byte and returns the same record.
///
/// # Safety
/// `record` must point to a writable allocation covering byte +4. No NULL
/// check or alignment requirement is added to the original byte store.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn transfer_kind_set(record: *mut u8, kind: u32) -> *mut u8 {
    record.add(4).write(kind as u8);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_kind_and_preserves_surrounding_bytes_at_every_alignment() {
        for offset in 0..4 {
            for kind in [0, 2, 3, 4, 0xff, 0x100, 0x1234_5678, u32::MAX] {
                let mut storage = [0xa5u8; 16];
                let pointer = unsafe { storage.as_mut_ptr().add(offset) };
                assert_eq!(unsafe { transfer_kind_set(pointer, kind) }, pointer);
                let mut expected = [0xa5u8; 16];
                expected[offset + 4] = kind as u8;
                assert_eq!(storage, expected, "offset={offset}, kind={kind:#x}");
            }
        }
    }

    #[test]
    fn replaces_an_invalid_kind_without_initializing_other_fields() {
        let mut record = [0x5au8; 12];
        unsafe { crate::app::transfer_kind_invalidate::transfer_kind_invalidate(record.as_mut_ptr()) };
        assert_eq!(record[4], 0xff);
        unsafe { transfer_kind_set(record.as_mut_ptr(), 3) };
        let mut expected = [0x5au8; 12];
        expected[4] = 3;
        assert_eq!(record, expected);
    }
}
