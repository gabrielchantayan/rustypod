//! `transfer_kind_invalidate` — original: `FUN_081890f0` @ 0x081890f0
//! (12 bytes; **4 plain `bl` call sites, 0 predicated `bl` call sites**).
//!
//! Raw ARM establishes the exact extent 0x081890f0..0x081890fb: `mov r1,#0xff;
//! strb r1,[r0,#4]; bx lr`. The preceding function ends at 0x081890ec and the
//! next real function starts at 0x081890fc with `push {r4,lr}`; neither side is
//! a veneer or literal pool. Independent branch-target decoding finds four
//! inbound unconditional `bl` calls and no predicated `bl` calls.
//!
//! The callers initialize byte +0x04 with a transfer kind (2, 3, or 4), pass
//! the record to the transfer operation, then mark that kind invalid with the
//! `0xff` sentinel during scope exit. The routine preserves r0, so it returns
//! the record pointer. Deliberate deviations: none.

/// Marks an opaque transfer record's kind byte invalid and returns the record.
///
/// # Safety
///
/// `record` must point to a writable allocation covering byte `+0x04`. The
/// retail routine has no NULL check and performs a single byte store.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn transfer_kind_invalidate(record: *mut u8) -> *mut u8 {
    record.add(4).write(0xff);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalidates_each_observed_transfer_kind_and_preserves_pointer() {
        for kind in [2u8, 3, 4] {
            let mut record = [0xa5u8; 12];
            record[4] = kind;
            let pointer = record.as_mut_ptr();

            assert_eq!(unsafe { transfer_kind_invalidate(pointer) }, pointer);
            assert_eq!(record[4], 0xff, "kind={kind}");
        }
    }

    #[test]
    fn writes_only_kind_byte() {
        let mut record = [0xa5u8; 12];
        record[4] = 0;
        let before = record;

        unsafe { transfer_kind_invalidate(record.as_mut_ptr()) };

        assert_eq!(record[..4], before[..4]);
        assert_eq!(record[4], 0xff);
        assert_eq!(record[5..], before[5..]);
    }
}
