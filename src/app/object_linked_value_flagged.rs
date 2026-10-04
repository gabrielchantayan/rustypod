//! `object_linked_value_flagged` — original: `FUN_081fb58c` @ 0x081fb58c.
//! True extent: 60 bytes, ending at the independent accessor at 0x081fb5c8.
//! Verified raw call counts: zero outgoing plain or predicated BL instructions;
//! two inbound plain BL sites (0x081fb8c8, 0x081fb8e4), zero predicated sites.
//!
//! Loads the 32-bit linked-record pointer at object +0x1c and compares the
//! record's word at +4 with the requested value. A mismatch returns zero;
//! otherwise either flag 0x100 or 0x200 at object +0x14 produces one.
//! The event-0x206 caller checks objects in controller slots +0x48 and +0x5c.
//! Their concrete type and the wider meanings of the flags are unidentified.
//! Sources: raw osos.dec and decomp/c/021/081fb58c_FUN_081fb58c.c,
//! 081fbb34_FUN_081fbb34.c. Deliberate deviations: none; word indices preserve
//! the firmware's four-byte pointer fields on both target and host.

/// Returns whether the linked value matches and either flag is set.
///
/// # Safety
/// `object` must reference eight readable aligned u32 words. Its word seven
/// must encode a non-null aligned pointer to two readable u32 words, even
/// when the flags are clear. The linked record is read before the flags.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_linked_value_flagged(object: *const u32, value: u32) -> u32 {
    let linked_record = object.add(7).read() as usize as *const u32;
    if linked_record.add(1).read() != value {
        return 0;
    }
    ((object.add(5).read() & 0x300) != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_full_linked_value_and_accepts_either_flag() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::OBJECT_LINKED_VALUE_FLAGGED, 4096,
        ) else {
            crate::testing::note_missing_u32_fixture("app::object_linked_value_flagged");
            return;
        };
        unsafe {
            let record = slab as *mut u32;
            record.write(0xfeed_face);
            let mut object = [0xa5a5_a5a5; 8];
            object[7] = record as usize as u32;
            for linked_value in [0, 1, 0x8000_0000, u32::MAX] {
                record.add(1).write(linked_value);
                for value in [linked_value, linked_value ^ 1, linked_value ^ 0x8000_0000] {
                    for flags in [0, 0xff, 0x100, 0x200, 0x300, 0x400, 0xffff_fcff, u32::MAX] {
                        object[5] = flags;
                        let before = object;
                        let expected = (linked_value == value &&
                            (flags & 0x100 != 0 || flags & 0x200 != 0)) as u32;
                        assert_eq!(object_linked_value_flagged(object.as_ptr(), value), expected,
                            "linked={linked_value:#x} value={value:#x} flags={flags:#x}");
                        assert_eq!(object, before);
                        assert_eq!(record.read(), 0xfeed_face);
                        assert_eq!(record.add(1).read(), linked_value);
                    }
                }
            }
        }
    }
}
