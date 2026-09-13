//! Clears the initialized fields of a tagged three-word record.

/// A 16-byte record whose tag and three word payloads are initialized by
/// `clear_u16_three_word_record`.
///
/// The original function deliberately leaves `reserved` (bytes 2 and 3)
/// unchanged while writing the aligned word fields.
#[repr(C)]
pub struct U16ThreeWordRecord {
    pub tag: u16,
    pub reserved: u16,
    pub first: u32,
    pub second: u32,
    pub third: u32,
}

/// `clear_u16_three_word_record` — original: `FUN_0822c4d8` @ **0x0822c4d8**
/// (24 bytes exactly, `0x0822c4d8..0x0822c4f0`; the distinct next function
/// starts at `0x0822c4f0`).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies **6 direct inbound
/// call sites**, all unconditional `bl`: 0x081b2600, 0x081b261c, 0x081b2674,
/// 0x081b26c8, 0x081b271c, and 0x081b2770. There are no predicated BL forms
/// or direct tail branches. The function writes zero to the u16 tag and the
/// three aligned u32 payload fields, preserving the intervening two bytes and
/// returning the unchanged destination in r0.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `record` must be non-NULL, aligned for `U16ThreeWordRecord`, and writable.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.clear_u16_three_word_record")]
#[inline(never)]
pub unsafe extern "C" fn clear_u16_three_word_record(
    record: *mut U16ThreeWordRecord,
) -> *mut U16ThreeWordRecord {
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).tag), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).first), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).second), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).third), 0);
    record
}

#[cfg(test)]
mod tests {
    use super::{clear_u16_three_word_record, U16ThreeWordRecord};

    #[test]
    fn clears_the_tag_and_payloads_but_preserves_reserved_bytes() {
        let mut record = U16ThreeWordRecord {
            tag: 0xffff,
            reserved: 0x5aa5,
            first: 0x1111_1111,
            second: 0x8000_0000,
            third: u32::MAX,
        };

        let returned = unsafe { clear_u16_three_word_record(&mut record) };

        assert_eq!(returned, &mut record as *mut U16ThreeWordRecord);
        assert_eq!(record.tag, 0);
        assert_eq!(record.reserved, 0x5aa5);
        assert_eq!([record.first, record.second, record.third], [0; 3]);
    }

    #[test]
    fn only_mutates_the_selected_record() {
        let mut records = [
            U16ThreeWordRecord { tag: 1, reserved: 2, first: 3, second: 4, third: 5 },
            U16ThreeWordRecord { tag: 6, reserved: 7, first: 8, second: 9, third: 10 },
            U16ThreeWordRecord { tag: 11, reserved: 12, first: 13, second: 14, third: 15 },
        ];

        unsafe { clear_u16_three_word_record(&mut records[1]) };

        assert_eq!(records[0].tag, 1);
        assert_eq!([records[0].first, records[0].second, records[0].third], [3, 4, 5]);
        assert_eq!(records[1].tag, 0);
        assert_eq!(records[1].reserved, 7);
        assert_eq!([records[1].first, records[1].second, records[1].third], [0; 3]);
        assert_eq!(records[2].tag, 11);
        assert_eq!([records[2].first, records[2].second, records[2].third], [13, 14, 15]);
    }
}
