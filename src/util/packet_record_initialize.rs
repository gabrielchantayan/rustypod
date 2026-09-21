//! Packet record initialization — `FUN_082e2674` @ 0x082e2674.
//!
//! Raw `osos.dec` spans 120 bytes (30 ARM words) from 0x082e2674 through the
//! tail branch at 0x082e26e8; the next independently linked function starts
//! at 0x082e26ec. It contains three plain, unconditional `bl` instructions
//! and no predicated call. The routine space-pads the two fixed-width text
//! fields, writes the record metadata, clears its ten-byte reserved range,
//! then tail-calls a four-word state clear.
//! Deliberate deviation: the three unported retailOS callees are inlined from
//! their verified ARM behavior, so this port has no invented dispatch seam.

const FIRST_TEXT_OFFSET: usize = 0;
const FIRST_TEXT_LEN: usize = 8;
const SECOND_TEXT_OFFSET: usize = 8;
const SECOND_TEXT_LEN: usize = 3;
const KIND_OFFSET: usize = 0xb;
const RESERVED_OFFSET: usize = 0xc;
const RESERVED_LEN: usize = 10;
const HIGH_VALUE_OFFSET: usize = 0x14;
const SECOND_PAIR_OFFSET: usize = 0x16;
const FIRST_PAIR_OFFSET: usize = 0x18;
const STATE_FIRST_OFFSET: usize = 0x40;
const STATE_SECOND_OFFSET: usize = 0x44;
const STATE_THIRD_OFFSET: usize = 0x4c;
const STATE_FOURTH_OFFSET: usize = 0x50;
const LOW_VALUE_OFFSET: usize = 0x1a;
const CONTEXT_OFFSET: usize = 0x1c;

unsafe fn copy_text_padded_with_spaces(destination: *mut u8, source: *const u8, len: usize) {
    for offset in 0..len {
        let byte = source.add(offset).read_volatile();
        destination.add(offset).write_volatile(if byte == 0 { b' ' } else { byte });
    }
}

/// initialize_packet_record — original: `FUN_082e2674` @ 0x082e2674
/// (120 bytes).
///
/// Initializes the fixed fields of a packet record. Text fields copy through
/// their fixed widths, replacing every encountered NUL with a space; they do
/// not stop at the first NUL. `packed_value` supplies the high and low u16
/// fields in target little-endian layout.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn initialize_packet_record(
    record: *mut u8,
    first_text: *const u8,
    second_text: *const u8,
    kind: u8,
    packed_value: u32,
    context: u32,
    pair: *const u16,
) {
    copy_text_padded_with_spaces(record.add(FIRST_TEXT_OFFSET), first_text, FIRST_TEXT_LEN);
    copy_text_padded_with_spaces(record.add(SECOND_TEXT_OFFSET), second_text, SECOND_TEXT_LEN);
    record.add(KIND_OFFSET).write_volatile(kind);

    for offset in 0..RESERVED_LEN {
        record.add(RESERVED_OFFSET + offset).write_volatile(0);
    }

    record
        .add(SECOND_PAIR_OFFSET)
        .cast::<u16>()
        .write_volatile(pair.add(1).read_volatile());
    record
        .add(FIRST_PAIR_OFFSET)
        .cast::<u16>()
        .write_volatile(pair.read_volatile());
    record
        .add(HIGH_VALUE_OFFSET)
        .cast::<u16>()
        .write_volatile((packed_value >> 16) as u16);
    record
        .add(LOW_VALUE_OFFSET)
        .cast::<u16>()
        .write_volatile(packed_value as u16);
    record.add(CONTEXT_OFFSET).cast::<u32>().write_volatile(context);
    record.add(STATE_FIRST_OFFSET).cast::<u32>().write_volatile(0);
    record.add(STATE_SECOND_OFFSET).cast::<u32>().write_volatile(0);
    record.add(STATE_THIRD_OFFSET).cast::<u32>().write_volatile(0);
    record.add(STATE_FOURTH_OFFSET).cast::<u32>().write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct Record([u8; 0x58]);

    fn word_at(record: &Record, offset: usize) -> u32 {
        u32::from_le_bytes(record.0[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn initializes_fixed_fields_and_preserves_bytes_outside_the_extent() {
        let mut record = Record([0xa5; 0x58]);
        let first = *b"A\0CDE\0GH";
        let second = *b"\0Y\0";
        let pair = [0x1122u16, 0x3344];

        unsafe {
            initialize_packet_record(
                record.0.as_mut_ptr(),
                first.as_ptr(),
                second.as_ptr(),
                0x7e,
                0x89ab_cdef,
                0x0123_4567,
                pair.as_ptr(),
            );
        }

        assert_eq!(&record.0[0..8], b"A CDE GH");
        assert_eq!(&record.0[8..11], b" Y ");
        assert_eq!(record.0[KIND_OFFSET], 0x7e);
        assert_eq!(&record.0[RESERVED_OFFSET..HIGH_VALUE_OFFSET], &[0; 8]);
        assert_eq!(&record.0[HIGH_VALUE_OFFSET..HIGH_VALUE_OFFSET + 2], &0x89abu16.to_le_bytes());
        assert_eq!(&record.0[SECOND_PAIR_OFFSET..SECOND_PAIR_OFFSET + 2], &0x3344u16.to_le_bytes());
        assert_eq!(&record.0[FIRST_PAIR_OFFSET..FIRST_PAIR_OFFSET + 2], &0x1122u16.to_le_bytes());
        assert_eq!(&record.0[LOW_VALUE_OFFSET..LOW_VALUE_OFFSET + 2], &0xcdefu16.to_le_bytes());
        assert_eq!(word_at(&record, CONTEXT_OFFSET), 0x0123_4567);
        assert_eq!(word_at(&record, STATE_FIRST_OFFSET), 0);
        assert_eq!(word_at(&record, STATE_SECOND_OFFSET), 0);
        assert_eq!(word_at(&record, STATE_THIRD_OFFSET), 0);
        assert_eq!(word_at(&record, STATE_FOURTH_OFFSET), 0);
        assert_eq!(&record.0[0x54..], &[0xa5; 4]);
    }

    #[test]
    fn copies_non_nul_text_without_touching_the_following_record_byte() {
        let mut record = Record([0; 0x58]);
        let first = *b"12345678";
        let second = *b"xyz";
        let pair = [0, 0];
        record.0[0x54] = 0x5a;

        unsafe {
            initialize_packet_record(
                record.0.as_mut_ptr(), first.as_ptr(), second.as_ptr(), 1, 0, 0, pair.as_ptr(),
            );
        }

        assert_eq!(&record.0[0..8], &first);
        assert_eq!(&record.0[8..11], &second);
        assert_eq!(record.0[0x54], 0x5a);
    }
}
