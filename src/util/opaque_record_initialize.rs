//! Opaque 36-byte record initialization — `FUN_0827b2d8` @ 0x0827b2d8.
//!
//! Raw `osos.dec` establishes a 44-byte A32 body from 0x0827b2d8 through the
//! `bx lr` at 0x0827b300; the literal vtable word is at 0x0827b304 and the
//! next independently entered function begins at 0x0827b308. There are three
//! inbound plain unconditional `bl` calls and no predicated inbound call.
//! The initializer installs the opaque vtable, clears fields at offsets 4,
//! 8, 16, 20, and 24, and stores its two supplied values at offsets 12 and 28.
//! Deliberate deviation: the concrete record and vtable type are not yet
//! recoverable, so the target-width fields remain byte offsets and the vtable
//! address is represented as its raw u32 value.

const OPAQUE_RECORD_VTABLE: u32 = 0x089a_60f0;
const FIRST_VALUE_OFFSET: usize = 12;
const SECOND_VALUE_OFFSET: usize = 28;

/// Initializes an allocated opaque 36-byte record and returns `record`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_record_initialize(
    record: *mut u8,
    first_value: u32,
    second_value: u32,
) -> *mut u8 {
    unsafe {
        (record as *mut u32).write(OPAQUE_RECORD_VTABLE);
        record.add(4).cast::<u32>().write(0);
        record.add(FIRST_VALUE_OFFSET).cast::<u32>().write(first_value);
        record.add(8).cast::<u32>().write(0);
        record.add(16).cast::<u32>().write(0);
        record.add(20).write(0);
        record.add(SECOND_VALUE_OFFSET).cast::<u32>().write(second_value);
        record.add(24).cast::<u32>().write(0);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_every_field_and_preserves_padding() {
        let mut record = [0xa5_u8; 40];
        let returned = unsafe {
            opaque_record_initialize(record.as_mut_ptr(), 0x1122_3344, 0x5566_7788)
        };

        assert_eq!(returned, record.as_mut_ptr());
        assert_eq!(u32::from_le_bytes(record[0..4].try_into().unwrap()), OPAQUE_RECORD_VTABLE);
        assert_eq!(u32::from_le_bytes(record[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(record[8..12].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(record[12..16].try_into().unwrap()), 0x1122_3344);
        assert_eq!(u32::from_le_bytes(record[16..20].try_into().unwrap()), 0);
        assert_eq!(record[20], 0);
        assert_eq!(record[21..24], [0xa5; 3]);
        assert_eq!(u32::from_le_bytes(record[24..28].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(record[28..32].try_into().unwrap()), 0x5566_7788);
        assert_eq!(record[32..], [0xa5; 8]);
    }
}
