//! Sparse opaque-record state clear — `FUN_08261ce8` @ 0x08261ce8.
//!
//! Raw `osos.dec` establishes the exact 28-byte A32 extent
//! 0x08261ce8..0x08261d03: `mov r1,#0`, byte stores at offsets 0, 1, and 8,
//! word stores at offsets 4 and 12, then `bx lr`. The next independently
//! entered function starts at 0x08261d04 with `push {r4,lr}`. Full-image A32
//! decoding finds three inbound plain, unconditional `bl` call sites
//! (0x08261828, 0x08261aa4, and 0x08261d0c) and zero predicated inbound
//! `bl` call sites. The leaf has no calls.
//!
//! The record's concrete type is not recoverable, but its callers establish
//! that this clears the status and link/payload state before recycling it.
//! Deliberate deviation: volatile stores retain the firmware's distinct
//! byte/word write widths and prevent LLVM from coalescing them into a wider
//! store with different alignment and observable-write behavior.

const STATUS_OFFSET: usize = 0;
const MODE_OFFSET: usize = 1;
const OWNER_OFFSET: usize = 4;
const PENDING_OFFSET: usize = 8;
const PAYLOAD_OFFSET: usize = 12;

/// Clears the initialized fields of an aligned 16-byte opaque record.
///
/// # Safety
///
/// `record` must point to at least 16 writable bytes and be four-byte aligned,
/// matching the two aligned ARM `str` instructions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clear_opaque_record_state(record: *mut u8) {
    record.add(STATUS_OFFSET).write_volatile(0);
    record.add(MODE_OFFSET).write_volatile(0);
    record.add(OWNER_OFFSET).cast::<u32>().write_volatile(0);
    record.add(PENDING_OFFSET).write_volatile(0);
    record.add(PAYLOAD_OFFSET).cast::<u32>().write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct Record([u8; 16]);

    #[test]
    fn clears_only_the_firmware_selected_fields() {
        let mut record = Record([0xa5; 16]);

        unsafe { clear_opaque_record_state(record.0.as_mut_ptr()) };

        assert_eq!(record.0[STATUS_OFFSET], 0);
        assert_eq!(record.0[MODE_OFFSET], 0);
        assert_eq!(&record.0[OWNER_OFFSET..OWNER_OFFSET + 4], &[0; 4]);
        assert_eq!(record.0[PENDING_OFFSET], 0);
        assert_eq!(&record.0[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 4], &[0; 4]);
        assert_eq!(&record.0[2..4], &[0xa5; 2]);
        assert_eq!(&record.0[9..12], &[0xa5; 3]);
    }

    #[test]
    fn overwrites_nonzero_word_fields_little_endian() {
        let mut record = Record([0; 16]);
        record.0[OWNER_OFFSET..OWNER_OFFSET + 4].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        record.0[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 4].copy_from_slice(&0xaabb_ccddu32.to_le_bytes());

        unsafe { clear_opaque_record_state(record.0.as_mut_ptr()) };

        assert_eq!(u32::from_le_bytes(record.0[OWNER_OFFSET..OWNER_OFFSET + 4].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(record.0[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 4].try_into().unwrap()), 0);
    }
}
