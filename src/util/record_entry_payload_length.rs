//! `record_entry_payload_length` — original: `FUN_083384d4` @ `0x083384d4`.
//!
//! Raw ARM confirms a 216-byte instruction body (`0x083384d4..0x083385ac`)
//! followed by three literal-pool words at `0x083385ac..0x083385b8`; the next
//! separately linked function starts at `0x083385b8`, so the full extent is
//! 228 bytes. Decoding every ARM `B`/`BL` word in `osos.dec` finds exactly six
//! direct inbound calls, all unconditional `bl`: `0x082f2644`, `0x082f5978`,
//! `0x083144dc`, `0x083267dc`, `0x083401e8`, and `0x0834f644`. There are no
//! predicated calls or direct tail `b` transfers.
//!
//! The function rejects a NULL record-source slot or NULL byte source with
//! `0xffff5bd9`. It delegates entry-offset validation to the unported
//! `FUN_08350954` @ `0x08350954`; a zero result returns `0xffff5b1e`, while
//! every nonzero result is accepted. For an optional output, it decodes the
//! selected entry's first four bytes (each byte is multiplied by `0x17` modulo
//! 256, in big-endian order), subtracts the 20-byte entry header, and applies
//! the wrapping multiplier `0xbd7d7cff`.
//!
//! Deliberate deviations: none. The validator is not yet ported, so target
//! builds retain its verified retail address and host tests install a seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const MISSING_RECORD_SOURCE: i32 = 0xffff_5bd9u32 as i32;
const INVALID_ENTRY_OFFSET: i32 = 0xffff_5b1eu32 as i32;
const BYTE_DECODE_MULTIPLIER: u32 = 0x17;
const PAYLOAD_LENGTH_MULTIPLIER: u32 = 0xbd7d_7cff;

type ValidateRecordOffset = unsafe extern "C" fn(*const *const u8, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn validate_record_offset(record_source: *const *const u8, requested_offset: u32) -> u32 {
    let validate: ValidateRecordOffset = unsafe { core::mem::transmute(0x0835_0954usize) };
    unsafe { validate(record_source, requested_offset) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_validate_record_offset(_: *const *const u8, _: u32) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct RecordEntryValidatorOps {
    validate_record_offset: ValidateRecordOffset,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_RECORD_ENTRY_VALIDATOR_OPS: RecordEntryValidatorOps = RecordEntryValidatorOps {
    validate_record_offset: unavailable_validate_record_offset,
};

#[cfg(not(target_os = "none"))]
static mut RECORD_ENTRY_VALIDATOR_OPS: RecordEntryValidatorOps = DEFAULT_RECORD_ENTRY_VALIDATOR_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn validate_record_offset(record_source: *const *const u8, requested_offset: u32) -> u32 {
    let validate = unsafe {
        core::ptr::read_volatile(addr_of!(RECORD_ENTRY_VALIDATOR_OPS.validate_record_offset))
    };
    unsafe { validate(record_source, requested_offset) }
}

/// Returns the decoded payload length for an entry selected from a byte record.
///
/// Original: `FUN_083384d4` @ `0x083384d4` (228-byte full extent; six
/// unconditional direct `bl` callers).
///
/// # Safety
///
/// `record_source`, when non-NULL, must name a readable pointer slot. Its
/// non-NULL byte source must contain the entry accepted by the retail
/// validator. `out_payload_length`, when non-NULL, must be writable for one
/// aligned `u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.record_entry_payload_length")]
#[inline(never)]
pub unsafe extern "C" fn record_entry_payload_length(
    requested_offset: u32,
    out_payload_length: *mut u32,
    record_source: *const *const u8,
) -> i32 {
    if record_source.is_null() || unsafe { record_source.read() }.is_null() {
        return MISSING_RECORD_SOURCE;
    }

    let entry_offset = unsafe { validate_record_offset(record_source, requested_offset) };
    if entry_offset == 0 {
        return INVALID_ENTRY_OFFSET;
    }

    if !out_payload_length.is_null() {
        let bytes = unsafe { record_source.read() };
        let entry = unsafe { bytes.add(entry_offset as usize) };
        let encoded_entry_size = unsafe {
            ((entry.read() as u32).wrapping_mul(BYTE_DECODE_MULTIPLIER) << 24)
                | (((entry.add(1).read() as u32).wrapping_mul(BYTE_DECODE_MULTIPLIER) & 0xff) << 16)
                | (((entry.add(2).read() as u32).wrapping_mul(BYTE_DECODE_MULTIPLIER) & 0xff) << 8)
                | ((entry.add(3).read() as u32).wrapping_mul(BYTE_DECODE_MULTIPLIER) & 0xff)
        };
        let payload_length = encoded_entry_size
            .wrapping_sub(0x14)
            .wrapping_mul(PAYLOAD_LENGTH_MULTIPLIER);
        unsafe { out_payload_length.write(payload_length) };
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of_mut, null, null_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut VALIDATOR_RESULT: u32 = 0;
    static mut SEEN_SOURCE: *const *const u8 = null();
    static mut SEEN_REQUESTED_OFFSET: u32 = 0;

    unsafe extern "C" fn recovered_validate_record_offset(
        record_source: *const *const u8,
        requested_offset: u32,
    ) -> u32 {
        unsafe {
            SEEN_SOURCE = record_source;
            SEEN_REQUESTED_OFFSET = requested_offset;
            VALIDATOR_RESULT
        }
    }

    fn install_validator(result: u32) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            VALIDATOR_RESULT = result;
            SEEN_SOURCE = null();
            SEEN_REQUESTED_OFFSET = u32::MAX;
            addr_of_mut!(RECORD_ENTRY_VALIDATOR_OPS).write(RecordEntryValidatorOps {
                validate_record_offset: recovered_validate_record_offset,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(RECORD_ENTRY_VALIDATOR_OPS).write(DEFAULT_RECORD_ENTRY_VALIDATOR_OPS) };
        drop(guard);
    }

    fn encode_byte(decoded: u8) -> u8 {
        decoded.wrapping_mul(167)
    }

    #[test]
    fn null_record_source_or_byte_source_returns_missing_source_error() {
        let mut output = u32::MAX;
        assert_eq!(
            unsafe { record_entry_payload_length(7, &mut output, null()) },
            MISSING_RECORD_SOURCE
        );
        assert_eq!(output, u32::MAX);

        let byte_source: *const u8 = null();
        assert_eq!(
            unsafe { record_entry_payload_length(7, &mut output, &byte_source) },
            MISSING_RECORD_SOURCE
        );
        assert_eq!(output, u32::MAX);
    }

    #[test]
    fn rejected_offset_preserves_optional_output() {
        let guard = install_validator(0);
        let bytes = [0u8; 16];
        let byte_source = bytes.as_ptr();
        let mut output = 0xa5a5_a5a5;

        assert_eq!(
            unsafe { record_entry_payload_length(0x48, &mut output, &byte_source) },
            INVALID_ENTRY_OFFSET
        );
        assert_eq!(output, 0xa5a5_a5a5);
        unsafe {
            assert_eq!(SEEN_SOURCE, &byte_source);
            assert_eq!(SEEN_REQUESTED_OFFSET, 0x48);
        }
        restore_default(guard);
    }

    #[test]
    fn decodes_payload_length_after_a_nonzero_validation_result() {
        let guard = install_validator(3);
        let decoded_entry_size = 0x89ab_cdefu32;
        let mut bytes = [0x5a; 16];
        for (index, byte) in decoded_entry_size.to_be_bytes().into_iter().enumerate() {
            bytes[3 + index] = encode_byte(byte);
        }
        let byte_source = bytes.as_ptr();
        let mut output = 0;

        assert_eq!(
            unsafe { record_entry_payload_length(0xdead_beef, &mut output, &byte_source) },
            0
        );
        assert_eq!(
            output,
            decoded_entry_size
                .wrapping_sub(0x14)
                .wrapping_mul(PAYLOAD_LENGTH_MULTIPLIER)
        );
        unsafe {
            assert_eq!(SEEN_SOURCE, &byte_source);
            assert_eq!(SEEN_REQUESTED_OFFSET, 0xdead_beef);
        }
        restore_default(guard);
    }

    #[test]
    fn nonzero_validation_allows_a_null_output_pointer() {
        let guard = install_validator(1);
        let bytes = [0u8; 8];
        let byte_source = bytes.as_ptr();

        assert_eq!(unsafe { record_entry_payload_length(1, null_mut(), &byte_source) }, 0);
        unsafe {
            assert_eq!(SEEN_SOURCE, &byte_source);
            assert_eq!(SEEN_REQUESTED_OFFSET, 1);
        }
        restore_default(guard);
    }
}
