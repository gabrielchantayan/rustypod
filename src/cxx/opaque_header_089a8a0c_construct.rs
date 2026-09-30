//! `opaque_header_089a8a0c_construct` — retailOS `FUN_082a8c64` @ `0x082a8c64`.
//!
//! True size: 28 bytes, six A32 instructions plus literal `0x089a8a0c`
//! at `0x082a8c7c`; the next function starts at `0x082a8c80`. Ghidra's
//! 24-byte extent excludes the literal. Whole-image aligned BL decoding
//! finds two incoming plain BLs (`0x083b6328`, `0x083b6c7c`) and zero
//! predicated BLs. The body has one plain BL to `0x082a89b4`, zero predicated.
//!
//! Initialize the four-word record using `opaque_header_payload_construct`
//! with third word 32, then replace word 0 with the opaque header literal.
//! Return the record pointer unchanged, as the raw r0 flow and caller's
//! store at `0x083b6c80` establish despite Ghidra's void return.
//! Deliberate deviations: none. No class identity is inferred for the
//! opaque literal, and no null/alignment checks are added.

use super::opaque_header_payload_construct::opaque_header_payload_construct;

/// Literal loaded from `0x082a8c7c`.
pub const OPAQUE_HEADER_089A8A0C: u32 = 0x089a_8a0c;

/// Initializes a four-word record and returns its address.
///
/// # Safety
/// `this` must address four writable, four-byte-aligned `u32` words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_header_089a8a0c_construct(
    this: *mut u32,
    payload: u32,
) -> *mut u32 {
    let record = unsafe { opaque_header_payload_construct(this, payload, 32) };
    unsafe { record.write_volatile(OPAQUE_HEADER_089A8A0C) };
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_record_without_touching_adjacent_words() {
        for payload in [0, 1, 0x8000_0000, 0xffff_ffff] {
            let mut words = [0xa5a5_a5a5; 6];
            let record = unsafe { words.as_mut_ptr().add(1) };
            let returned = unsafe { opaque_header_089a8a0c_construct(record, payload) };
            assert_eq!(returned, record);
            assert_eq!(words, [0xa5a5_a5a5, OPAQUE_HEADER_089A8A0C, 32, 0,
                               payload, 0xa5a5_a5a5]);
        }
    }

    #[test]
    fn reconstruction_resets_state_and_replaces_payload() {
        let mut record = [0xffff_ffff; 4];
        unsafe { opaque_header_089a8a0c_construct(record.as_mut_ptr(), 0xffff_ffff) };
        record[1] = 7;
        record[2] = 9;
        unsafe { opaque_header_089a8a0c_construct(record.as_mut_ptr(), 0) };
        assert_eq!(record, [OPAQUE_HEADER_089A8A0C, 32, 0, 0]);
    }
}
