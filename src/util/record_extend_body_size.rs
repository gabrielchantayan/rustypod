//! Extend a record's body-size field — `FUN_0814d7a4` @ 0x0814d7a4.
//!
//! Raw A32 establishes a 40-byte extent ending at the next real function's
//! push at 0x0814d7cc. Whole-image decoding finds two inbound plain BL calls
//! (0x0814d5a8, 0x0814d654), zero predicated BL calls, and no inbound B.
//! The body has one plain BL to record_body_size(record, 4), no predicated
//! BL, and a tail B to record_header_set_body_size. Add the supplied body
//! size and 16 bytes of record overhead to the current low-24-bit size,
//! then store the low 24 bits while preserving the header's flag byte.
//! Callers use this to combine adjacent records; their class is unidentified.
//! Deliberate deviations: no behavior changes. LLVM adds a frame pointer;
//! the body-size call and setter tail branch are preserved.

use super::record_body_size::record_body_size;
use super::record_header_set_body_size::record_header_set_body_size;

/// Adds `additional_body_size + 16` modulo 2^24 to the record body size.
///
/// # Safety
/// `record` must point to an aligned, readable and writable u32 header.
/// No NULL check, size validation, or trailer update is performed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_extend_body_size(record: *mut u32, additional_body_size: u32) {
    let body_size = unsafe { record_body_size(record, 4) };
    let extended_size = body_size.wrapping_add(additional_body_size).wrapping_add(16);
    unsafe { record_header_set_body_size(record, extended_size) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_preserves_every_flag_byte_and_neighbor() {
        for flags in 0..=255u32 {
            let mut words = [0xdead_beef, (flags << 24) | 0x1234, 0xcafe_babe];
            unsafe { record_extend_body_size(words.as_mut_ptr().add(1), 0x5678) };
            assert_eq!(words, [0xdead_beef, (flags << 24) | 0x68bc, 0xcafe_babe]);
        }
    }

    #[test]
    fn includes_overhead_and_wraps_size_without_carrying_into_flags() {
        for (header, additional, expected) in [
            (0x8100_0000, 0, 0x8100_0010),
            (0xa5ff_fff0, 0, 0xa500_0000),
            (0x7fff_ffff, 1, 0x7f00_0010),
            (0x4200_0000, 0xffff_ffff, 0x4200_000f),
            (0xff00_0001, 0xffff_ffff, 0xff00_0010),
            (0x1200_0008, 0x0100_0020, 0x1200_0038),
        ] {
            let mut word = header;
            unsafe { record_extend_body_size(&mut word, additional) };
            assert_eq!(word, expected, "header={header:08x} additional={additional:08x}");
        }
    }
}
