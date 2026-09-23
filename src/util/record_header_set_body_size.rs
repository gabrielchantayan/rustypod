//! Set a record header's low-24-bit body size — `FUN_0814d6b0` @
//! `0x0814d6b0`.
//!
//! Raw `osos.dec` words establish the exact 24-byte A32 body at
//! `0x0814d6b0..0x0814d6c4`; `push {r4, lr}` at `0x0814d6c8` begins the next
//! real function. Full raw-image A32 decoding finds three inbound plain,
//! unconditional `bl` sites (0x0814d860, 0x0814d8b8, and 0x081a860c), with
//! zero predicated inbound `bl` forms. The leaf preserves header bits 24..31
//! and replaces bits 0..23 with the supplied body size.
//!
//! Deliberate deviations: none.

/// Replaces `record[0]`'s low-24-bit body size while preserving its high-byte
/// flags.
///
/// # Safety
///
/// `record` must point to a writable record header. As in retailOS, this
/// performs no NULL check or validation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_header_set_body_size(record: *mut u32, body_size: u32) {
    let header = unsafe { record.read() };
    unsafe { record.write((header & 0xff00_0000) | (body_size & 0x00ff_ffff)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_the_entire_low_twenty_four_bits() {
        let mut record = [0xa5ff_55aa];

        unsafe { record_header_set_body_size(record.as_mut_ptr(), 0x1234_5678) };

        assert_eq!(record[0], 0xa534_5678);
    }

    #[test]
    fn masks_high_bits_from_the_supplied_size() {
        let mut record = [0x3c00_0000];

        unsafe { record_header_set_body_size(record.as_mut_ptr(), 0xffff_ffff) };

        assert_eq!(record[0], 0x3cff_ffff);
    }

    #[test]
    fn permits_a_zero_body_size_without_changing_flags() {
        let mut record = [0x8100_0001];

        unsafe { record_header_set_body_size(record.as_mut_ptr(), 0) };

        assert_eq!(record[0], 0x8100_0000);
    }
}
