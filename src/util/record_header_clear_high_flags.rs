//! Clear selected high-byte record-header flags — `record_header_clear_high_flags`
//! @ 0x0814d78c.
//!
//! Raw ARM is six instructions at `0x0814d78c..0x0814d7a0`; `push {r4, lr}`
//! at `0x0814d7a4` starts the next real function, confirming Ghidra's
//! 24-byte extent. There are three direct plain `bl` callers and no
//! predicated `bl` callers. The function loads `record[0]`, intersects the
//! supplied mask with its high byte, clears those selected bits, and stores
//! the result back.
//!
//! Deliberate deviations: none.

/// Clears from `record[0]` only the high-byte flags selected by `flags`.
///
/// # Safety
///
/// `record` must point to a writable record header. As in retailOS, this
/// performs no NULL check or validation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_header_clear_high_flags(record: *mut u32, flags: u32) {
    let header = unsafe { record.read() };
    let selected_high_flags = header & flags & 0xff00_0000;
    unsafe { record.write(header & !selected_high_flags) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_selected_high_byte_bits() {
        let mut record = [0xa5ff_55aa];

        unsafe { record_header_clear_high_flags(record.as_mut_ptr(), 0x3c12_ffff) };

        assert_eq!(record[0], 0x81ff_55aa);
    }

    #[test]
    fn ignores_masks_outside_the_high_byte() {
        let mut record = [0x5aa5_1234];

        unsafe { record_header_clear_high_flags(record.as_mut_ptr(), 0x00ff_ffff) };

        assert_eq!(record[0], 0x5aa5_1234);
    }

    #[test]
    fn preserves_unselected_high_byte_flags() {
        let mut record = [0xff00_0000];

        unsafe { record_header_clear_high_flags(record.as_mut_ptr(), 0x5500_0000) };

        assert_eq!(record[0], 0xaa00_0000);
    }
}
