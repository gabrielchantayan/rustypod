//! `input_report_action_flags` — original: `FUN_0836d718` @ **0x0836d718**
//! (124 bytes, `0x0836d718..0x0836d790`; the next real function starts at
//! `0x0836d794`).
//!
//! The raw ARM words establish two inbound plain `bl` sites (the veneer at
//! `0x082e5b3c`, called from `0x0805caf8` and `0x080e3d7c`), zero inbound
//! predicated `bl` sites, and no outbound calls.
//!
//! # Algorithm
//!
//! Converts selected bits from a six-byte input report into the action-flag
//! mask consumed by the input dispatcher. Report byte 0 contributes bits 2,
//! 7, and 8; byte 1 contributes bits 3--6, 10, and 11; byte 3 contributes
//! bits 0 and 1; and byte 5 contributes bit 9. Either of byte 1's low two
//! bits maps to action bit 11.
//!
//! Deliberate deviations: the retail entry is reached through the four-byte
//! veneer at `0x082e5b3c`; this export provides the canonical body directly.

const REPORT_MINIMUM_SIZE: usize = 6;

/// Converts the observed input-report bit fields into retailOS action flags.
///
/// `report` must point to at least six readable bytes. RetailOS performs no
/// null or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_report_action_flags(report: *const u8) -> u32 {
    debug_assert!(!report.is_null());

    let byte0 = unsafe { report.read() };
    let byte1 = unsafe { report.add(1).read() };
    let byte3 = unsafe { report.add(3).read() };
    let byte5 = unsafe { report.add(REPORT_MINIMUM_SIZE - 1).read() };

    let mut flags = 0;
    if byte0 & 0x40 != 0 {
        flags |= 0x004;
    }
    if byte1 & 0x10 != 0 {
        flags |= 0x020;
    }
    if byte1 & 0x20 != 0 {
        flags |= 0x040;
    }
    if byte0 & 0x01 != 0 {
        flags |= 0x080;
    }
    if byte0 & 0x02 != 0 {
        flags |= 0x100;
    }
    if byte1 & 0xc0 != 0 {
        flags |= 0x018;
    }
    if byte3 & 0x01 != 0 {
        flags |= 0x001;
    }
    if byte3 & 0x02 != 0 {
        flags |= 0x002;
    }
    if byte5 & 0x02 != 0 {
        flags |= 0x200;
    }
    if byte1 & 0x04 != 0 {
        flags |= 0x400;
    }
    if byte1 & 0x03 != 0 {
        flags |= 0x800;
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn flags_for(report: &[u8; REPORT_MINIMUM_SIZE]) -> u32 {
        unsafe { input_report_action_flags(report.as_ptr()) }
    }

    #[test]
    fn empty_report_has_no_actions() {
        assert_eq!(unsafe { flags_for(&[0; REPORT_MINIMUM_SIZE]) }, 0);
    }

    #[test]
    fn each_report_field_maps_to_its_observed_action_bits() {
        assert_eq!(unsafe { flags_for(&[0x43, 0, 0, 0, 0, 0]) }, 0x184);
        assert_eq!(unsafe { flags_for(&[0, 0xf4, 0, 0, 0, 0]) }, 0x478);
        assert_eq!(unsafe { flags_for(&[0, 0, 0, 0x03, 0, 0x02]) }, 0x203);
    }

    #[test]
    fn either_low_byte_one_bit_sets_the_shared_action() {
        assert_eq!(unsafe { flags_for(&[0, 0x01, 0, 0, 0, 0]) }, 0x800);
        assert_eq!(unsafe { flags_for(&[0, 0x02, 0, 0, 0, 0]) }, 0x800);
        assert_eq!(unsafe { flags_for(&[0, 0x03, 0, 0, 0, 0]) }, 0x800);
    }

    #[test]
    fn unrelated_report_bits_do_not_leak_into_actions() {
        assert_eq!(unsafe { flags_for(&[0xbc, 0x08, 0xff, 0xfc, 0xff, 0xfd]) }, 0);
    }
}
