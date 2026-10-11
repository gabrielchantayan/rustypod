//! Predicate guarding the inline 16-byte 'plst' payload.

use super::plst_class_check::ui_element_is_plst_class;

const PAYLOAD_BLOCK_STATE_OFFSET: usize = 0x1a4;

/// Original: `FUN_080613b4` @ 0x080613b4, 44 bytes, ending at the
/// independently decoded class-check entry 0x080613e0. Raw BL decoding
/// finds two inbound plain calls (0x0806131c, 0x080672dc), no predicated
/// calls, and one outbound plain call to `ui_element_is_plst_class`.
///
/// Returns 0 only for a 'plst' object whose halfword at +0x1a4 is zero;
/// otherwise returns 1, including for NULL and other classes. The class
/// check precedes the halfword load. Caller 0x08061058 masks the returned
/// payload when blocked; caller 0x080672d0 skips storing the four words
/// at +0x608..+0x614 when blocked. The precise meaning of the state
/// halfword is unknown; no stronger interpretation is assumed.
///
/// Deviations: none in behavior. Calls the existing Rust class predicate
/// rather than stock firmware. Uses an aligned unsigned halfword load,
/// matching the original `ldrh` (Ghidra describes a signed short).
///
/// # Safety
/// A non-NULL `element` must be word-aligned and readable through +0x7.
/// A 'plst' element must additionally be readable through +0x1a5.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn plst_payload_is_blocked(element: *const u8) -> u32 {
    if ui_element_is_plst_class(element) == 0 {
        return 1;
    }
    u32::from(element.add(PAYLOAD_BLOCK_STATE_OFFSET).cast::<u16>().read() != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_and_short_other_class_are_blocked_without_state_read() {
        assert_eq!(unsafe { plst_payload_is_blocked(core::ptr::null()) }, 1);
        let other = [0u32, 0x74646174];
        assert_eq!(unsafe { plst_payload_is_blocked(other.as_ptr().cast()) }, 1);
    }

    #[test]
    fn only_zero_state_allows_payload_and_adjacent_halfword_is_ignored() {
        let mut object = [0u32; 0x1a8 / 4];
        object[1] = 0x706c7374;
        for state in [0u16, 1, 0x100, 0x7fff, 0x8000, 0xffff] {
            object[PAYLOAD_BLOCK_STATE_OFFSET / 4] = 0xa55a0000 | u32::from(state);
            assert_eq!(
                unsafe { plst_payload_is_blocked(object.as_ptr().cast()) },
                if state == 0 { 0 } else { 1 },
                "state {state:#06x}"
            );
        }
    }
}
