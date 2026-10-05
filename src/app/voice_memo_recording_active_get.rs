//! Voice memo recording-active byte — retail `FUN_081a2eac` at `0x081a2eac`.
//! True size: 8 bytes, ending before the next push prologue at `0x081a2eb4`.
//! Raw A32: `e5d0008a` (ldrb r0,[r0,#0x8a]), `e12fff1e` (bx lr).
//! Whole-image decoding verifies two inbound plain BLs (`0x081263c0`,
//! `0x0815fc94`), zero inbound predicated BLs, and zero outbound BLs.
//!
//! Load and zero-extend the recording-active byte at controller +0x8a.
//! Both callers test nonzero; the getter itself preserves all byte values.
//! Deliberate deviations: none; no null check, boolean normalization, or seam.

/// Returns the raw recording-active byte, zero-extended to an ARM register.
///
/// # Safety
/// `controller` must point into an allocation readable through byte +0x8a.
/// No alignment requirement.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn voice_memo_recording_active_get(controller: *const u8) -> u32 {
    u32::from(controller.add(0x8a).read())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_byte_is_zero_extended_without_mutating_controller() {
        for alignment in 0..4 {
            let mut storage = [0xa5u8; 0x8e];
            for active in 0..=255u8 {
                storage[alignment + 0x8a] = active;
                let before = storage;
                assert_eq!(unsafe {
                    voice_memo_recording_active_get(storage.as_ptr().add(alignment))
                }, u32::from(active));
                assert_eq!(storage, before);
            }
        }
    }

    #[test]
    fn activity_changes_are_observed_with_no_trailing_storage() {
        let mut controller = [0xffu8; 0x8b];
        for active in [0, 1, 0x80, 0xff, 0] {
            controller[0x8a] = active;
            assert_eq!(unsafe { voice_memo_recording_active_get(controller.as_ptr()) },
                u32::from(active));
        }
    }
}
