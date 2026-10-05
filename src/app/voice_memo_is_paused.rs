//! Voice memo paused predicate — retail `FUN_081a4028` at `0x081a4028`.
//! True size: 28 bytes, ending at the next function's push at `0x081a4044`.
//! Raw A32 decoding verifies two inbound plain BLs (`0x0815fd7c`,
//! `0x081a4a34`), zero inbound predicated BLs, and zero outbound BLs.
//!
//! Return 1 exactly when the recording-active byte at +0x8a and the paused
//! byte at +0x8c are both nonzero. Do not read +0x8c when inactive.
//! The status-label caller selects "VoiceMemos Paused" for a true result.
//! Deliberate deviations: volatile byte reads preserve the conditional memory
//! access in LLVM codegen; no algorithm, layout, or null-handling changes.

/// Tests whether an active voice memo recording is paused.
///
/// # Safety
/// `controller` is readable through +0x8a, and through +0x8c if the
/// recording-active byte is nonzero. No alignment requirement.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn voice_memo_is_paused(controller: *const u8) -> u32 {
    if controller.add(0x8a).read_volatile() == 0 {
        return 0;
    }
    (controller.add(0x8c).read_volatile() != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_byte_values_match_nonzero_conjunction_without_mutation() {
        let mut controller = [0xa5u8; 0x90];
        for active in 0..=255u8 {
            for paused in 0..=255u8 {
                controller[0x8a] = active;
                controller[0x8c] = paused;
                let before = controller;
                assert_eq!(unsafe { voice_memo_is_paused(controller.as_ptr()) },
                    u32::from(active != 0 && paused != 0));
                assert_eq!(controller, before);
            }
        }
    }

    #[test]
    fn inactive_controller_does_not_need_paused_storage() {
        let mut controller = [0xffu8; 0x8b];
        controller[0x8a] = 0;
        assert_eq!(unsafe { voice_memo_is_paused(controller.as_ptr()) }, 0);
    }
}
