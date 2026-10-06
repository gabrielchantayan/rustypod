//! Tests whether a resource's controller category slot is available.
//!
//! `app_controller_resource_slot_available` — original: `FUN_08180f9c` @
//! **0x08180f9c**. Raw ARM establishes the **52-byte** extent
//! `0x08180f9c..0x08180fd0`, where the next independent push begins.
//! There is one outbound plain `bl` (to `0x081842e8`) and no predicated
//! BL instructions. Whole-image A32 decoding finds two inbound plain BL
//! sites, at `0x0817f504` and `0x08180a34`, and no predicated BL callers.
//!
//! # Algorithm
//!
//! Read the resource category byte at `+0x11d`, map it through the existing
//! `controller_event_category_index`, and return 1 exactly when the category
//! is valid and its controller active byte at `+0xd4 + slot` is zero.
//! Invalid categories return 0 without accessing the controller's fields.
//!
//! # Deliberate deviations
//!
//! None semantically. Rust preserves the controller across the helper call
//! using its normal ABI rather than relying on the stock helper leaving r2
//! untouched. Object offsets remain byte offsets on both ARM and the host.

use crate::app::controller_event_category_index::controller_event_category_index;

/// # Safety
/// `resource` must have a readable byte at `+0x11d`. For categories 1..4,
/// `controller` must have a readable active byte at `+0xd4 + category - 1`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_controller_resource_slot_available(
    controller: *mut u8,
    resource: *const u8,
) -> u32 {
    let category = unsafe { resource.add(0x11d).read() };
    let slot = controller_event_category_index(controller, category as u32);
    if slot == -1 {
        return 0;
    }
    u32::from(unsafe { controller.add(0xd4 + slot as usize).read() } == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_category_checks_only_its_own_slot_for_exact_zero() {
        let mut resource = [0u8; 0x11e];
        for category in 1u8..=4 {
            resource[0x11d] = category;
            for active in [0, 1, 0x7f, 0x80, 0xff] {
                let mut controller = [0xa5u8; 0xd8];
                controller[0xd4 + category as usize - 1] = active;
                let original = controller;
                assert_eq!(unsafe {
                    app_controller_resource_slot_available(controller.as_mut_ptr(), resource.as_ptr())
                }, u32::from(active == 0));
                assert_eq!(controller, original);
            }
        }
    }

    #[test]
    fn every_invalid_byte_category_skips_controller_access() {
        let mut resource = [0u8; 0x11e];
        for category in 0u8..=255 {
            if (1..=4).contains(&category) {
                continue;
            }
            resource[0x11d] = category;
            assert_eq!(unsafe {
                app_controller_resource_slot_available(core::ptr::null_mut(), resource.as_ptr())
            }, 0);
        }
    }
}
