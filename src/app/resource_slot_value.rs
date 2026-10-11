//! Resource-slot value query — `FUN_0805382c` @ `0x0805382c`.
//!
//! True extent: 36 bytes, `0x0805382c..0x08053850`; the next function
//! starts with `push {r4,r5,lr}`. Whole-image aligned A32 decoding verifies
//! two inbound plain BLs (0x08112404, 0x08112424), zero predicated BLs,
//! and zero outgoing calls. For an unsigned slot index below four, read
//! the controller's four-byte handle entry at +0xf7c and return the handle's
//! aligned word at +8. Invalid indices and null handles return zero.
//! The caller compares slot zero's value with one; its finer meaning is
//! unrecovered. No deliberate algorithm deviations; stored pointers remain
//! u32 on hosts too, rather than widening the firmware table layout.

/// Returns the selected resource handle's value, or zero if absent.
///
/// # Safety
/// For `slot_index < 4`, `controller` must contain the aligned readable
/// selected u32 entry at +0xf7c. A nonzero entry must point to an aligned
/// readable u32 at handle +8. Invalid indices do not access `controller`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_slot_value(controller: *const u32, slot_index: u32) -> u32 {
    if slot_index > 3 {
        return 0;
    }
    let handle = unsafe { controller.add(0xf7c / 4 + slot_index as usize).read() };
    if handle == 0 {
        return 0;
    }
    unsafe { (handle as usize as *const u32).add(2).read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_unsigned_indices_do_not_access_controller() {
        for index in [4, 5, 0x8000_0000, u32::MAX] {
            assert_eq!(unsafe { resource_slot_value(core::ptr::null(), index) }, 0);
        }
    }

    #[test]
    fn absent_handles_return_zero() {
        let controller = [0u32; 0xf8c / 4];
        for index in 0..4 {
            assert_eq!(unsafe { resource_slot_value(controller.as_ptr(), index) }, 0);
        }
    }

    #[test]
    fn selects_four_byte_entries_and_preserves_full_value() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::RESOURCE_SLOT_VALUE, 4096,
        ) else {
            crate::testing::note_missing_u32_fixture("app::resource_slot_value");
            return;
        };
        let mut controller = [0xa5a5_a5a5u32; 0xf8c / 4];
        let values = [0, 1, 0x8000_0001, u32::MAX];
        for (index, value) in values.into_iter().enumerate() {
            unsafe {
                let handle = slab.cast::<u32>().add(index * 4);
                handle.write(0x1122_3344);
                handle.add(1).write(0x5566_7788);
                handle.add(2).write(value);
                handle.add(3).write(0x99aa_bbcc);
                controller[0xf7c / 4 + index] = handle as usize as u32;
            }
        }
        let before = controller;
        for (index, value) in values.into_iter().enumerate() {
            assert_eq!(unsafe { resource_slot_value(controller.as_ptr(), index as u32) }, value);
        }
        assert_eq!(controller, before);
        unsafe {
            slab.cast::<u32>().add(2).write(0x1234_5678);
        }
        assert_eq!(unsafe { resource_slot_value(controller.as_ptr(), 0) }, 0x1234_5678);
    }
}
