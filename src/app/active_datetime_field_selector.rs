//! Active date/time field selector — retail `FUN_081dd80c` at `0x081dd80c`.
//! True size: 56 bytes, ending at `0x081dd844`, the next function's push.
//! Raw A32 words verify two inbound plain BLs (`0x081dd75c`, `0x081dd864`),
//! no inbound predicated BLs, and zero outbound BLs of either kind.
//!
//! Read controller mode at +0x138. Modes 0, 1, and 2 select the target-width
//! pointer at +0x140, +0x144, or +0x148; return that object's word at +0x44.
//! All other modes return zero without reading a selector pointer.
//! Deliberate deviations: volatile aligned word reads retain the existing
//! controller-access convention; no algorithm or null-handling changes.

/// Returns the active selector object's date/time field code, or zero for an
/// unsupported controller mode.
///
/// # Safety
/// `controller` is word-aligned and readable through +0x13b. For modes 0..=2,
/// the selected pointer word and its aligned pointee through +0x47 are valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn active_datetime_field_selector(controller: *const u8) -> u32 {
    let mode = controller.add(0x138).cast::<u32>().read_volatile();
    let offset = match mode {
        0 => 0x140,
        1 => 0x144,
        2 => 0x148,
        _ => return 0,
    };
    let selector = controller.add(offset).cast::<u32>().read_volatile();
    (selector as usize as *const u32).add(0x44 / 4).read_volatile()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_each_target_width_pointer_and_preserves_field_bits() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::ACTIVE_DATETIME_FIELD_SELECTOR, 0x400,
        ).expect("target-width selector fixture");
        unsafe {
            slab.write_bytes(0, 0x400);
            let values = [0x2d01, 0, 0xffff_ffff];
            for (mode, value) in values.into_iter().enumerate() {
                let selector = slab.add(0x200 + mode * 0x80);
                slab.add(0x140 + mode * 4).cast::<u32>().write(selector as usize as u32);
                selector.add(0x44).cast::<u32>().write(value);
            }
            for (mode, expected) in values.into_iter().enumerate() {
                slab.add(0x138).cast::<u32>().write(mode as u32);
                assert_eq!(active_datetime_field_selector(slab), expected);
            }
        }
    }

    #[test]
    fn unsupported_modes_do_not_require_selector_storage() {
        // Ends immediately after the mode word: even forming a selected slot
        // access here would exceed the caller's valid controller storage.
        let mut controller = [0u32; 0x13c / 4];
        for mode in [3, 4, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            controller[0x138 / 4] = mode;
            assert_eq!(unsafe {
                active_datetime_field_selector(controller.as_ptr().cast())
            }, 0);
        }
    }
}
