//! `class_8900_set_playback_selection` — `FUN_081eda64` @ 0x081eda64.
//! True size: 48 bytes; next real function starts at 0x081eda94.
//! Whole-image raw A32 scan: two incoming plain BLs at 0x08237940 and
//! 0x082379bc, no predicated BLs. One outgoing plain BL to 0x08171ff8,
//! no predicated BLs, and a tail B to 0x0817209c.
//!
//! Obtain the store's playback settings, truncate the selection to byte +5,
//! write the two payload words at +8/+12, reload the object's store, and
//! apply all settings through the stock routine at 0x0817209c. The payload's
//! domain is not established; retain its two-word ABI rather than inventing
//! a u64 argument (which would change ARM argument alignment).
//!
//! Deliberate deviations: reuse Class8900's host-width pointer layout;
//! express STRD as two aligned word writes and the tail B as call-and-return.
//! The unported settings application routine remains a fixed-address seam.

use crate::app::class_8900::Class8900;
use crate::app::registry::instance_6000_settings_block;

#[inline(always)]
unsafe fn set_selection(
    this: *const Class8900,
    selection: u32,
    payload_low: u32,
    payload_high: u32,
    apply: impl FnOnce(*mut u8),
) {
    let settings = instance_6000_settings_block((*this).store.cast());
    settings.add(5).write(selection as u8);
    settings.add(8).cast::<u32>().write(payload_low);
    settings.add(12).cast::<u32>().write(payload_high);
    apply((*this).store.cast());
}

/// Updates playback selection and applies the complete settings record.
///
/// # Safety
/// `this` must contain a valid store with writable, word-aligned settings
/// through +0x70. Must run in retailOS with its application routine and
/// global media-player state initialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_set_playback_selection(
    this: *const Class8900,
    selection: u32,
    payload_low: u32,
    payload_high: u32,
) {
    let apply: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0817_209cusize);
    set_selection(this, selection, payload_low, payload_high, |store| apply(store));
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn truncates_selection_preserves_neighbors_and_applies_completed_record() {
        for selection in [0, 1, 6, 255, 256, 0x1234_5680, u32::MAX] {
            for (low, high) in [(0, 0), (u32::MAX, 0), (0, u32::MAX), (0x1234_5678, 0x9abc_def0)] {
                let mut store = [0xa5a5_a5a5u32; 0x74 / 4];
                let bytes = store.as_mut_ptr().cast::<u8>();
                let object = Class8900 {
                    vtable: ptr::null(),
                    state_below_cache: [0; 11],
                    cached_6031: 0,
                    state_below_store: [0; 209],
                    store: bytes.cast(),
                };
                let mut expected = [0xa5u8; 0x74];
                expected[0x65] = selection as u8;
                expected[0x68..0x6c].copy_from_slice(&low.to_ne_bytes());
                expected[0x6c..0x70].copy_from_slice(&high.to_ne_bytes());
                unsafe {
                    set_selection(&object, selection, low, high, |applied_store| {
                        let actual = core::slice::from_raw_parts(applied_store, 0x74);
                        assert_eq!(actual, &expected, "application must see all writes, and no other changes");
                        // Model the consumer modifying a different preference: no
                        // deferred write in the setter may overwrite that change.
                        applied_store.add(0x64).write(0x19);
                    });
                    expected[0x64] = 0x19;
                    assert_eq!(core::slice::from_raw_parts(bytes, 0x74), &expected);
                }
            }
        }
    }
}
