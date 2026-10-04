//! `class_8900_playback_selection` — `FUN_081eda40` @ 0x081eda40.
//! True size: 36 bytes; next real function begins at 0x081eda64.
//! Raw A32 scan: two incoming plain BLs (0x0810ccc0, 0x08237574),
//! zero predicated BLs; one outgoing plain BL to 0x08171ff8.
//!
//! Load the class-0x6000 store at this+0x378 and obtain settings at +0x60.
//! Snapshot the payload words at settings+8/+12, write them to the output,
//! then return the signed selection byte at settings+5. Callers use the
//! selection to choose a playback item; the payload's full domain remains
//! unrecovered. Output may overlap settings: the final byte read is after
//! both writes, matching stock.
//!
//! Deliberate deviations: reuse the repr(C) Class8900 host-pointer layout
//! and existing settings accessor; express STM as two aligned word writes.
//! No NULL guards, selection normalization, or payload interpretation added.

use crate::app::class_8900::Class8900;
use crate::app::registry::instance_6000_settings_block;

/// Returns the signed playback selection and copies its two-word payload.
///
/// # Safety
/// `this` must contain a valid store readable through +0x70, with word-aligned
/// payload fields. `payload` must permit two aligned u32 writes. Overlap with
/// the writable settings record is allowed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_playback_selection(
    this: *const Class8900,
    payload: *mut u32,
) -> i32 {
    let settings = instance_6000_settings_block((*this).store.cast());
    let low = settings.add(8).cast::<u32>().read();
    let high = settings.add(12).cast::<u32>().read();
    payload.write(low);
    payload.add(1).write(high);
    settings.add(5).cast::<i8>().read() as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    fn object(store: *mut u8) -> Class8900 {
        Class8900 {
            vtable: ptr::null(), state_below_cache: [0; 11], cached_6031: 0,
            state_below_store: [0; 209], store: store.cast(),
        }
    }

    #[test]
    fn signed_selection_and_exact_payload_preserve_neighbors() {
        for selection in [0u8, 1, 2, 3, 4, 5, 6, 0x7f, 0x80, 0xfe, 0xff] {
            for (low, high) in [(0, u32::MAX), (u32::MAX, 0), (0x1234_5678, 0x9abc_def0)] {
                let mut store = [0xa5a5_a5a5u32; 0x74 / 4];
                let bytes = store.as_mut_ptr().cast::<u8>();
                unsafe { bytes.add(0x65).write(selection); }
                store[0x68 / 4] = low;
                store[0x6c / 4] = high;
                let before = store;
                let mut output = [0x5555_5555u32; 4];
                let result = unsafe { class_8900_playback_selection(&object(bytes), output.as_mut_ptr().add(1)) };
                assert_eq!(result, selection as i8 as i32);
                assert_eq!(output, [0x5555_5555, low, high, 0x5555_5555]);
                assert_eq!(store, before);
            }
        }
    }

    #[test]
    fn overlapping_output_snapshots_both_words_then_reads_selection() {
        for offset in [4usize, 8, 12] {
            let mut store = [0xa5a5_a5a5u32; 0x78 / 4];
            let bytes = store.as_mut_ptr().cast::<u8>();
            unsafe { bytes.add(0x65).write(6); }
            store[0x68 / 4] = 0x1234_fe78;
            store[0x6c / 4] = 0x9abc_def0;
            let mut expected = store;
            expected[(0x60 + offset) / 4] = 0x1234_fe78;
            expected[(0x64 + offset) / 4] = 0x9abc_def0;
            let expected_selection = if offset == 4 { -2 } else { 6 };
            let result = unsafe {
                class_8900_playback_selection(&object(bytes), bytes.add(0x60 + offset).cast())
            };
            assert_eq!(result, expected_selection);
            assert_eq!(store, expected);
        }
    }
}
