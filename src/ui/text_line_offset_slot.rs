//! `text_line_offset_slot` — original: `FUN_080f8690` @ `0x080f8690`.
//! The raw `osos.dec` body is exactly **28 bytes** (`0x080f8690..0x080f86ac`):
//! seven ARM words ending in `bx lr`; the distinct next function starts with
//! `push {r4,lr}` at `0x080f86ac`. Decoding every aligned ARM B/BL-immediate
//! in `osos.dec` finds exactly **5 direct inbound `bl` call sites**, all
//! unconditional (`0x080f827c`, `0x080f82e4`, `0x080f8614`, `0x080f862c`, and
//! `0x080f8680`); there are no predicated BL calls. This leaf has no calls.
//!
//! # Algorithm
//!
//! Read the layout's line base at `+0x00`, read its target-width record pointer
//! at `+0x08`, then read that record's unsigned offset at `+0x1c`. Return the
//! address `line_base + offset - 2 * line_index - 2`, using ARM's wrapping
//! 32-bit arithmetic. Callers use the returned address as a `u16` line-offset
//! slot.
//!
//! # Deliberate deviations
//!
//! The encompassing layout type and record identity are not yet recovered, so
//! this port exposes only the verified three-word prefix. The record pointer
//! remains a `u32` target-width field rather than a host pointer.

/// Verified target-width prefix consumed by `text_line_offset_slot`.
#[repr(C)]
pub struct TextLineOffsetLayout {
    pub line_base: u32,
    pub _word_at_4: u32,
    pub offset_record: u32,
}

/// Returns the indexed line-offset slot in a layout record.
///
/// # Safety
///
/// `layout` must be non-NULL and readable through `+0x0b`; its target-width
/// `offset_record` must point to readable storage through `+0x1d`. The
/// resulting address must be a valid aligned `u16` slot before dereferencing.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn text_line_offset_slot(
    layout: *const TextLineOffsetLayout,
    line_index: u32,
) -> *mut u16 {
    let line_base = (*layout).line_base;
    let offset_record = (*layout).offset_record as usize as *const u8;
    let offset = offset_record.add(0x1c).cast::<u16>().read() as u32;
    line_base
        .wrapping_add(offset)
        .wrapping_sub(line_index.wrapping_mul(2))
        .wrapping_sub(2) as usize as *mut u16
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const FIXTURE_BYTES: usize = 0x1000;
    const SLOT_OFFSET: usize = 0x100;
    const RECORD_OFFSET: usize = 0x200;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::UI_TEXT_LINE_OFFSET_SLOT, FIXTURE_BYTES).map(|storage| storage as usize)
    });

    #[test]
    fn derives_slots_from_record_offsets_and_wrapping_indices() {
        let Some(storage) = *FIXTURE else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let storage = storage as *mut u8;
        let slot = unsafe { storage.add(SLOT_OFFSET).cast::<u16>() };
        let record = unsafe { storage.add(RECORD_OFFSET) };
        let line_index = 3u32;

        for offset in [0, 1, 0x7fff, u16::MAX] {
            unsafe { record.add(0x1c).cast::<u16>().write(offset) };
            let line_base = (slot as usize as u32)
                .wrapping_add(2)
                .wrapping_add(line_index.wrapping_mul(2))
                .wrapping_sub(offset as u32);
            let layout = TextLineOffsetLayout {
                line_base,
                _word_at_4: 0xa5a5_a5a5,
                offset_record: record as usize as u32,
            };

            let actual = unsafe { text_line_offset_slot(&layout, line_index) };
            assert_eq!(actual, slot);
        }

        let layout = TextLineOffsetLayout {
            line_base: 0,
            _word_at_4: 0,
            offset_record: record as usize as u32,
        };
        unsafe { record.add(0x1c).cast::<u16>().write(0) };
        assert_eq!(unsafe { text_line_offset_slot(&layout, 0) } as usize as u32, u32::MAX - 1);
    }
}
