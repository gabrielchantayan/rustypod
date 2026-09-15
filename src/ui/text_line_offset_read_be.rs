//! `text_line_offset_read_be` — original: `FUN_080f867c` @ `0x080f867c`.
//! The raw `osos.dec` body is exactly **20 bytes** (`0x080f867c..0x080f8690`):
//! `push {r4,lr}`, one `bl` to `0x080f8690`, `ldrh r0,[r0]`, restored
//! registers, then a tail `b` to `bswap16` (`0x0805dd48`). The next function
//! begins at `0x080f8690` with `ldr r2,[r0]`. Raw ARM B/BL decoding finds five
//! direct inbound plain `bl` callers and no predicated `bl` callers; this body
//! makes one plain outbound `bl` plus its tail branch.
//!
//! # Algorithm
//!
//! Locate a line-offset slot with `text_line_offset_slot`, load its native-endian
//! halfword, then tail-call `bswap16`; consequently this reads a big-endian
//! unsigned line offset.
//!
//! # Deliberate deviations
//!
//! The original tail-branches to the separately ported `bswap16`; this source
//! expresses that as a Rust call, which LLVM inlines into shifts, ORs, and a
//! low-half mask. The observable return value and zero extension are unchanged.

use crate::ui::text_line_offset_slot::{text_line_offset_slot, TextLineOffsetLayout};
use crate::util::bswap::bswap16;

/// Reads the big-endian line offset for `line_index`.
///
/// # Safety
///
/// `layout` and its target-width record pointer must meet
/// [`text_line_offset_slot`]'s requirements; the resulting slot must be valid
/// for an aligned `u16` read.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn text_line_offset_read_be(
    layout: *const TextLineOffsetLayout,
    line_index: u32,
) -> u32 {
    bswap16(text_line_offset_slot(layout, line_index).read() as u32)
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
        try_map_u32_slab(hints::UI_TEXT_LINE_OFFSET_READ_BE, FIXTURE_BYTES)
            .map(|storage| storage as usize)
    });

    #[test]
    fn reads_big_endian_offsets_at_indexed_slots() {
        let Some(storage) = *FIXTURE else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let storage = storage as *mut u8;
        let slot = unsafe { storage.add(SLOT_OFFSET).cast::<u16>() };
        let record = unsafe { storage.add(RECORD_OFFSET) };
        let line_index = 3u32;

        for record_offset in [0, 1, 0x7fff, u16::MAX] {
            unsafe { record.add(0x1c).cast::<u16>().write(record_offset) };
            let line_base = (slot as usize as u32)
                .wrapping_add(2)
                .wrapping_add(line_index.wrapping_mul(2))
                .wrapping_sub(record_offset as u32);
            let layout = TextLineOffsetLayout {
                line_base,
                _word_at_4: 0,
                offset_record: record as usize as u32,
            };

            for value in [0, 1, 0x7fff, u16::MAX] {
                unsafe { slot.write(value.swap_bytes()) };
                assert_eq!(unsafe { text_line_offset_read_be(&layout, line_index) }, value as u32);
            }
        }
    }
}
