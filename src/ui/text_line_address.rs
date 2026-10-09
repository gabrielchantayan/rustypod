//! `text_line_address` — original: `FUN_080f86ac` @ `0x080f86ac`.
//! True size: **24 bytes** (`0x080f86ac..0x080f86c4`), six ARM words ending
//! in `pop {r4,pc}` before the next function's `push {r4,r5,r6,lr}`.
//! Raw ARM decoding finds two plain inbound BLs (0x080f85a8, 0x080f85c0),
//! no predicated inbound BLs, and one plain outbound BL to 0x080f867c.
//!
//! Read the indexed big-endian line offset through `text_line_offset_read_be`,
//! then add the layout's line base with wrapping 32-bit arithmetic. Ghidra
//! omits the live r1 line-index argument. Callers use the result as a byte address.
//!
//! Deliberate deviations: return the target address as u32 rather than a host
//! pointer; retain the existing verified three-word layout prefix. No algorithm
//! changes or additional validation.

use crate::ui::text_line_offset_read_be::text_line_offset_read_be;
use crate::ui::text_line_offset_slot::TextLineOffsetLayout;

/// Returns the target byte address of the indexed line.
///
/// # Safety
/// `layout` must meet `text_line_offset_read_be`'s requirements, including a
/// readable aligned offset slot. The returned address is not dereferenced here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn text_line_address(
    layout: *const TextLineOffsetLayout,
    line_index: u32,
) -> u32 {
    let offset = text_line_offset_read_be(layout, line_index);
    offset.wrapping_add((*layout).line_base)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn indexed_big_endian_offsets_and_address_wrap() {
        let Some(storage) = try_map_u32_slab(hints::UI_TEXT_LINE_ADDRESS, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let record = unsafe { storage.add(0x200) };
        let slots = unsafe { storage.add(0x100).cast::<u16>() };
        let values = [0u16, 1, 0x1234, 0x8000, 0xffff];
        for (index, value) in values.iter().enumerate() {
            unsafe { slots.add(index).write(value.swap_bytes()) };
        }
        // Choose indices that place each slot at a real mapped address while
        // allowing arbitrary line bases, including carry across 2^32.
        for line_base in [0u32, 1, 0x08000000, 0xffff8000, 0xffffffff] {
            let record_offset = ((slots as usize as u32).wrapping_sub(line_base) & 1) as u16;
            unsafe { record.add(0x1c).cast::<u16>().write(record_offset) };
            let layout = TextLineOffsetLayout {
                line_base,
                _word_at_4: 0,
                offset_record: record as usize as u32,
            };
            for (slot_index, value) in values.iter().enumerate() {
                let slot_address = unsafe { slots.add(slot_index) } as usize as u32;
                let index = line_base.wrapping_add(record_offset as u32)
                    .wrapping_sub(slot_address).wrapping_sub(2) / 2;
                let expected = ((line_base as u64 + *value as u64) & 0xffffffff) as u32;
                assert_eq!(unsafe { text_line_address(&layout, index) }, expected);
            }
        }
    }
}
