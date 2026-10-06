//! Indexed item lookup through an owner's embedded UI element reference.

use crate::ui::element_reference_item::ui_element_reference_item_at;

/// ui_owner_reference_item_at — original: FUN_0817bb2c @ 0x0817bb2c.
/// True extent: 8 bytes, ending at the next function's push at 0x0817bb34.
/// Raw words: e2800060 (add r0,r0,#0x60), ea04a95c (b 0x082a60a8).
/// Whole-image ARM branch decoding finds two plain BL callers (0x08064958,
/// 0x080673e8), zero predicated BL callers, and one B caller (0x081003c0).
/// No outgoing BL: adjusts the owner to its embedded reference at +0x60,
/// preserves the index, and tail-transfers to ui_element_reference_item_at.
/// Deliberate deviations: none; reference resolution and item selection use
/// the existing callee port, including its documented host vtable layout.
///
/// # Safety
/// `owner + 0x60` must satisfy ui_element_reference_item_at's requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_owner_reference_item_at(owner: *const u8, index: u32) -> u32 {
    ui_element_reference_item_at(owner.add(0x60), index)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    unsafe extern "C" fn resolve(reference: *const u8) -> u32 {
        // A zero target models failed resolution without dereferencing it.
        (reference.add(4).cast::<u32>().read() != 0) as u32
    }

    #[test]
    fn embedded_reference_resolution_selection_and_index_boundaries() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::OWNER_REFERENCE_ITEM, 0x4000,
        ) else { return; };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x4000);
            let reference = slab.add(0x60);
            let vtable = slab.add(0x100);
            let element = slab.add(0x400);
            let header = slab.add(0x1000);
            let first = slab.add(0x2000);
            let second = slab.add(0x3000);
            reference.cast::<u32>().write(vtable as u32);
            vtable.add(0x0c).cast::<unsafe extern "C" fn(*const u8) -> u32>()
                .write_unaligned(resolve);
            assert_eq!(ui_owner_reference_item_at(slab, u32::MAX), 0);
            reference.add(4).cast::<u32>().write(element as u32);
            element.add(4).cast::<u32>().write(0x706c7374);
            element.add(0x40).cast::<u32>().write(header as u32);
            header.add(0x2e).cast::<u16>().write(3);
            element.add(0x3b0).cast::<u32>().write(first as u32);
            element.add(0x3b4).cast::<u32>().write(second as u32);
            for i in 0..3 {
                first.add(0x10 + i * 4).cast::<u32>().write(100 + i as u32);
                second.add(0x10 + i * 4).cast::<u32>().write(200 + i as u32);
            }
            for selector_flag in [0u8, 1] {
                element.add(0x18c).write(selector_flag);
                for reverse in [0u8, 4] {
                    element.add(0x18d).write(reverse);
                    for index in 0..3u32 {
                        let selected = if reverse == 0 { index } else { 2 - index };
                        let base = if selector_flag == 0 { 100 } else { 200 };
                        assert_eq!(ui_owner_reference_item_at(slab, index), base + selected);
                    }
                    assert_eq!(ui_owner_reference_item_at(slab, 3), 0);
                    assert_eq!(ui_owner_reference_item_at(slab, u32::MAX), 0);
                }
            }
            element.add(4).cast::<u32>().write(0);
            assert_eq!(ui_owner_reference_item_at(slab, 0), 0);
        }
    }
}
