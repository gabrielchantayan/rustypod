//! Class-gated access to a 'tdat' element's node-list head.

use super::tdat_class_check::ui_element_is_tdat_class;

/// `tdat_node_list_head` — `FUN_080522fc` @ 0x080522fc, 24 bytes.
///
/// Raw extent [0x080522fc, 0x08052314); the next function starts with
/// `ldr r0,[r0,#0xf64]`. Words: e1a02000 e52de004 eb0061cc e1b00000
/// 15920028 e49df004: preserve element, call the class predicate, conditionally
/// load the head word at +0x28, return. Whole-image word decoding verifies
/// two plain inbound BLs (0x08050cd8, 0x08050d4c), zero predicated; one plain
/// outbound BL to 0x0806aa3c, zero predicated.
///
/// Return the head word unchanged for a 'tdat' object, otherwise zero without
/// reading the head. Deliberate deviations: call the existing Rust class
/// predicate directly; no behavioral changes. Keep a real exported BL target.
///
/// # Safety
/// `element` may be NULL. Non-NULL elements must have a readable aligned class
/// word at +4; accepted elements must also have a readable aligned word at +0x28.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tdat_node_list_head")]
#[inline(never)]
pub unsafe extern "C" fn tdat_node_list_head(element: *const u8) -> u32 {
    if ui_element_is_tdat_class(element) != 0 {
        element.add(0x28).cast::<u32>().read()
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_objects_need_no_head_storage() {
        assert_eq!(unsafe { tdat_node_list_head(core::ptr::null()) }, 0);
        for tag in [0, 0x706c_7374, 0x7464_6175, u32::MAX] {
            let prefix = [0u32, tag];
            assert_eq!(unsafe { tdat_node_list_head(prefix.as_ptr().cast()) }, 0);
        }
    }

    #[test]
    fn accepted_class_returns_exact_head_not_adjacent_fields() {
        let mut element = [0xdead_beefu32; 14];
        element[1] = 0x7464_6174;
        element[0x34 / 4] = 0x1122_3344;
        for head in [0, 1, 0x0805_3d54, 0x8000_0000, u32::MAX] {
            element[0x28 / 4] = head;
            assert_eq!(unsafe { tdat_node_list_head(element.as_ptr().cast()) }, head);
        }
        element[1] = 0x706c_7374;
        assert_eq!(unsafe { tdat_node_list_head(element.as_ptr().cast()) }, 0);
    }
}
