//! Clear the state word on every node attached to a 'tdat' element.

use super::tdat_class_check::ui_element_is_tdat_class;

/// ui_tdat_clear_node_state — original: `FUN_0806c1f8` @ 0x0806c1f8.
/// True extent: 48 bytes, ending at the next prologue at 0x0806c228.
/// Raw aligned ARM BL decoding: 2 incoming plain BLs (0x0806c1bc,
/// 0x0806d6d8), 0 predicated; 1 outgoing plain BL to 0x0806aa3c.
///
/// Reject NULL and non-'tdat' elements. Otherwise load the target-width list
/// head at element+0x28, clear the word at each node+0x20, and follow its
/// target-width successor at node+4 until NULL. The caller at 0x0806c1a4
/// separately resets the 'plst' list; this function only touches this list.
/// Deliberate deviation: call the existing Rust class predicate directly,
/// rather than stock firmware. Aligned u32 fields preserve target offsets on
/// hosts; no allocation, node-class validation, or cycle detection is added.
///
/// Verification: independent whole-image A32 decoding confirms both incoming
/// BLs and the sole outgoing BL, with no predicated BLs. Host suite, ARM
/// release build, and executable single-node smoke pass. match.py reports
/// 12 stock versus 14 Rust instructions: frame setup and loop predication
/// differ, while the class gate, +0x28 head, +0x20 clear, and +4 link remain.
///
/// # Safety
/// A non-NULL element must be aligned and readable through +7. A 'tdat'
/// element must additionally be readable through +0x2b. Its list must be
/// finite, with aligned valid u32 pointers to nodes readable through +7 and
/// writable through +0x23, exclusively accessible during this call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_tdat_clear_node_state(element: *const u8) {
    if ui_element_is_tdat_class(element) == 0 {
        return;
    }
    let mut node = element.add(0x28).cast::<u32>().read();
    while node != 0 {
        let words = node as usize as *mut u32;
        words.add(0x20 / 4).write(0);
        node = words.add(1).read();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn rejects_null_and_short_wrong_class_without_reading_head() {
        unsafe {
            ui_tdat_clear_node_state(core::ptr::null());
            let object = [0xfeed_beefu32, 0x706c_7374];
            ui_tdat_clear_node_state(object.as_ptr().cast());
            assert_eq!(object, [0xfeed_beef, 0x706c_7374]);
        }
    }

    #[test]
    fn empty_list_preserves_element() {
        let mut element = [0xdead_beefu32; 11];
        element[1] = 0x7464_6174;
        element[10] = 0;
        let before = element;
        unsafe { ui_tdat_clear_node_state(element.as_ptr().cast()); }
        assert_eq!(element, before);
    }

    #[test]
    fn clears_only_reachable_state_words_and_preserves_links() {
        let Some(base) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TDAT_NODE_CLEAR_STATE, 4096,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let element = base.cast::<u32>();
            let first = base.add(0x100).cast::<u32>();
            let second = base.add(0x200).cast::<u32>();
            let unreachable = base.add(0x300).cast::<u32>();
            let mut expected_element = [0xa5a5_a5a5u32; 11];
            expected_element[1] = 0x7464_6174;
            expected_element[10] = first as usize as u32;
            core::ptr::copy_nonoverlapping(expected_element.as_ptr(), element, 11);
            let mut expected_first = [0x1122_3344u32; 10];
            expected_first[1] = second as usize as u32;
            let mut expected_second = [0xffff_ffffu32; 10];
            expected_second[1] = 0;
            core::ptr::copy_nonoverlapping(expected_first.as_ptr(), first, 10);
            core::ptr::copy_nonoverlapping(expected_second.as_ptr(), second, 10);
            core::ptr::copy_nonoverlapping(expected_first.as_ptr(), unreachable, 10);
            // Rejected class must leave even a populated list unchanged.
            element.add(1).write(0);
            ui_tdat_clear_node_state(base);
            assert_eq!(core::slice::from_raw_parts(first, 10), &expected_first);
            element.add(1).write(0x7464_6174);
            ui_tdat_clear_node_state(base);
            assert_eq!(core::slice::from_raw_parts(unreachable, 10), &expected_first);
            expected_first[8] = 0;
            expected_second[8] = 0;
            assert_eq!(core::slice::from_raw_parts(first, 10), &expected_first);
            assert_eq!(core::slice::from_raw_parts(second, 10), &expected_second);
            assert_eq!(core::slice::from_raw_parts(element, 11), &expected_element);
            // Repeating the reset leaves links and all other fields intact.
            ui_tdat_clear_node_state(base);
            assert_eq!(core::slice::from_raw_parts(first, 10), &expected_first);
            assert_eq!(core::slice::from_raw_parts(second, 10), &expected_second);
        }
    }
}
