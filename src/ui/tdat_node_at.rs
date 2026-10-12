//! Indexed lookup in the 'tdat' master-track node list.

use super::tdat_class_check::ui_element_is_tdat_class;

/// ui_tdat_node_at — original: `FUN_080528ac` @ 0x080528ac.
/// True extent: 64 bytes, 0x080528ac..0x080528ec; the next word is a
/// separate function's `push {r4,r5,r6,r7,r8,lr}` prologue.
/// Whole-image aligned A32 decoding finds 2 incoming plain BLs at
/// 0x080ab0c4 and 0x080ab41c, 0 predicated BLs. The body has 1 plain
/// outgoing BL to the 'tdat' class predicate at 0x0806aa3c, 0 predicated.
///
/// Reject NULL/non-'tdat' elements and unsigned indices >= the count at
/// element+0x24. Otherwise load the head at +0x28 and follow exactly
/// `index` raw successor words at node+4. Return the selected target pointer.
/// The callers restore playlist tracks from serialized master-track indices.
/// No node-class gate or early NULL termination exists in the original.
/// Deliberate deviation: call the existing Rust class predicate directly;
/// retain aligned u32 pointer fields on hosts rather than native pointers.
///
/// # Safety
/// A non-NULL element must be aligned and readable through +7. A 'tdat'
/// element must also be readable through +0x27, and through +0x2b when
/// `index` is in range. Each of the first `index` nodes must be a nonzero
/// target-width pointer to aligned storage readable through +7. The returned
/// pointer need not be nonzero or dereferenceable; no selected-node read occurs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_tdat_node_at(element: *const u8, index: u32) -> u32 {
    if ui_element_is_tdat_class(element) == 0 {
        return 0;
    }
    if index >= element.add(0x24).cast::<u32>().read() {
        return 0;
    }
    let mut node = element.add(0x28).cast::<u32>().read();
    let mut position = 0;
    while position < index {
        node = (node as usize as *const u32).add(1).read();
        position += 1;
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_null_and_short_wrong_class() {
        let object = [0xdead_beefu32, 0x706c_7374];
        unsafe {
            for index in [0, 1, u32::MAX] {
                assert_eq!(ui_tdat_node_at(core::ptr::null(), index), 0);
                assert_eq!(ui_tdat_node_at(object.as_ptr().cast(), index), 0);
            }
        }
    }

    #[test]
    fn unsigned_bounds_do_not_read_head_or_nodes() {
        // No head word exists: bounds rejection must precede that load.
        let mut element = [0u32; 10];
        element[1] = 0x7464_6174;
        unsafe {
            for count in [0, 1, 0x8000_0000, u32::MAX] {
                element[9] = count;
                assert_eq!(ui_tdat_node_at(element.as_ptr().cast(), count), 0);
                assert_eq!(ui_tdat_node_at(element.as_ptr().cast(), u32::MAX), 0);
            }
        }
    }

    #[test]
    fn zero_index_returns_raw_head_without_dereferencing_it() {
        let mut element = [0u32; 11];
        element[1] = 0x7464_6174;
        element[9] = u32::MAX;
        for head in [0, 1, 0x8000_0000, u32::MAX] {
            element[10] = head;
            assert_eq!(unsafe { ui_tdat_node_at(element.as_ptr().cast(), 0) }, head);
        }
    }

    #[test]
    fn follows_exactly_index_raw_links_without_owner_validation() {
        let Some(base) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TDAT_NODE_AT, 4096,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let first = base.cast::<u32>();
            let second = base.add(0x100).cast::<u32>();
            let third = base.add(0x200).cast::<u32>();
            // Invalid owners ensure this never substitutes tdat_node_next.
            first.write(0);
            first.add(1).write(second as usize as u32);
            second.write(1);
            second.add(1).write(third as usize as u32);
            third.write(u32::MAX);
            third.add(1).write(0);
            let mut element = [0u32; 11];
            element[1] = 0x7464_6174;
            element[9] = 4;
            element[10] = first as usize as u32;
            let expected = [first as usize as u32, second as usize as u32,
                third as usize as u32, 0];
            for (index, node) in expected.into_iter().enumerate() {
                assert_eq!(ui_tdat_node_at(element.as_ptr().cast(), index as u32), node);
            }
            element[9] = 3;
            assert_eq!(ui_tdat_node_at(element.as_ptr().cast(), 3), 0);
            assert_eq!(first.add(1).read(), second as usize as u32);
            assert_eq!(second.add(1).read(), third as usize as u32);
            assert_eq!(third.add(1).read(), 0);
        }
    }
}
