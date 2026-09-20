//! `red_black_tree_root_replace` — retailOS `FUN_083c4150` @ `0x083c4150`.
//!
//! Raw ARM establishes the true 56-byte extent from `push {r4,r5,r6,lr}` at
//! `0x083c4150` through `pop {r4,r5,r6,pc}` at `0x083c4184`; the separately
//! linked left-rotation sibling begins at `0x083c4188`. Whole-image decoding
//! finds three incoming direct calls, all plain unconditional `bl` at
//! `0x082a812c`, `0x083c4610`, and `0x083c4ab0`; no predicated `bl` reaches
//! this entry. The routine makes `node` the tree header's root at word +1,
//! first setting node word +3 to the old root. With a nonzero destruction
//! flag, it releases the COW strings at target words +5 then +4.
//!
//! Deliberate deviations: the target's four-byte COW string words are copied
//! through native pointer locals before calling `cxx_string_release`. This
//! preserves the target layout on 64-bit host fixtures without changing any
//! target read, release, or store.

use crate::cxx::string::cxx_string_release;

#[inline]
unsafe fn release_target_string(word: *mut u32) {
    let mut string = unsafe { word.read() as usize as *mut u8 };
    unsafe { cxx_string_release(&mut string) };
    unsafe { word.write(string as usize as u32) };
}

/// Replaces a red-black tree header's root, optionally releasing two node strings.
///
/// `tree` and `node` are target-layout word arrays. Both must be valid for the
/// accessed words; if `destroy_strings` is nonzero, node words +4 and +5 must
/// hold valid COW string data pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_root_replace(
    tree: *mut u32,
    node: *mut u32,
    destroy_strings: u32,
) {
    unsafe { node.add(3).write(tree.add(1).read()) };
    if destroy_strings != 0 {
        unsafe { release_target_string(node.add(5)) };
        unsafe { release_target_string(node.add(4)) };
    }
    unsafe { tree.add(1).write(node as usize as u32) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn replaces_root_without_releasing_when_flag_is_zero() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_ROOT_REPLACE, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let tree = slab.cast::<u32>();
        let node = unsafe { tree.add(8) };
        unsafe {
            tree.add(1).write(0x1234_5678);
            node.add(4).write(0xaaaa_aaaa);
            node.add(5).write(0xbbbb_bbbb);
            red_black_tree_root_replace(tree, node, 0);
        }
        assert_eq!(unsafe { node.add(3).read() }, 0x1234_5678);
        assert_eq!(unsafe { node.add(4).read() }, 0xaaaa_aaaa);
        assert_eq!(unsafe { node.add(5).read() }, 0xbbbb_bbbb);
        assert_eq!(unsafe { tree.add(1).read() }, node as usize as u32);
    }

    #[test]
    fn releases_node_strings_in_reverse_member_order() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_ROOT_REPLACE_STRINGS, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let tree = slab.cast::<u32>();
        let node = unsafe { tree.add(8) };
        let first_rep = unsafe { slab.add(0x100).cast::<i32>() };
        let second_rep = unsafe { slab.add(0x200).cast::<i32>() };
        unsafe {
            first_rep.write(1);
            second_rep.write(1);
            node.add(4).write(first_rep.add(3) as usize as u32);
            node.add(5).write(second_rep.add(3) as usize as u32);
            red_black_tree_root_replace(tree, node, 1);
        }
        assert_eq!(unsafe { first_rep.read() }, 0);
        assert_eq!(unsafe { second_rep.read() }, 0);
        assert_eq!(unsafe { tree.add(1).read() }, node as usize as u32);
    }
}
