//! Red-black-tree cursor predecessor returning the original node.
//!
//! `red_black_tree_decrement_cursor_083b5760` — retailOS `FUN_083b5760` at
//! load address `0x083b5760` (88 bytes, `0x083b5760..0x083b57b4`; the next
//! independently entered function begins at `0x083b57b8`). Complete aligned
//! A32 B/BL-immediate decoding finds two inbound unconditional plain `bl`
//! calls at `0x08257e50` and `0x08257ed0`, zero predicated `bl` calls, and no
//! outbound calls.
//!
//! The function moves `*cursor` to the in-order predecessor: it descends the
//! left subtree's right spine, or climbs parent links out of left-child edges
//! until reaching a right-child edge, retaining the header sentinel. Unlike
//! the closely related cursor-returning body at `0x083b59b4`, it returns the
//! original target-width node word. Deliberate deviations: target links remain
//! `u32` words so the host fixture preserves the retail four-byte layout.

const PARENT: usize = 1;
const LEFT: usize = 2;
const RIGHT: usize = 3;

/// Moves `cursor` to its red-black-tree in-order predecessor and returns its
/// original target-width node address.
///
/// # Safety
///
/// `cursor` must be writable and initially contain a valid non-NULL node
/// address. Every link traversed by the tree and header-sentinel invariants
/// must name a readable aligned four-word node.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_decrement_cursor_083b5760")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_decrement_cursor_083b5760(cursor: *mut u32) -> u32 {
    let original = unsafe { cursor.read() };
    let mut current = original as usize as *mut u32;
    let mut previous = unsafe { current.add(LEFT).read() };

    if previous != 0 {
        loop {
            unsafe { cursor.write(previous) };
            current = previous as usize as *mut u32;
            previous = unsafe { current.add(RIGHT).read() };
            if previous == 0 {
                return original;
            }
        }
    }

    previous = unsafe { current.add(PARENT).read() };
    while unsafe { (previous as usize as *mut u32).add(LEFT).read() } == cursor.read() {
        unsafe { cursor.write(previous) };
        previous = unsafe { (previous as usize as *mut u32).add(PARENT).read() };
    }
    if unsafe { (cursor.read() as usize as *mut u32).add(LEFT).read() } != previous {
        unsafe { cursor.write(previous) };
    }
    original
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{red_black_tree_decrement_cursor_083b5760, LEFT, PARENT, RIGHT};
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::LazyLock;

    const SLAB_SIZE: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::RED_BLACK_TREE_DECREMENT_CURSOR_083B5760, SLAB_SIZE)
            .map(|pointer| pointer as usize)
    });

    #[test]
    fn returns_original_node_across_predecessor_paths() {
        let Some(base) = *SLAB else {
            crate::testing::note_missing_u32_fixture("red_black_tree_decrement_cursor_083b5760");
            return;
        };
        unsafe {
            let base = base as *mut u8;
            core::ptr::write_bytes(base, 0, SLAB_SIZE);
            let header = base.cast::<u32>();
            let root = base.add(0x20).cast::<u32>();
            let left = base.add(0x40).cast::<u32>();
            let rightmost = base.add(0x60).cast::<u32>();
            let right_child = base.add(0x80).cast::<u32>();

            // A left subtree selects its rightmost descendant.
            root.add(LEFT).write(left as usize as u32);
            left.add(PARENT).write(root as usize as u32);
            left.add(RIGHT).write(rightmost as usize as u32);
            rightmost.add(PARENT).write(left as usize as u32);
            let mut cursor = root as usize as u32;
            assert_eq!(red_black_tree_decrement_cursor_083b5760(&mut cursor), root as usize as u32);
            assert_eq!(cursor, rightmost as usize as u32);

            // A leftmost node climbs through left edges and retains the header.
            core::ptr::write_bytes(base, 0, SLAB_SIZE);
            left.add(PARENT).write(root as usize as u32);
            root.add(PARENT).write(header as usize as u32);
            root.add(LEFT).write(left as usize as u32);
            header.add(LEFT).write(left as usize as u32);
            let mut cursor = left as usize as u32;
            assert_eq!(red_black_tree_decrement_cursor_083b5760(&mut cursor), left as usize as u32);
            assert_eq!(cursor, header as usize as u32);

            // The first ancestor reached from a right-child edge is selected.
            core::ptr::write_bytes(base, 0, SLAB_SIZE);
            right_child.add(PARENT).write(root as usize as u32);
            root.add(RIGHT).write(right_child as usize as u32);
            let mut cursor = right_child as usize as u32;
            assert_eq!(red_black_tree_decrement_cursor_083b5760(&mut cursor), right_child as usize as u32);
            assert_eq!(cursor, root as usize as u32);
        }
    }
}
