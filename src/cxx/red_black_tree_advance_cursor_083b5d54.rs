//! `red_black_tree_advance_cursor_083b5d54` — retailOS `FUN_083b5d54` @
//! `0x083b5d54`.
//!
//! Raw `osos.dec` establishes the exact 84-byte A32 extent
//! `0x083b5d54..0x083b5da4`: the next separately linked function begins at
//! `0x083b5da8`. Its 21 words end in `bx lr`; complete aligned A32 branch
//! decoding finds two inbound unconditional plain `bl` calls at `0x083c5b40`
//! and `0x083c6018`, zero predicated `bl` calls, and no outbound calls. It
//! advances an in-order red-black-tree cursor to its successor: descend the
//! right subtree's left spine, or climb parents while leaving right-child edges.
//!
//! # Deliberate deviations
//!
//! Target pointers remain `u32` words rather than host pointers, preserving the
//! retail four-byte node-link layout on 64-bit host test builds.

const PARENT: usize = 1;
const LEFT: usize = 2;
const RIGHT: usize = 3;

/// Advances `cursor` to its red-black-tree in-order successor.
///
/// Returns `cursor`, exactly as retailOS leaves r0 unchanged.
///
/// # Safety
///
/// `cursor` must be writable and point to a valid non-NULL target-width node
/// address. Every traversed node must be readable and aligned. RetailOS has no
/// NULL checks beyond testing the initial right-child link.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_advance_cursor_083b5d54")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_advance_cursor_083b5d54(cursor: *mut u32) -> *mut u32 {
    let mut node = unsafe { cursor.read() as usize as *mut u32 };
    let mut next = unsafe { node.add(RIGHT).read_volatile() };

    if next != 0 {
        loop {
            unsafe { cursor.write(next) };
            node = next as usize as *mut u32;
            next = unsafe { node.add(LEFT).read_volatile() };
            if next == 0 {
                return cursor;
            }
        }
    }

    next = unsafe { node.add(PARENT).read_volatile() };
    while unsafe { (next as usize as *mut u32).add(RIGHT).read_volatile() } == unsafe { cursor.read() } {
        unsafe { cursor.write(next) };
        next = unsafe { (next as usize as *mut u32).add(PARENT).read_volatile() };
    }
    if unsafe { (cursor.read() as usize as *mut u32).add(RIGHT).read_volatile() } != next {
        unsafe { cursor.write(next) };
    }
    cursor
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::red_black_tree_advance_cursor_083b5d54;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const WORDS: usize = 0x1000;
    const HEADER: usize = 0;
    const ROOT: usize = 16;
    const LEFT: usize = 32;
    const RIGHT: usize = 48;
    const RIGHT_LEFT: usize = 64;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::RED_BLACK_TREE_ADVANCE_CURSOR_083B5D54, WORDS * core::mem::size_of::<u32>())
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    fn node(base: *mut u32, offset: usize) -> *mut u32 {
        unsafe { base.add(offset) }
    }

    #[test]
    fn descends_to_leftmost_node_of_right_subtree() {
        let _lock = LOCK.lock();
        let Some(base) = (*SLAB).map(|address| address as *mut u32) else { return };
        unsafe {
            let header = node(base, HEADER);
            let root = node(base, ROOT);
            let right = node(base, RIGHT);
            let right_left = node(base, RIGHT_LEFT);
            root.add(1).write(header as usize as u32);
            root.add(3).write(right as usize as u32);
            right.add(1).write(root as usize as u32);
            right.add(2).write(right_left as usize as u32);
            right_left.add(1).write(right as usize as u32);
            right_left.add(2).write(0);
            right_left.add(3).write(0);
            let mut cursor = root as usize as u32;

            assert_eq!(red_black_tree_advance_cursor_083b5d54(&mut cursor), core::ptr::addr_of_mut!(cursor));
            assert_eq!(cursor, right_left as usize as u32);
        }
    }

    #[test]
    fn climbs_right_edges_then_preserves_header_sentinel() {
        let _lock = LOCK.lock();
        let Some(base) = (*SLAB).map(|address| address as *mut u32) else { return };
        unsafe {
            let header = node(base, HEADER);
            let root = node(base, ROOT);
            let left = node(base, LEFT);
            header.add(3).write(root as usize as u32);
            header.add(1).write(root as usize as u32);
            root.add(1).write(header as usize as u32);
            root.add(2).write(left as usize as u32);
            root.add(3).write(0);
            left.add(1).write(root as usize as u32);
            left.add(2).write(0);
            left.add(3).write(0);
            let mut cursor = left as usize as u32;

            red_black_tree_advance_cursor_083b5d54(&mut cursor);
            assert_eq!(cursor, root as usize as u32);
            red_black_tree_advance_cursor_083b5d54(&mut cursor);
            assert_eq!(cursor, header as usize as u32);
        }
    }
}
