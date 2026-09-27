//! Event-list red-black-tree subtree clone — original: `FUN_083c1e9c` at
//! load address `0x083c1e9c`.
//!
//! Raw `osos.dec` establishes the exact 116-byte extent: 29 ARM words from
//! `push {r4-r8,lr}` at `0x083c1e9c` through `pop {r4-r8,pc}` at
//! `0x083c1f0c`; the next function starts at `0x083c1f10`. Decoding its words
//! finds two unconditional `bl` instructions (to 0x083c1580 and recursively
//! to itself), with no predicated `bl`.
//!
//! The routine recursively clones a source subtree. For each source node it
//! obtains a node with its 24-byte payload cloned by 0x083c1580, links that
//! node below the supplied destination header, copies the color byte, then
//! clones its left child. It iterates down right links and terminates the
//! final right link with null.
//!
//! Deliberate deviations: the type-specialized allocation and payload-copy
//! helper at 0x083c1580 remains unported. ARM calls that verified target;
//! host tests inject it into the algorithm.

#[inline(always)]
unsafe fn word(pointer: *const u8, offset: usize) -> u32 {
    unsafe { pointer.add(offset).cast::<u32>().read() }
}

#[inline(always)]
unsafe fn set_word(pointer: *mut u8, offset: usize, value: u32) {
    unsafe { pointer.add(offset).cast::<u32>().write(value) };
}

unsafe fn clone_subtree_with(
    tree: *mut u8,
    mut source_root: u32,
    mut destination_header: u32,
    clone_node: unsafe fn(*mut u8, *const u8) -> u32,
) -> u32 {
    let mut first_clone = 0;
    while source_root != 0 {
        let source = source_root as usize as *const u8;
        let clone = unsafe { clone_node(tree, source.add(0x10)) };
        let allocated_node = clone as usize as *mut u8;

        if first_clone == 0 {
            first_clone = clone;
        }
        unsafe {
            set_word(destination_header as usize as *mut u8, 0x08, clone);
            set_word(allocated_node, 0x04, destination_header);
            allocated_node.write(source.read());
            set_word(allocated_node, 0x0c, clone_subtree_with(tree, word(source, 0x08), clone, clone_node));
        }

        destination_header = clone;
        source_root = unsafe { word(source, 0x0c) };
    }
    unsafe { set_word(destination_header as usize as *mut u8, 0x08, 0) };
    first_clone
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn clone_node(tree: *mut u8, source_payload: *const u8) -> u32 {
    let retail_clone_node: unsafe extern "C" fn(*mut u8, *const u8) -> u32 =
        unsafe { core::mem::transmute(0x083c_1580usize) };
    unsafe { retail_clone_node(tree, source_payload) }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn clone_node(_tree: *mut u8, _source_payload: *const u8) -> u32 {
    panic!("event_list_tree_copy_subtree requires 0x083c1580")
}

/// Clones `source_root` and all descendants below `destination_header`.
///
/// Original: `FUN_083c1e9c` at load address `0x083c1e9c` (116 bytes; two
/// unconditional internal `bl` instructions).
///
/// # Safety
///
/// `source_root` and `destination_header` must be target-width tree nodes.
/// Their links and the allocation helper's result must be valid writable
/// 40-byte nodes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.event_list_tree_copy_subtree")]
#[inline(never)]
pub unsafe extern "C" fn event_list_tree_copy_subtree(
    tree: *mut u8,
    mut source_root: u32,
    mut destination_header: u32,
) -> u32 {
    let mut first_clone = 0;
    while source_root != 0 {
        let source = source_root as usize as *const u8;
        let clone = unsafe { clone_node(tree, source.add(0x10)) };
        let clone_node = clone as usize as *mut u8;
        if first_clone == 0 {
            first_clone = clone;
        }
        unsafe {
            set_word(destination_header as usize as *mut u8, 0x08, clone);
            set_word(clone_node, 0x04, destination_header);
            clone_node.write(source.read());
            set_word(clone_node, 0x0c, event_list_tree_copy_subtree(tree, word(source, 0x08), clone));
        }
        destination_header = clone;
        source_root = unsafe { word(source, 0x0c) };
    }
    unsafe { set_word(destination_header as usize as *mut u8, 0x08, 0) };
    first_clone
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    const BYTES: usize = 0x1000;
    const HEADER: usize = 0x00;
    const ROOT: usize = 0x40;
    const LEFT: usize = 0x80;
    const LEFT_RIGHT: usize = 0xc0;
    const RIGHT: usize = 0x100;
    const CLONE_ROOT: usize = 0x200;
    const CLONE_LEFT: usize = 0x240;
    const CLONE_LEFT_RIGHT: usize = 0x280;
    const CLONE_RIGHT: usize = 0x2c0;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CLONES: [u32; 4] = [0; 4];
    static mut CLONE_COUNT: usize = 0;
    static mut OBSERVED_PAYLOADS: [u32; 4] = [0; 4];

    unsafe fn clone_node_for_test(_tree: *mut u8, source_payload: *const u8) -> u32 {
        let index = unsafe { CLONE_COUNT };
        unsafe {
            OBSERVED_PAYLOADS[index] = source_payload as usize as u32;
            CLONE_COUNT += 1;
            CLONES[index]
        }
    }

    fn node(base: *mut u8, offset: usize) -> *mut u8 {
        unsafe { base.add(offset) }
    }

    #[test]
    fn clones_empty_subtree_and_terminates_destination_right_link() {
        let _lock = LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::EVENT_LIST_TREE_COPY_SUBTREE, BYTES) else {
            note_missing_u32_fixture("app/event_list_tree_copy_subtree");
            return;
        };
        unsafe {
            ptr::write_bytes(base, 0xa5, BYTES);
            set_word(node(base, HEADER), 0x08, 0xfeed_beef);
            let result = clone_subtree_with(base, 0, node(base, HEADER) as usize as u32, clone_node_for_test);
            assert_eq!(result, 0);
            assert_eq!(word(node(base, HEADER), 0x08), 0);
        }
    }

    #[test]
    fn clones_colors_left_subtrees_and_right_chain() {
        let _lock = LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::EVENT_LIST_TREE_COPY_SUBTREE, BYTES) else {
            note_missing_u32_fixture("app/event_list_tree_copy_subtree");
            return;
        };
        unsafe {
            ptr::write_bytes(base, 0, BYTES);
            for (offset, color) in [(ROOT, 1u8), (LEFT, 2), (LEFT_RIGHT, 3), (RIGHT, 4)] {
                node(base, offset).write(color);
            }
            set_word(node(base, ROOT), 0x08, node(base, LEFT) as usize as u32);
            set_word(node(base, ROOT), 0x0c, node(base, RIGHT) as usize as u32);
            set_word(node(base, LEFT), 0x0c, node(base, LEFT_RIGHT) as usize as u32);

            CLONES = [
                node(base, CLONE_ROOT) as usize as u32,
                node(base, CLONE_LEFT) as usize as u32,
                node(base, CLONE_LEFT_RIGHT) as usize as u32,
                node(base, CLONE_RIGHT) as usize as u32,
            ];
            CLONE_COUNT = 0;
            OBSERVED_PAYLOADS = [0; 4];
            let header = node(base, HEADER) as usize as u32;
            let result = clone_subtree_with(base, node(base, ROOT) as usize as u32, header, clone_node_for_test);

            assert_eq!(result, CLONES[0]);
            assert_eq!(CLONE_COUNT, 4);
            assert_eq!(OBSERVED_PAYLOADS, [
                node(base, ROOT + 0x10) as usize as u32,
                node(base, LEFT + 0x10) as usize as u32,
                node(base, LEFT_RIGHT + 0x10) as usize as u32,
                node(base, RIGHT + 0x10) as usize as u32,
            ]);
            assert_eq!(word(node(base, HEADER), 0x08), CLONES[0]);
            assert_eq!(word(node(base, CLONE_ROOT), 0x04), header);
            assert_eq!(word(node(base, CLONE_ROOT), 0x0c), CLONES[1]);
            assert_eq!(word(node(base, CLONE_ROOT), 0x08), CLONES[3]);
            assert_eq!(word(node(base, CLONE_LEFT), 0x04), CLONES[0]);
            assert_eq!(word(node(base, CLONE_LEFT), 0x08), CLONES[2]);
            assert_eq!(word(node(base, CLONE_LEFT_RIGHT), 0x04), CLONES[1]);
            assert_eq!(word(node(base, CLONE_LEFT_RIGHT), 0x08), 0);
            assert_eq!(word(node(base, CLONE_RIGHT), 0x04), CLONES[0]);
            assert_eq!(word(node(base, CLONE_RIGHT), 0x08), 0);
            assert_eq!(*node(base, CLONE_ROOT), 1);
            assert_eq!(*node(base, CLONE_LEFT), 2);
            assert_eq!(*node(base, CLONE_LEFT_RIGHT), 3);
            assert_eq!(*node(base, CLONE_RIGHT), 4);
        }
    }
}
