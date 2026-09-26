//! `word_pair_list_insert_before` — retailOS `FUN_083dd048` @ `0x083dd048`.
//!
//! Raw `osos.dec` establishes the exact 116-byte extent: 29 A32 words from
//! `push {r3-r7,lr}` through `pop {r3-r7,pc}` at `0x083dd0b8`; `0x083dd0bc`
//! starts `word_pair_list_sentinel_initialize`. The body has one unconditional
//! plain `bl`, to the 16-byte pair-node-pool acquire helper @ `0x083dce90`,
//! and no predicated `bl` calls. Whole-image A32 decoding finds two inbound
//! plain `bl` sites and no predicated inbound `bl` sites.
//!
//! It acquires a node, copies a value pair, inserts the node immediately before
//! `position` in the intrusive ring, increments the list state word, and stores
//! the new node through `output`. Deliberate deviation: host builds use the
//! equivalent shared pool-acquire implementation; target builds retain the
//! verified retail pool-acquire seam.

#[cfg(not(target_os = "none"))]
use super::word_pair_list_copy_construct::acquire_node;
use super::word_pair_list_copy_construct::{WordPairList, WordPairListNode};
use core::ptr::addr_of_mut;

#[cfg(target_os = "none")]
unsafe fn acquire_node(list: *mut WordPairList, single: u32) -> *mut WordPairListNode {
    let acquire: unsafe extern "C" fn(*mut WordPairList, u32) -> *mut WordPairListNode =
        core::mem::transmute(0x083d_ce90usize);
    acquire(list, single)
}

#[inline(always)]
fn pointer_word(pointer: *mut WordPairListNode) -> u32 { pointer as usize as u32 }

/// Inserts `value` immediately before `position` and writes the new node to `output`.
///
/// # Safety
///
/// `output`, `list`, `position`, and `value` must be valid target-layout objects.
/// `position` must be linked into `list`'s intrusive ring, and the list's node pool
/// must be valid.
///
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.word_pair_list_insert_before")]
#[inline(never)]
pub unsafe extern "C" fn word_pair_list_insert_before(
    output: *mut u32,
    list: *mut WordPairList,
    position: *mut WordPairListNode,
    value: *const u32,
) {
    let node = acquire_node(list, 0);
    if pointer_word(node).wrapping_add(8) != 0 {
        addr_of_mut!((*node).first).write(value.read());
        addr_of_mut!((*node).second).write(value.add(1).read());
    }
    let position_word = pointer_word(position);
    addr_of_mut!((*node).next).write(position_word);
    let previous = (*position).previous;
    addr_of_mut!((*node).previous).write(previous);
    let previous_node = previous as usize as *mut WordPairListNode;
    addr_of_mut!((*previous_node).next).write(pointer_word(node));
    addr_of_mut!((*position).previous).write(pointer_word(node));
    addr_of_mut!((*list).state).write((*list).state.wrapping_add(1));
    output.write(pointer_word(node));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn inserts_before_position_and_wraps_state() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::WORD_PAIR_LIST_INSERT_BEFORE, 0x1000) else {
            note_missing_u32_fixture("cxx/word_pair_list_insert_before");
            return;
        };
        unsafe {
            let mut output = 0;
            let list = slab.cast::<WordPairList>();
            let predecessor = slab.add(0x100).cast::<WordPairListNode>();
            let position = slab.add(0x120).cast::<WordPairListNode>();
            let free_node = slab.add(0x140).cast::<WordPairListNode>();
            let value = slab.add(0x160).cast::<u32>();
            slab.write_bytes(0xa5, 0x1000);

            (*list).free = pointer_word(free_node);
            (*list).state = u32::MAX;
            (*predecessor).next = pointer_word(position);
            (*position).previous = pointer_word(predecessor);
            value.write(0x1122_3344);
            value.add(1).write(0x5566_7788);

            word_pair_list_insert_before(&mut output, list, position, value);

            assert_eq!(output, pointer_word(free_node));
            assert_eq!(((*free_node).first, (*free_node).second), (0x1122_3344, 0x5566_7788));
            assert_eq!((*free_node).next, pointer_word(position));
            assert_eq!((*free_node).previous, pointer_word(predecessor));
            assert_eq!((*predecessor).next, pointer_word(free_node));
            assert_eq!((*position).previous, pointer_word(free_node));
            assert_eq!((*list).free, 0xa5a5_a5a5);
            assert_eq!((*list).state, 0);
        }
    }
}
