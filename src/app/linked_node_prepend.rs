//! Intrusive node prepend — `FUN_081f198c` @ `0x081f198c`, 32 bytes.
//!
//! Eight raw A32 words end at `bx lr`; the next independent function starts
//! at 0x081f19ac. Whole-image decoding verifies two plain inbound BL sites
//! (0x081d633c, 0x0820c138), zero predicated inbound BLs, and zero body BLs.
//! Clear node+4, load owner+8, link the old head when nonzero, publish the
//! node as head, and set owner+12 only when the loaded head was zero.
//! Deliberate deviations: word-indexed u32 fields preserve target offsets on
//! hosts; volatile accesses preserve the original store/load order even for
//! overlapping objects. No allocation, dispatch, or callee seams.

use core::ptr::{read_volatile, write_volatile};

/// # Safety
/// `owner` must expose four aligned writable u32 words and `node` at least
/// two. The node address must fit in u32. Existing links are opaque target
/// addresses; this routine does not dereference them. Overlap is permitted.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_node_prepend(owner: *mut u32, node: *mut u32) {
    write_volatile(node.add(1), 0);
    let old_head = read_volatile(owner.add(2));
    if old_head != 0 {
        write_volatile(node.add(1), old_head);
    }
    let address = node as usize as u32;
    write_volatile(owner.add(2), address);
    if old_head == 0 {
        write_volatile(owner.add(3), address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn empty_then_multiple_nodes_preserve_tail_and_payloads() {
        let Some(slab) = try_map_u32_slab(hints::LINKED_NODE_PREPEND, 0x1000) else {
            note_missing_u32_fixture("app/linked_node_prepend");
            return;
        };
        unsafe {
            let owner = slab.cast::<u32>();
            let first = owner.add(8);
            let second = owner.add(12);
            owner.copy_from_nonoverlapping([0x11, 0x22, 0, 0xdead_beef].as_ptr(), 4);
            first.copy_from_nonoverlapping([0x33, 0xffff_ffff, 0x44].as_ptr(), 3);
            second.copy_from_nonoverlapping([0x55, 0xdead_beef, 0x66].as_ptr(), 3);
            linked_node_prepend(owner, first);
            assert_eq!(core::slice::from_raw_parts(owner, 4), &[0x11, 0x22, first as u32, first as u32]);
            assert_eq!(core::slice::from_raw_parts(first, 3), &[0x33, 0, 0x44]);
            linked_node_prepend(owner, second);
            assert_eq!(core::slice::from_raw_parts(owner, 4), &[0x11, 0x22, second as u32, first as u32]);
            assert_eq!(core::slice::from_raw_parts(second, 3), &[0x55, first as u32, 0x66]);
            assert_eq!(core::slice::from_raw_parts(first, 3), &[0x33, 0, 0x44]);

            // Clearing an overlapping node link precedes loading the head.
            owner.copy_from_nonoverlapping([0x77, 0x88, first as u32, 0x99].as_ptr(), 4);
            linked_node_prepend(owner, owner.add(1));
            assert_eq!(core::slice::from_raw_parts(owner, 4), &[0x77, 0x88, owner.add(1) as u32, owner.add(1) as u32]);
        }
    }
}
