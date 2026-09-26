//! Cached region-list node erase primitive.

use crate::heap::veneers::operator_delete;

/// region_list_erase_recycle — original: `FUN_083dcd38` @ 0x083dcd38
/// (128 bytes, `0x083dcd38..0x083dcdb7`; Ghidra reports 132 bytes).
///
/// Removes the node named by `cursor` from a region list unless it is the
/// list's end sentinel. A real node is unlinked, its inline allocation at
/// node + 0x10 is passed to the raw branch target `operator_delete` veneer
/// (0x082804f8 -> 0x082aad24), the live count at list + 0x14 is decremented
/// with ARM wrapping arithmetic, and the node itself is pushed onto the
/// cached-node chain at list + 0x04. `output` receives the original cursor.
///
/// Raw ARM establishes the extent from `push {r1,r2,r3,r4,r5,r6,r7,lr}` at
/// 0x083dcd38 through `pop {r1,r2,r3,r4,r5,r6,r7,pc}` at 0x083dcdb4; the
/// next real function starts at 0x083dcdb8. A full-image B/BL census finds
/// two incoming plain `bl` calls (0x081a7b04 and 0x083dce04), no predicated
/// calls. The body has one plain `bl`, to 0x082804f8, and no predicated calls.
///
/// Deliberate deviations: target pointer fields are represented as `u32`
/// words, preserving the 32-bit layout on 64-bit hosts; the raw branch veneer
/// is replaced by the canonical `operator_delete` port it reaches.
///
/// # Safety
///
/// `output`, `list`, and `cursor` must be valid aligned target-word pointers.
/// When `*cursor != list[4]`, the node's next/previous links and its inline
/// allocation at byte offset 0x10 must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn region_list_erase_recycle(
    output: *mut u32,
    list: *mut u32,
    cursor: *mut u32,
) {
    let node = cursor.read();
    let end_sentinel = list.add(4).read();

    if node != end_sentinel {
        let node_words = node as usize as *mut u32;
        let next = node_words.read();
        let previous = node_words.add(1).read();
        (next as usize as *mut u32).add(1).write(previous);
        (previous as usize as *mut u32).write(next);
        list.add(5).write(list.add(5).read().wrapping_sub(1));
        operator_delete((node as usize as *mut u8).add(0x10));
        node_words.write(list.add(1).read());
        list.add(1).write(node);
    }

    output.write(node);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::mock_heap;
    use crate::testing::{hints, try_map_u32_slab};

    const LIST: usize = 0x100;
    const PREVIOUS: usize = 0x200;
    const NODE: usize = 0x300;
    const NEXT: usize = 0x400;
    const WORDS: usize = 0x200;

    #[test]
    fn unlinks_node_decrements_count_and_recycles_node() {
        let Some(slab) = try_map_u32_slab(hints::REGION_LIST_ERASE_RECYCLE, WORDS) else {
            return;
        };
        let _heap = mock_heap();
        unsafe {
            slab.write_bytes(0, WORDS * core::mem::size_of::<u32>());
            let list = slab.add(LIST).cast::<u32>();
            let previous = slab.add(PREVIOUS).cast::<u32>();
            let node = slab.add(NODE).cast::<u32>();
            let next = slab.add(NEXT).cast::<u32>();
            let mut output = 0;
            let mut cursor = node as usize as u32;

            list.add(1).write(0x1234_5678);
            list.add(4).write(0xfeed_cafe);
            list.add(5).write(7);
            previous.write(node as usize as u32);
            node.write(next as usize as u32);
            node.add(1).write(previous as usize as u32);
            next.add(1).write(node as usize as u32);

            region_list_erase_recycle(&mut output, list, &mut cursor);

            assert_eq!(output, node as usize as u32);
            assert_eq!(previous.read(), next as usize as u32);
            assert_eq!(next.add(1).read(), previous as usize as u32);
            assert_eq!(list.add(5).read(), 6);
            assert_eq!(node.read(), 0x1234_5678);
            assert_eq!(list.add(1).read(), node as usize as u32);
        }
    }

    #[test]
    fn end_sentinel_is_returned_without_mutation() {
        let Some(slab) = try_map_u32_slab(hints::REGION_LIST_ERASE_RECYCLE, WORDS) else {
            return;
        };
        let _heap = mock_heap();
        unsafe {
            slab.write_bytes(0, WORDS * core::mem::size_of::<u32>());
            let list = slab.add(LIST).cast::<u32>();
            let mut output = 0;
            let mut cursor = 0xfeed_cafe;
            list.add(1).write(0x1234_5678);
            list.add(4).write(cursor);
            list.add(5).write(7);

            region_list_erase_recycle(&mut output, list, &mut cursor);

            assert_eq!(output, cursor);
            assert_eq!(list.add(1).read(), 0x1234_5678);
            assert_eq!(list.add(5).read(), 7);
        }
    }
}
