//! Input-sequence item release — `FUN_081292cc` @ **0x081292cc**.
//!
//! Raw extent: **60 bytes**, `[0x081292cc, 0x08129308)`; the next
//! independent function begins with push {r4,lr}. Whole-image aligned A32
//! decoding verifies two inbound plain BLs (0x0839bec8, 0x0839bf20), no
//! predicated inbound BLs, two outgoing plain BLs and one outgoing BLNE.
//!
//! Drain the chain rooted at item word +4. Save each node's successor at
//! +4 before tag-2 operator_delete, then publish that successor in the item.
//! After the chain is empty, sample Timer E and store microseconds/1000 at
//! +12. Preserve all other item words. No node payload destructor is called.
//!
//! Deliberate deviations: initialize the overwritten timer stack word rather
//! than saving incoming r3; omit scratch-register effects. Production reuses
//! existing callee ports; tests replace delete and timer sampling only.

#[cfg(test)]
static mut DELETE_NODE: unsafe extern "C" fn(*mut u8) = crate::heap::veneers::operator_delete;
#[cfg(test)]
static mut READ_USEC_TIMER: unsafe extern "C" fn(*mut u32) = crate::drivers::timer::read_usec_timer_into;

#[inline(always)]
unsafe fn delete_node(node: *mut u8) {
    #[cfg(test)]
    core::ptr::read_volatile(core::ptr::addr_of!(DELETE_NODE))(node);
    #[cfg(not(test))]
    crate::heap::veneers::operator_delete(node);
}

#[inline(always)]
unsafe fn sample_timer(out: *mut u32) {
    #[cfg(test)]
    core::ptr::read_volatile(core::ptr::addr_of!(READ_USEC_TIMER))(out);
    #[cfg(not(test))]
    crate::drivers::timer::read_usec_timer_into(out);
}

/// Drain an input-sequence item's linked entries and refresh its timestamp.
///
/// # Safety
/// `item` must contain four writable aligned target words. Its +4 chain must
/// be finite, with valid tag-2 allocations readable through their +4 word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_sequence_item_release(item: *mut u32) {
    loop {
        let node = item.add(1).read() as usize as *mut u32;
        if node.is_null() {
            break;
        }
        let next = node.add(1).read();
        delete_node(node.cast());
        item.add(1).write(next);
    }
    let mut counter_usec = 0;
    sample_timer(&mut counter_usec);
    item.add(3).write(crate::drivers::timer::usec_to_millis(&counter_usec));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static mut ITEM: *mut u32 = core::ptr::null_mut();
    static mut EXPECTED_NODE: *mut u32 = core::ptr::null_mut();
    static mut DELETED: usize = 0;
    static mut COUNTER: u32 = 0;

    unsafe extern "C" fn poison_deleted_node(node: *mut u8) {
        let node = node.cast::<u32>();
        assert_eq!(node, EXPECTED_NODE);
        // The owner must still name the node during delete; its successor
        // must already have been saved before freed memory is overwritten.
        assert_eq!((*ITEM.add(1)) as usize, node as usize);
        EXPECTED_NODE = node.add(1).read() as usize as *mut u32;
        node.add(1).write(0xdead_beef);
        DELETED += 1;
    }

    unsafe extern "C" fn fixed_timer(out: *mut u32) {
        assert_eq!(ITEM.add(1).read(), 0);
        assert!(EXPECTED_NODE.is_null());
        out.write(COUNTER);
    }

    #[test]
    fn empty_single_and_multi_node_chains_preserve_state_and_refresh_time() {
        let Some(slab) = try_map_u32_slab(hints::INPUT_SEQUENCE_ITEM_RELEASE, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let item = slab.cast::<u32>();
            let nodes = slab.add(0x100).cast::<u32>();
            let old_delete = DELETE_NODE;
            let old_timer = READ_USEC_TIMER;
            DELETE_NODE = poison_deleted_node;
            READ_USEC_TIMER = fixed_timer;
            ITEM = item;
            for count in [0usize, 1, 3] {
                for counter in [0u32, 999, 1000, 1001, u32::MAX] {
                    for index in 0..count {
                        let node = nodes.add(index * 4);
                        node.write(0x1234_5678);
                        node.add(1).write(if index + 1 == count { 0 } else {
                            nodes.add((index + 1) * 4) as usize as u32
                        });
                    }
                    EXPECTED_NODE = if count == 0 { core::ptr::null_mut() } else { nodes };
                    let initial = [0x1234_5678, EXPECTED_NODE as usize as u32, 0x8765_4321, 0xfeed_face];
                    core::ptr::copy_nonoverlapping(initial.as_ptr(), item, 4);
                    DELETED = 0;
                    COUNTER = counter;
                    input_sequence_item_release(item);
                    assert_eq!(DELETED, count);
                    assert_eq!(core::slice::from_raw_parts(item, 4),
                        &[initial[0], 0, initial[2], (counter as u64 / 1000) as u32]);
                }
            }
            DELETE_NODE = old_delete;
            READ_USEC_TIMER = old_timer;
        }
    }
}
