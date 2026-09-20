//! Wrapper around the unrecovered list-node insertion member.

/// list_insert_header_value — original: `FUN_083dc0f8` @ 0x083dc0f8
/// (40 bytes; raw extent `0x083dc0f8..0x083dc120`, bounded by the next
/// separately linked `push {r4,r5,r6,r7,lr}` entry). Exactly three inbound
/// direct calls are unconditional plain `bl`; there are no predicated calls.
///
/// The wrapper loads the target node word through `list + 0x10`, materializes
/// it in a stack local, and calls the unrecovered `FUN_083dc2d0` with that
/// local, `list`, and `value`. Its fourth ABI argument only initializes the
/// stack output slot that the callee overwrites; the wrapper discards it.
///
/// # Deliberate deviation
///
/// `FUN_083dc2d0` is not ported, so target builds retain its verified firmware
/// boundary. The host test injects the same ABI-shaped call to prove the
/// target-word load, stack-local indirection, argument order, and discarded
/// output seed without assigning an identity to the callee.
///
/// # Safety
///
/// `list` must point to at least five readable target words, and its word at
/// +0x10 must be a valid aligned pointer to a readable node word. The
/// firmware callee's additional allocation and list invariants apply.
type ListNodeInsertFn = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32, u32);

#[inline(always)]
unsafe fn list_insert_header_value_with(
    insert: ListNodeInsertFn,
    list: *mut u32,
    value: u32,
    discarded_output_seed: u32,
) {
    let mut node = *((*list.add(4)) as *const u32);
    let mut discarded_output = discarded_output_seed;
    insert(&mut discarded_output, list, &mut node, value);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_list_node_insert(
    output: *mut u32,
    list: *mut u32,
    node: *mut u32,
    value: u32,
) {
    let insert: ListNodeInsertFn = core::mem::transmute(0x083d_c2d0usize);
    insert(output, list, node, value);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_list_node_insert(
    _output: *mut u32,
    _list: *mut u32,
    _node: *mut u32,
    _value: u32,
) {
    panic!("list_insert_header_value requires FUN_083dc2d0")
}

#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_insert_header_value")]
#[inline(never)]
pub unsafe extern "C" fn list_insert_header_value(
    list: *mut u32,
    value: u32,
    _unused: u32,
    discarded_output_seed: u32,
) {
    list_insert_header_value_with(firmware_list_node_insert, list, value, discarded_output_seed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: (usize, usize, u32, u32) = (0, 0, 0, 0);

    unsafe extern "C" fn record_insert(output: *mut u32, list: *mut u32, node: *mut u32, value: u32) {
        CALL = (list as usize, node as usize, *node, value);
        *output = 0xfeed_beef;
    }

    #[test]
    fn loads_the_header_node_word_and_discards_the_output_seed() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_INSERT_HEADER_VALUE, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/list_insert_header_value"));
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let list = slab.cast::<u32>();
            let node_slot = list.add(8);
            *node_slot = 0x1357_9bdf;
            *list.add(4) = node_slot as usize as u32;
            CALL = (0, 0, 0, 0);
            list_insert_header_value_with(record_insert, list, 0x2468_ace0, 0xaaaa_5555);
            assert_eq!(CALL.0, list as usize);
            assert_ne!(CALL.1, node_slot as usize);
            assert_eq!(CALL.2, 0x1357_9bdf);
            assert_eq!(CALL.3, 0x2468_ace0);
        }
    }
}
