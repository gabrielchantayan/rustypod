//! Propagates an 8-bit status through an intrusive node ring.

/// `linked_node_status_set` — original: `FUN_081f507c` @ `0x081f507c`
/// (56 bytes).
///
/// Raw ARM words establish the exact body at `0x081f507c..0x081f50b4`; the
/// next real function starts at `0x081f50b4`. Whole-image decoding finds three
/// inbound plain `bl` calls (`0x0803c2dc`, `0x0805bba4`, and `0x081b11dc`), no
/// predicated `bl` calls, and no outbound calls. It writes the low status byte
/// at `+0x3d` to every node in a null-terminated or root-terminated intrusive
/// chain. Status `3` additionally clears the root owner's words at `+0xac` and
/// `+0x90` when the root's `+0x34` owner is nonzero.
///
/// Deliberate deviation: node and owner pointers remain target-width `u32`
/// words so offsets retain their retailOS layout on 64-bit host tests; volatile
/// owner writes preserve the retail store order.
///
/// # Safety
/// `root` and every nonzero `+0x40` link must name a readable node with a
/// writable byte at `+0x3d`. For status `3`, a nonzero root `+0x34` owner must
/// provide writable words at `+0x90` and `+0xac`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_node_status_set(root: u32, status: u32) {
    let mut node = root;
    loop {
        let node_bytes = node as usize as *mut u8;
        *node_bytes.add(0x3d) = status as u8;
        node = *(node_bytes.add(0x40).cast::<u32>());
        if node == 0 || node == root {
            break;
        }
    }

    if status == 3 {
        let root_bytes = root as usize as *mut u8;
        let owner = *(root_bytes.add(0x34).cast::<u32>());
        if owner != 0 {
            let owner_words = owner as usize as *mut u32;
            core::ptr::write_volatile(owner_words.add(0x2b), 0);
            core::ptr::write_volatile(owner_words.add(0x24), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::linked_node_status_set;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const RECORD_BYTES: usize = 0x100;
    const FIXTURE_BYTES: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LINKED_NODE_STATUS_SET, FIXTURE_BYTES).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn record(base: *mut u8, index: usize) -> *mut u8 {
        base.add(index * RECORD_BYTES)
    }

    unsafe fn target_pointer(record: *mut u8) -> u32 {
        record as usize as u32
    }

    #[test]
    fn writes_every_node_in_a_root_terminated_ring_and_clears_status_three_owner_fields() {
        let _guard = LOCK.lock();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/linked_node_status_set"));
            return;
        };
        unsafe {
            let root = record(base as *mut u8, 0);
            let middle = record(base as *mut u8, 1);
            let tail = record(base as *mut u8, 2);
            let owner = record(base as *mut u8, 3);
            ptr::write_bytes(root, 0, RECORD_BYTES * 4);
            *root.add(0x40).cast::<u32>() = target_pointer(middle);
            *middle.add(0x40).cast::<u32>() = target_pointer(tail);
            *tail.add(0x40).cast::<u32>() = target_pointer(root);
            *root.add(0x34).cast::<u32>() = target_pointer(owner);
            *owner.add(0x90).cast::<u32>() = 0xfeed_face;
            *owner.add(0xac).cast::<u32>() = 0xcafe_babe;

            linked_node_status_set(target_pointer(root), 3);

            assert_eq!(*root.add(0x3d), 3);
            assert_eq!(*middle.add(0x3d), 3);
            assert_eq!(*tail.add(0x3d), 3);
            assert_eq!(*owner.add(0x90).cast::<u32>(), 0);
            assert_eq!(*owner.add(0xac).cast::<u32>(), 0);
        }
    }

    #[test]
    fn stops_at_a_null_link_and_preserves_owner_fields_for_other_statuses() {
        let _guard = LOCK.lock();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/linked_node_status_set"));
            return;
        };
        unsafe {
            let root = record(base as *mut u8, 4);
            let tail = record(base as *mut u8, 5);
            let owner = record(base as *mut u8, 6);
            ptr::write_bytes(root, 0, RECORD_BYTES * 3);
            *root.add(0x40).cast::<u32>() = target_pointer(tail);
            *root.add(0x34).cast::<u32>() = target_pointer(owner);
            *owner.add(0x90).cast::<u32>() = 0x1111_2222;
            *owner.add(0xac).cast::<u32>() = 0x3333_4444;

            linked_node_status_set(target_pointer(root), 0x104);

            assert_eq!(*root.add(0x3d), 4);
            assert_eq!(*tail.add(0x3d), 4);
            assert_eq!(*owner.add(0x90).cast::<u32>(), 0x1111_2222);
            assert_eq!(*owner.add(0xac).cast::<u32>(), 0x3333_4444);
        }
    }
}
