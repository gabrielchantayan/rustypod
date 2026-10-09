//! Linked-list associated-object flag predicate.

/// retailOS `FUN_080f74d4` @ 0x080f74d4, 52 bytes (13 ARM words), ending
/// at the next function @ 0x080f7508. Verified from raw osos.dec: two
/// incoming plain BLs (0x0814296c, 0x0814298c), zero predicated BLs,
/// and zero outgoing calls.
///
/// Load the head word; for each node, read its associated-object pointer
/// at +0x128 and that object's byte at +0x2c. Return 1 on a zero byte;
/// otherwise follow the next pointer at +0x134. Return 0 at list end.
/// Deliberate deviations: none. The flag's domain meaning is not known.
/// Target pointer fields remain u32 words, including in host fixtures.
///
/// # Safety
/// `head` must be readable and aligned. Every visited nonzero node must
/// contain readable aligned pointer words at +0x128 and +0x134; its
/// associated object must have a readable byte at +0x2c. No NULL guard
/// exists for the head argument or associated-object pointer. Traversal
/// must terminate or encounter a zero flag; cyclic all-nonzero lists loop.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn linked_items_have_clear_associated_flag(head: *const u32) -> u32 {
    let mut node = head.read();
    while node != 0 {
        let words = node as usize as *const u32;
        let associated = words.add(0x128 / 4).read() as usize as *const u8;
        if associated.add(0x2c).read() == 0 {
            return 1;
        }
        node = words.add(0x134 / 4).read();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn empty_list() {
        let head = 0;
        assert_eq!(unsafe { linked_items_have_clear_associated_flag(&head) }, 0);
    }

    #[test]
    fn flag_values_position_and_short_circuit() {
        unsafe {
            let slab = try_map_u32_slab(hints::LINKED_ITEMS_HAVE_CLEAR_ASSOCIATED_FLAG, 0x1000)
                .expect("low-address fixture required");
            core::ptr::write_bytes(slab, 0, 0x1000);
            let nodes = [slab, slab.add(0x200), slab.add(0x400)];
            let flags = [slab.add(0x62c), slab.add(0x72c), slab.add(0x82c)];
            for i in 0..3 {
                nodes[i].cast::<u32>().add(0x128 / 4)
                    .write(flags[i].sub(0x2c) as usize as u32);
                nodes[i].cast::<u32>().add(0x134 / 4)
                    .write(if i == 2 { 0 } else { nodes[i + 1] as usize as u32 });
            }
            let head = nodes[0] as usize as u32;
            // All nonzero bytes, including high-bit values, mean continue.
            for value in [1, 0x80, 0xff] {
                for flag in flags { flag.write(value); }
                assert_eq!(linked_items_have_clear_associated_flag(&head), 0);
                for position in 0..3 {
                    flags[position].write(0);
                    assert_eq!(linked_items_have_clear_associated_flag(&head), 1);
                    flags[position].write(value);
                }
            }
            // A successful predicate must not dereference the next node.
            flags[0].write(0);
            nodes[0].cast::<u32>().add(0x134 / 4).write(1);
            assert_eq!(linked_items_have_clear_associated_flag(&head), 1);
            assert_eq!(head, nodes[0] as usize as u32);
            assert_eq!(flags[0].read(), 0);
            assert_eq!(nodes[0].cast::<u32>().add(0x134 / 4).read(), 1);
        }
    }
}
