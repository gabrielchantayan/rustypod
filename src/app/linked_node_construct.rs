//! Default construction of the intrusive node used by linked_node_status_set.

/// `linked_node_construct` — original `FUN_081f50b4` @ `0x081f50b4`.
/// True extent: 128 bytes through the next function at `0x081f5134`;
/// 120 instruction bytes and two literal words. Verified whole-image call
/// count: two inbound plain BLs (0x0803c290, 0x0805bb54), zero predicated
/// inbound BLs, and zero outbound BLs.
///
/// Installs vtable 0x089901fc, a 44100 rate, unit/16 defaults, three 0x7fff
/// limits and a 1000 interval; clears the remaining specified words and
/// flag bytes, including the owner and next-node links. Returns this unchanged.
/// Concrete class identity and the meanings of other fields remain unresolved.
///
/// Deliberate deviations: target-width word indices preserve the layout on
/// hosts; volatile stores preserve original store widths/order and padding.
/// The explicit pointer return corrects Ghidra's void signature, as confirmed
/// by raw r0 pass-through and callers forwarding it to cxa_atexit. No validation.
///
/// # Safety
/// `node` must be word-aligned and writable for at least 77 bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_node_construct(node: *mut u32) -> *mut u32 {
    use core::ptr::write_volatile;
    let flags = node.cast::<u8>();
    write_volatile(node, 0x089901fc);
    write_volatile(node.add(1), 0);
    write_volatile(node.add(2), 0);
    write_volatile(flags.add(0x0c), 0);
    write_volatile(node.add(4), 44100);
    write_volatile(node.add(5), 1);
    write_volatile(node.add(6), 16);
    write_volatile(node.add(9), 0);
    write_volatile(node.add(7), 0x7fff);
    write_volatile(node.add(8), 1000);
    write_volatile(node.add(10), 0);
    write_volatile(node.add(11), 0);
    write_volatile(node.add(12), 0x7fff);
    write_volatile(node.add(13), 0);
    write_volatile(node.add(14), 1);
    write_volatile(flags.add(0x3c), 0);
    write_volatile(flags.add(0x3d), 0);
    write_volatile(flags.add(0x3e), 0);
    write_volatile(node.add(16), 0);
    write_volatile(node.add(17), 0x7fff);
    write_volatile(node.add(18), 0);
    write_volatile(flags.add(0x4c), 0);
    node
}

#[cfg(test)]
mod tests {
    use super::linked_node_construct;

    #[test]
    fn initializes_dirty_storage_preserving_padding_and_neighbors() {
        for fill in [0u8, 0xa5, 0xff] {
            let mut storage = [u32::from_ne_bytes([fill; 4]); 22];
            let node = unsafe { storage.as_mut_ptr().add(1) };
            let returned = unsafe { linked_node_construct(node) };
            assert_eq!(returned, node);
            let mut expected = [fill; 88];
            // Independent byte-layout reference, including untouched padding.
            for (offset, value) in [(0, 0x089901fcu32), (4, 0), (8, 0),
                                   (16, 44100), (20, 1), (24, 16),
                                   (28, 0x7fff), (32, 1000), (36, 0),
                                   (40, 0), (44, 0), (48, 0x7fff),
                                   (52, 0), (56, 1), (64, 0),
                                   (68, 0x7fff), (72, 0)] {
                expected[4 + offset..8 + offset].copy_from_slice(&value.to_ne_bytes());
            }
            for offset in [12, 60, 61, 62, 76] {
                expected[4 + offset] = 0;
            }
            let actual = unsafe {
                core::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), 88)
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn reconstruction_resets_mutated_links_limits_and_flags() {
        let mut node = [0xdeadbeefu32; 20];
        unsafe { linked_node_construct(node.as_mut_ptr()); }
        node[7] = 0;
        node[13] = 0x12345678;
        node[15] = 0x87654321;
        node[16] = 0x23456789;
        node[17] = 0;
        node[19] = 0xabcdef12;
        unsafe { linked_node_construct(node.as_mut_ptr()); }
        assert_eq!(node[7], 0x7fff);
        assert_eq!(node[13], 0);
        assert_eq!(node[16], 0);
        assert_eq!(node[17], 0x7fff);
        assert_eq!(node[15].to_ne_bytes(), [0, 0, 0, 0x87]);
        assert_eq!(node[19].to_ne_bytes(), [0, 0xef, 0xcd, 0xab]);
    }
}
