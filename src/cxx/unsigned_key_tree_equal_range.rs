//! Unsigned-key equal range — `FUN_083d6578` @ load address `0x083d6578`.
//!
//! True size: 204 bytes, `0x083d6578..0x083d6644` (next function's push).
//! Raw A32 decoding verifies one incoming plain BL at 0x081b5cb4, zero
//! predicated incoming BLs, and two outgoing plain BLs at 0x083d65b0 and
//! 0x083d65ec to `less_unsigned_alias_7568` @ 0x083d7568; no predicated BLs.
//! Independently descends lower and upper bounds from header+4, retaining
//! the current candidate before following its left child. Writes two
//! target-width iterator words; the header denotes end. Ghidra incorrectly
//! assigns the child to each candidate. Deliberate deviations: omit unused
//! fourth/stack comparator arguments and redundant stack copies. Reuse the
//! existing comparator port; no new firmware seam.

/// Target-width tree prefix; the header address remains at +0x10 on hosts.
#[repr(C)]
pub struct UnsignedKeyTree {
    pub opaque_prefix: [u32; 4],
    pub header: u32,
}

/// Find the half-open range of nodes whose unsigned key equals `*key`.
///
/// # Safety
/// Tree storage extends through +0x19. Header and reachable nodes have valid
/// aligned u32 links at +4/+8/+12 and keys at +16. `key` is readable and
/// `out` has two writable u32 words. Malformed trees remain unchecked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn unsigned_key_tree_equal_range(
    out: *mut u32,
    tree: *const UnsignedKeyTree,
    key: *const u32,
) {
    let header = (*tree).header;
    let comparator = tree.cast::<u8>().add(0x19);
    let mut lower = header;
    let mut node = (header as usize as *const u32).add(1).read();
    while node != 0 {
        let words = node as usize as *const u32;
        if crate::cxx::templates::less_unsigned_alias_7568(comparator, words.add(4), key) == 0 {
            lower = node;
            node = words.add(2).read();
        } else {
            node = words.add(3).read();
        }
    }
    let mut upper = header;
    node = (header as usize as *const u32).add(1).read();
    while node != 0 {
        let words = node as usize as *const u32;
        if crate::cxx::templates::less_unsigned_alias_7568(comparator, key, words.add(4)) != 0 {
            upper = node;
            node = words.add(2).read();
        } else {
            node = words.add(3).read();
        }
    }
    out.write(lower);
    out.add(1).write(upper);
}

#[cfg(test)]
mod tests {
    #[test]
    fn duplicate_bounds_unsigned_extremes_absences_and_empty() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::UNSIGNED_KEY_TREE_EQUAL_RANGE, 0x1000,
        ) else { return; };
        unsafe {
            let header = slab as usize as u32;
            let offsets = [0x40usize, 0x60, 0x80, 0xa0, 0xc0];
            let keys = [0u32, 7, 7, 0x8000_0000, u32::MAX];
            let nodes = offsets.map(|offset| slab.add(offset) as usize as u32);
            let left = [0, nodes[0], nodes[1], 0, 0];
            let right = [0, 0, nodes[3], nodes[4], 0];
            for i in 0..5 {
                let words = slab.add(offsets[i]).cast::<u32>();
                words.add(2).write(left[i]);
                words.add(3).write(right[i]);
                words.add(4).write(keys[i]);
            }
            let root = slab.cast::<u32>().add(1);
            root.write(nodes[2]);
            let tree = slab.add(0x200).cast::<super::UnsignedKeyTree>();
            tree.write(super::UnsignedKeyTree { opaque_prefix: [0; 4], header });
            for query in [0, 1, 6, 7, 8, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, u32::MAX] {
                let lower = keys.iter().position(|&key| key >= query).map_or(header, |i| nodes[i]);
                let upper = keys.iter().position(|&key| key > query).map_or(header, |i| nodes[i]);
                let mut output = [0xdead_beef, 0, 0, 0xfeed_face];
                super::unsigned_key_tree_equal_range(output.as_mut_ptr().add(1), tree, &query);
                assert_eq!(output, [0xdead_beef, lower, upper, 0xfeed_face], "query {query}");
            }
            root.write(0);
            let mut output = [0; 2];
            super::unsigned_key_tree_equal_range(output.as_mut_ptr(), tree, core::ptr::null());
            assert_eq!(output, [header; 2]);
            root.write(nodes[4]);
            for (query, expected) in [(0, [nodes[4]; 2]), (u32::MAX, [nodes[4], header])] {
                super::unsigned_key_tree_equal_range(output.as_mut_ptr(), tree, &query);
                assert_eq!(output, expected);
            }
        }
    }
}
