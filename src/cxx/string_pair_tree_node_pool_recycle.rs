//! String-pair tree node recycle — `FUN_083c5a34` @ load `0x083c5a34`.
//!
//! True extent: 40 bytes, ten A32 words through pop at 0x083c5a58;
//! the next independent rotation starts at 0x083c5a5c. Raw branch decoding
//! finds one inbound plain BL at 0x082a81b4 and no predicated inbound BLs.
//! The body has zero plain BLs and one predicated BL at 0x083c5a50 to
//! `cxx_string_release` @ 0x083d8b04.
//!
//! Also ports `FUN_083c369c` @ load `0x083c369c`: 40 bytes through the pop
//! at 0x083c36c0, before the independent rotation at 0x083c36c4. One inbound
//! plain BL at 0x0815bacc; zero predicated inbound BLs. Its body has zero
//! plain BLs and one BLNE at 0x083c36b8 to the same string release function.
//! All nine non-call words match 0x083c5a34; the call words differ only in
//! PC-relative displacement. Both addresses use this export, without a
//! redundant wrapper. The caller recycles its header with release_value=0.
//!
//! Copy pool+4 into node+12, optionally release the string at node+16 for
//! any nonzero flag, then publish the node at pool+4. Other node fields,
//! including the second payload word, remain untouched.
//!
//! Deliberate deviations: retain target-width pool/node words on hosts;
//! widen the string pointer into a temporary host slot before calling the
//! existing destructor, which does not modify its slot. ARM uses the real
//! node slot directly. Rust control flow replaces the predicated call.

use super::string::cxx_string_release;

/// # Safety
/// `pool` and `node` must address writable aligned pool/node words. For a
/// nonzero flag, node word 4 must identify a valid COW string representation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_pair_tree_node_pool_recycle(
    pool: *mut u32,
    node: *mut u32,
    release_value: u32,
) {
    node.add(3).write(pool.add(1).read());
    if release_value != 0 {
        #[cfg(target_pointer_width = "32")]
        cxx_string_release(node.add(4).cast());
        #[cfg(not(target_pointer_width = "32"))]
        {
            let mut string = node.add(4).read() as usize as *mut u8;
            cxx_string_release(&mut string);
        }
    }
    pool.add(1).write(node as usize as u32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string::StringRep;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn zero_flag_recycles_header_without_accessing_a_string_slot() {
        let mut pool = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        // Exactly four words: there is no string slot to dereference.
        let mut header = [0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc, 0xdddd_dddd];
        unsafe {
            string_pair_tree_node_pool_recycle(pool.as_mut_ptr(), header.as_mut_ptr(), 0);
        }
        assert_eq!(pool, [0x1111_1111, header.as_ptr() as usize as u32, 0x3333_3333, 0x4444_4444]);
        assert_eq!(header, [0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc, 0x2222_2222]);
    }

    #[test]
    fn prepends_preserves_payload_and_releases_for_every_nonzero_flag() {
        let Some(slab) = try_map_u32_slab(hints::STRING_PAIR_TREE_NODE_POOL_RECYCLE, 4096) else {
            assert!(crate::testing::note_missing_u32_fixture("cxx::string_pair_tree_node_pool_recycle"));
            return;
        };
        unsafe {
            let pool = slab.cast::<u32>();
            let node = pool.add(16);
            let rep = pool.add(32).cast::<StringRep>();
            let data = rep.add(1).cast::<u8>();
            for flag in [0, 1, 2, 0x8000_0000, u32::MAX] {
                for head in [0, 0x1234_5678] {
                    pool.write(0xaabb_ccdd);
                    pool.add(1).write(head);
                    pool.add(2).write(0x1122_3344);
                    pool.add(3).write(0x5566_7788);
                    let original = [0xface_0001, 0x123, 0x456, 0x789, data as usize as u32, 0xdead_beef];
                    core::ptr::copy_nonoverlapping(original.as_ptr(), node, 6);
                    rep.write(StringRep { refcount: 1, capacity: 8, length: 1 });
                    string_pair_tree_node_pool_recycle(pool, node, flag);
                    assert_eq!(core::slice::from_raw_parts(pool, 4), &[0xaabb_ccdd, node as usize as u32, 0x1122_3344, 0x5566_7788]);
                    let mut expected = original;
                    expected[3] = head;
                    assert_eq!(core::slice::from_raw_parts(node, 6), &expected);
                    assert_eq!((*rep).refcount, if flag == 0 { 1 } else { 0 });
                    assert_eq!(((*rep).capacity, (*rep).length), (8, 1));
                }
            }
            // Header recycling must not dereference its uninitialized value.
            node.add(4).write(0);
            string_pair_tree_node_pool_recycle(pool, node, 0);
            assert_eq!(node.add(3).read(), node as usize as u32);
            assert_eq!(node.add(4).read(), 0);
        }
    }
}
