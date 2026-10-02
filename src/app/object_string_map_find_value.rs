//! String-keyed object map value lookup.
//!
//! `object_string_map_find_value` — `FUN_0829af28` @ `0x0829af28`,
//! 64 bytes (`0x0829af28..0x0829af68`). Verified raw ARM words contain
//! one plain BL and no predicated BL; inbound calls are two plain BLs
//! at `0x081347e4` and `0x08134810`, with no predicated BL sites.
//!
//! Finds a string key in the tree at object + 0x94 via `0x083c1730`.
//! Compares the returned node word with the header word at object + 0xa4;
//! returns zero for end, otherwise the mapped value address at node + 0x14.
//! The key occupies node + 0x10. Raw callee code writes only one result word.
//! Deliberate deviations: omit the dead stack copy and unused saved r2/r3;
//! hosts replace the unported lookup with a typed seam. All stored addresses
//! remain u32, and address addition wraps like ARM.

pub type ObjectStringTreeFind = unsafe extern "C" fn(*mut u32, *const u32, *const u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_find(_: *mut u32, _: *const u32, _: *const u32) {
    panic!("object_string_map_find_value requires a host tree lookup seam")
}

#[cfg(not(target_os = "none"))]
pub static mut OBJECT_STRING_TREE_FIND: ObjectStringTreeFind = unavailable_find;

/// Object must contain a valid firmware tree at +0x94 and header at +0xa4.
/// Key must point to a firmware string handle valid for the tree comparator.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_string_map_find_value(object: *const u32, key: *const u32) -> u32 {
    let mut node = 0u32;
    #[cfg(target_os = "none")]
    let find: ObjectStringTreeFind = core::mem::transmute(0x083c_1730usize);
    #[cfg(not(target_os = "none"))]
    let find = core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_STRING_TREE_FIND));
    find(&mut node, object.add(0x94 / 4), key);
    mapped_value_address(node, object.add(0xa4 / 4).read())
}

#[inline(always)]
fn mapped_value_address(node: u32, header: u32) -> u32 {
    if node == header { 0 } else { node.wrapping_add(0x14) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_iterator_is_null_including_zero_header() {
        for header in [0, 0x0800_1000, u32::MAX] {
            assert_eq!(mapped_value_address(header, header), 0);
        }
    }

    #[test]
    fn value_skips_node_header_and_string_key_with_arm_wrapping() {
        for (node, expected) in [(0x0800_2000, 0x0800_2014), (0, 0x14), (0xffff_fff0, 4)] {
            assert_eq!(mapped_value_address(node, 0x0800_1000), expected);
        }
    }

    #[test]
    fn lookup_handles_empty_missing_and_present_keys() {
        // Host stand-in performs an actual single-entry lookup. Its fixture
        // uses target-width words without dereferencing encoded addresses.
        unsafe extern "C" fn find(out: *mut u32, tree: *const u32, key: *const u32) {
            let node = if tree.read() != 0 && tree.add(1).read() == key.read() {
                tree.add(2).read()
            } else { tree.add(4).read() };
            out.write(node);
        }
        unsafe {
            let old = OBJECT_STRING_TREE_FIND;
            OBJECT_STRING_TREE_FIND = find;
            let mut object = [0u32; 0xa8 / 4];
            object[0xa4 / 4] = 0x0800_1000;
            let key = 42;
            assert_eq!(object_string_map_find_value(object.as_ptr(), &key), 0);
            object[0x94 / 4] = 1;
            object[0x98 / 4] = 42;
            object[0x9c / 4] = 0x0800_2000;
            assert_eq!(object_string_map_find_value(object.as_ptr(), &key), 0x0800_2014);
            let absent = 43;
            assert_eq!(object_string_map_find_value(object.as_ptr(), &absent), 0);
            OBJECT_STRING_TREE_FIND = old;
        }
    }
}
