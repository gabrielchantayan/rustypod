//! Finds the equal-key iterator range in an unsigned-word red-black tree —
//! original: `FUN_083bd47c` @ `0x083bd47c` (160 bytes).
//!
//! Raw `osos.dec` establishes the exact 40-word A32 extent
//! `0x083bd47c..0x083bd51c`: `e92d43fe` begins the body and `e8bd83fe`
//! returns; `e591200c` at `0x083bd51c` begins the next separately linked
//! function. The body contains exactly two plain unconditional `bl` calls,
//! at `0x083bd4ac` and `0x083bd4e8`, both to `less_unsigned_alias_7464`;
//! none is predicated.
//!
//! Starting at `tree + 0x10`, it finds the lower bound and upper bound of
//! `*key` in two independent walks. Nodes hold left and right target pointer
//! words at `+0x08` and `+0x0c`, with their unsigned key at `+0x10`; the
//! header is both initial candidate and no-result sentinel. It writes the
//! two target pointer words to `out[0]` and `out[1]`. Deliberate deviation:
//! target pointers remain raw `u32` words, preserving retail offsets on
//! 64-bit hosts rather than modelling them as Rust pointer fields.

use crate::cxx::templates::less_unsigned_alias_7464;

const TREE_HEADER_OFFSET: usize = 0x10;
const HEADER_ROOT_OFFSET: usize = 0x04;
const NODE_LEFT_OFFSET: usize = 0x08;
const NODE_RIGHT_OFFSET: usize = 0x0c;
const NODE_KEY_OFFSET: usize = 0x10;

#[inline(always)]
unsafe fn raw_pointer(word: u32) -> *mut u8 {
    word as usize as *mut u8
}

#[inline(always)]
unsafe fn pointer_word(address: *const u8) -> u32 {
    address.cast::<u32>().read()
}

/// # Safety
///
/// `out`, `tree`, its header, every traversed node, and `key` must be readable
/// or writable as appropriate. Stored pointer words must be valid target
/// addresses. As in retailOS, no pointer or tree-invariant checks are made.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn u32_key_tree_equal_range(
    out: *mut u32,
    tree: *const u8,
    key: *const u32,
) {
    let header = unsafe { raw_pointer(pointer_word(tree.add(TREE_HEADER_OFFSET))) };
    let mut lower = header;
    let mut node = unsafe { raw_pointer(pointer_word(header.add(HEADER_ROOT_OFFSET))) };

    while !node.is_null() {
        let node_key = unsafe { node.add(NODE_KEY_OFFSET).cast::<u32>() };
        if unsafe { less_unsigned_alias_7464(tree.add(0x19), node_key, key) } != 0 {
            node = unsafe { raw_pointer(pointer_word(node.add(NODE_RIGHT_OFFSET))) };
        } else {
            lower = node;
            node = unsafe { raw_pointer(pointer_word(node.add(NODE_LEFT_OFFSET))) };
        }
    }

    let mut upper = header;
    node = unsafe { raw_pointer(pointer_word(header.add(HEADER_ROOT_OFFSET))) };
    while !node.is_null() {
        let node_key = unsafe { node.add(NODE_KEY_OFFSET).cast::<u32>() };
        if unsafe { less_unsigned_alias_7464(tree.add(0x19), key, node_key) } == 0 {
            node = unsafe { raw_pointer(pointer_word(node.add(NODE_RIGHT_OFFSET))) };
        } else {
            upper = node;
            node = unsafe { raw_pointer(pointer_word(node.add(NODE_LEFT_OFFSET))) };
        }
    }

    unsafe {
        out.write(lower as usize as u32);
        out.add(1).write(upper as usize as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    const HEADER_OFFSET: usize = 0x40;
    const ROOT_OFFSET: usize = 0x80;
    const LOW_OFFSET: usize = 0xc0;
    const DUPLICATE_OFFSET: usize = 0x100;
    const HIGH_OFFSET: usize = 0x140;

    unsafe fn write_word(base: *mut u8, offset: usize, value: *const u8) {
        unsafe { base.add(offset).cast::<u32>().write(value as usize as u32) };
    }

    unsafe fn write_node(base: *mut u8, offset: usize, left: *const u8, right: *const u8, key: u32) {
        unsafe {
            write_word(base, offset + NODE_LEFT_OFFSET, left);
            write_word(base, offset + NODE_RIGHT_OFFSET, right);
            base.add(offset + NODE_KEY_OFFSET).cast::<u32>().write(key);
        }
    }

    #[test]
    fn returns_bounds_for_duplicates_and_keys_outside_the_tree() {
        let Some(base) = try_map_u32_slab(hints::U32_KEY_TREE_EQUAL_RANGE, 0x1000) else {
            return;
        };
        unsafe {
            base.write_bytes(0, 0x1000);
            let header = base.add(HEADER_OFFSET);
            let root = base.add(ROOT_OFFSET);
            let low = base.add(LOW_OFFSET);
            let duplicate = base.add(DUPLICATE_OFFSET);
            let high = base.add(HIGH_OFFSET);
            write_word(base, TREE_HEADER_OFFSET, header);
            write_word(header, HEADER_ROOT_OFFSET, root);
            write_node(base, ROOT_OFFSET, low, duplicate, 5);
            write_node(base, LOW_OFFSET, core::ptr::null(), core::ptr::null(), 3);
            write_node(base, DUPLICATE_OFFSET, core::ptr::null(), high, 5);
            write_node(base, HIGH_OFFSET, core::ptr::null(), core::ptr::null(), 7);

            let mut bounds = [0u32; 2];
            let key = 5;
            u32_key_tree_equal_range(bounds.as_mut_ptr(), base, &key);
            assert_eq!(bounds, [root as usize as u32, high as usize as u32]);

            let key = 2;
            u32_key_tree_equal_range(bounds.as_mut_ptr(), base, &key);
            assert_eq!(bounds, [low as usize as u32, low as usize as u32]);

            let key = 8;
            u32_key_tree_equal_range(bounds.as_mut_ptr(), base, &key);
            assert_eq!(bounds, [header as usize as u32, header as usize as u32]);
        }
    }
}
