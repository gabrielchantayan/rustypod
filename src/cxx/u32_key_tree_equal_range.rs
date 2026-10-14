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

use crate::cxx::templates::{less_unsigned, less_unsigned_alias_7464};

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
    unsafe { equal_range(out, tree, key, less_unsigned_alias_7464) };
}

/// Unsigned-word tree equal range — `FUN_083d6710` @ load address
/// `0x083d6710`, true size 204 bytes (`0x083d6710..0x083d67dc`).
///
/// Raw A32 decoding verifies one inbound plain BL at `0x08185498`, zero
/// predicated inbound BLs, and two outbound plain BLs at `0x083d6748` and
/// `0x083d6784` to `less_unsigned` @ `0x083d7598`; no predicated BLs.
/// The next function starts with `ldr r1,[r0,#20]` at `0x083d67dc`.
/// Two independent root-to-leaf walks find the first node not less than
/// the query and the first node greater than it, using the header sentinel
/// when absent. Each candidate is the current node, not its left child
/// (Ghidra misorders those updates). Writes two four-byte iterator words.
///
/// Deliberate deviations: omit dead r3/stack arguments to the comparator
/// and redundant stack copies; share the existing inline two-walk algorithm.
/// Raw u32 links preserve target offsets on 64-bit hosts.
///
/// # Safety
/// All traversed links must be valid aligned target-address words in a
/// correctly ordered tree; `key` must be readable and `out` must hold two
/// writable u32 words. The header is at tree + 0x10, root at header + 4.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.u32_key_tree_equal_range_6710")]
#[inline(never)]
pub unsafe extern "C" fn u32_key_tree_equal_range_6710(
    out: *mut u32,
    tree: *const u8,
    key: *const u32,
) {
    unsafe { equal_range(out, tree, key, less_unsigned) };
}

#[inline(always)]
unsafe fn equal_range(
    out: *mut u32,
    tree: *const u8,
    key: *const u32,
    less: unsafe extern "C" fn(*const u8, *const u32, *const u32) -> u32,
) {
    let header = unsafe { raw_pointer(pointer_word(tree.add(TREE_HEADER_OFFSET))) };
    let mut lower = header;
    let mut node = unsafe { raw_pointer(pointer_word(header.add(HEADER_ROOT_OFFSET))) };

    while !node.is_null() {
        let node_key = unsafe { node.add(NODE_KEY_OFFSET).cast::<u32>() };
        if unsafe { less(tree.add(0x19), node_key, key) } != 0 {
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
        if unsafe { less(tree.add(0x19), key, node_key) } == 0 {
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

            // Exercise unsigned ordering, both bound candidates, absent keys,
            // duplicate ranges and the header-only empty-tree transition.
            let ports: [unsafe extern "C" fn(*mut u32, *const u8, *const u32); 2] =
                [u32_key_tree_equal_range, u32_key_tree_equal_range_6710];
            write_node(base, ROOT_OFFSET, low, duplicate, 0x8000_0000);
            write_node(base, LOW_OFFSET, core::ptr::null(), core::ptr::null(), 0);
            write_node(base, DUPLICATE_OFFSET, core::ptr::null(), high, 0x8000_0000);
            write_node(base, HIGH_OFFSET, core::ptr::null(), core::ptr::null(), u32::MAX);
            for port in ports {
                for (key, expected) in [
                    (0, [low, root]),
                    (1, [root, root]),
                    (0x7fff_ffff, [root, root]),
                    (0x8000_0000, [root, high]),
                    (0x8000_0001, [high, high]),
                    (u32::MAX, [high, header]),
                ] {
                    let mut output = [0xdead_beef, 0, 0, 0xcafe_babe];
                    port(output.as_mut_ptr().add(1), base, &key);
                    assert_eq!(output, [
                        0xdead_beef, expected[0] as usize as u32,
                        expected[1] as usize as u32, 0xcafe_babe,
                    ]);
                }
            }
            write_word(header, HEADER_ROOT_OFFSET, core::ptr::null());
            for port in ports {
                for key in [0, 0x8000_0000, u32::MAX] {
                    port(bounds.as_mut_ptr(), base, &key);
                    assert_eq!(bounds, [header as usize as u32; 2]);
                }
            }
        }
    }
}
