//! Signed-key tree search helpers.
//!
//!
//! `signed_key_tree_find_node_copy` — original: `FUN_083dbab4` @
//! `0x083dbab4` (**168 bytes**, exactly `0x083dbab4..0x083dbb58`; the
//! separately linked sibling starts at `0x083dbb5c`).
//!
//! Raw `osos.dec` decoding finds **2 direct inbound plain `bl` call sites**
//! (0x081bdd24 and 0x0839bce8), **0 predicated `bl` call sites**, and no
//! direct `b` transfers. Its body has four unconditional `bl` instructions:
//! two calls to `less_signed` @ 0x083d7580, one to the ported
//! `equal_deref_f950_copy` @ 0x083cf950, and one to the exact node-key
//! accessor @ 0x083b6b34.
//!
//! It first performs `std::_Rb_tree::lower_bound` descent from
//! `header->root` (+0x4): a node key at +0x10 less than the query follows
//! the right child (+0xc); otherwise it becomes the candidate and follows
//! the left child (+0x8). The final equality check returns that candidate
//! only when its key equals the query; it otherwise writes the header
//! sentinel through `out_node`. Deliberate deviations: equality is the
//! equivalent candidate/header and signed-key comparisons, the node-key
//! accessor is +0x10, and ignored comparator slack arguments are omitted.
//!
//! `signed_key_tree_find_value` — original: `FUN_0839bccc` @ `0x0839bccc`
//! (**84 bytes**, exactly `0x0839bccc..0x0839bd20`; the next separately
//! linked function starts with `push {r4-r8,lr}` at `0x0839bd20`).
//!
//! Decoding every ARM B/BL word in `osos.dec` finds exactly **8 direct
//! unconditional `bl` call sites** — 0x081bca78, 0x081bd1fc, 0x081bd67c,
//! 0x081bdcf4, 0x081bdf74, 0x081be008, 0x081be0cc, and 0x081be144. There are
//! no predicated calls, direct `b` transfers, or aligned data-word references.

use core::ptr::{addr_of, addr_of_mut};
/// `signed_key_tree_find_node_f8f0_copy` — original: `FUN_083db964` @
/// `0x083db964` (**168 bytes**, exactly `0x083db964..0x083dba08`; the next
/// separately linked sibling starts at `0x083dba0c`).
///
/// Raw A32 decoding finds **2 direct inbound plain `bl` call sites**
/// (0x081bd328 and 0x0839bc40), **0 predicated `bl` call sites**, and no
/// direct `b` transfers. Its body has four unconditional `bl` instructions:
/// `less_signed` @ 0x083d7580 twice, `equal_deref_f8f0_copy` @ 0x083cf8f0,
/// and the node-key accessor @ 0x083b6b14.
///
/// It descends `std::_Rb_tree::lower_bound` from `header->root` (+0x4):
/// a node key at +0x10 less than the query follows the right child (+0xc);
/// otherwise it becomes the candidate and follows the left child (+0x8).
/// A candidate equal to the header or strictly greater than the query writes
/// the header sentinel through `out_node`; otherwise it writes the candidate.
/// Deliberate deviations: the two leaf helpers are equivalent direct
/// candidate/header comparison and `candidate + 0x10`, and ignored comparator
/// slack arguments plus stack scratch stores are omitted.
///
/// Exact signed-key tree lookup after lower-bound descent.
///
/// # Safety
///
/// `tree`, `key`, and `out_node` must be valid, aligned pointers. `tree`'s
/// header must point to a readable target-layout header with its root at +0x4;
/// every reachable node must expose readable child words at +0x8/+0xc and a
/// signed key at +0x10. As in retailOS, NULL and malformed links fault or
/// loop rather than being checked.
#[cfg_attr(
    target_os = "none",
    link_section = ".text.signed_key_tree_find_node_f8f0_copy"
)]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_key_tree_find_node_f8f0_copy(
    out_node: *mut u32,
    tree: *const SignedKeyTree,
    key: *const i32,
) {
    let header = addr_of!((*tree).header).read();
    let mut node = (header as usize as *const u32).add(1).read();
    let mut candidate = header;
    let comparator = tree.cast::<u8>().add(0x19);
    while node != 0 {
        let node_words = node as usize as *const u32;
        if crate::cxx::templates::less_signed(
            comparator,
            node_words.add(4).cast::<i32>(),
            key,
        ) != 0
        {
            node = node_words.add(3).read();
        } else {
            candidate = node;
            node = node_words.add(2).read();
        }
    }
    if candidate == header
        || crate::cxx::templates::less_signed(
            comparator,
            key,
            (candidate as usize as *const i32).add(4),
        ) != 0
    {
        out_node.write(header);
    } else {
        out_node.write(candidate);
    }
}

/// The tree prefix consumed here: its header/sentinel pointer is at +0x10.
///
/// The preceding words are opaque because this wrapper neither reads nor
/// writes them. All fields are target-width words, so the layout remains 20
/// bytes on hosts as well as ARM.
#[repr(C)]
pub struct SignedKeyTree {
    pub opaque_prefix: [u32; 4],
    pub header: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(SignedKeyTree, header)];
const _: [u8; 0x14] = [0; core::mem::size_of::<SignedKeyTree>()];

/// signed_key_tree_find_node_f8a8_copy — original: `FUN_083db84c` @
/// `0x083db84c` (168 bytes, `0x083db84c..0x083db8f0`; `0x083db8f4` begins
/// the next separately entered body).
///
/// Raw `osos.dec` decoding finds exactly two inbound plain `bl` sites
/// (0x081bf824 and 0x0839bbec), no predicated inbound `bl` sites, and four
/// unconditional body `bl` instructions: `less_signed` @ 0x083d7580 twice,
/// `equal_deref` @ 0x083cf8a8, and node-key accessor @ 0x083b6b04.
///
/// Performs signed lower-bound descent from `header->root`, then writes the
/// candidate only when its key equals `key`; otherwise writes the header
/// sentinel through `out_node`.
///
/// Deliberate deviations: the byte-identical equality leaf and eight-byte
/// node-key accessor are inlined as candidate/header equality and `+0x10`;
/// the retail comparator's unused stack/register slack is omitted.
///
/// # Safety
///
/// `tree`, `key`, and `out_node` must be valid, aligned pointers. `tree`'s
/// header must point to a readable target-layout header with its root at +0x4;
/// every reachable node must expose readable child words at +0x8/+0xc and a
/// signed key at +0x10. As in retailOS, NULL and malformed links fault or
/// loop rather than being checked.
#[cfg_attr(target_os = "none", link_section = ".text.signed_key_tree_find_node_f8a8_copy")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_key_tree_find_node_f8a8_copy(
    out_node: *mut u32,
    tree: *const SignedKeyTree,
    key: *const i32,
) {
    let header = addr_of!((*tree).header).read();
    let mut node = (header as usize as *const u32).add(1).read();
    let mut candidate = header;
    let comparator = tree.cast::<u8>().add(0x19);
    while node != 0 {
        let node_words = node as usize as *const u32;
        if crate::cxx::templates::less_signed(
            comparator,
            node_words.add(4).cast::<i32>(),
            key,
        ) != 0
        {
            node = node_words.add(3).read();
        } else {
            candidate = node;
            node = node_words.add(2).read();
        }
    }
    if candidate == header
        || crate::cxx::templates::less_signed(
            comparator,
            key,
            (candidate as usize as *const i32).add(4),
        ) != 0
    {
        out_node.write(header);
    } else {
        out_node.write(candidate);
    }
}

/// Exact signed-key tree lookup after lower-bound descent.
///
/// # Safety
///
/// `tree`, `key`, and `out_node` must be valid, aligned pointers. `tree`'s
/// header must point to a readable target-layout header with its root at +0x4;
/// every reachable node must expose readable child words at +0x8/+0xc and a
/// signed key at +0x10. As in retailOS, NULL and malformed links fault or
/// loop rather than being checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_key_tree_find_node_copy(
    out_node: *mut u32,
    tree: *const SignedKeyTree,
    key: *const i32,
) {
    let header = addr_of!((*tree).header).read();
    let mut node = (header as usize as *const u32).add(1).read();
    let mut candidate = header;
    let comparator = tree.cast::<u8>().add(0x19);
    while node != 0 {
        let node_words = node as usize as *const u32;
        if crate::cxx::templates::less_signed(
            comparator,
            node_words.add(4).cast::<i32>(),
            key,
        ) != 0
        {
            node = node_words.add(3).read();
        } else {
            candidate = node;
            node = node_words.add(2).read();
        }
    }
    if candidate == header
        || crate::cxx::templates::less_signed(
            comparator,
            key,
            (candidate as usize as *const i32).add(4),
        ) != 0
    {
        out_node.write(header);
    } else {
        out_node.write(candidate);
    }
}
/// signed_key_tree_find_node_f908_copy — original: `FUN_083dba0c` @
/// `0x083dba0c` (168 bytes, exactly `0x083dba0c..0x083dbab0`; the next
/// separately linked function begins at `0x083dbab4`).
///
/// Raw A32 decoding finds two inbound unconditional plain `bl` call sites
/// (0x081bea14 and 0x0839bc78), no predicated inbound calls, and four
/// unconditional body `bl` instructions: `less_signed` @ 0x083d7580 twice,
/// `equal_deref_f908_copy` @ 0x083cf908, and `node_key_accessor` @
/// 0x083b6b1c. It is the signed lower-bound walk: select the least node not
/// less than `key`, then return it only when `key` is not less than its key;
/// otherwise write the header sentinel through `out_node`.
///
/// Deliberate deviations: the two byte-identical leaf helpers are expressed
/// as direct candidate/header comparison and the node key's +0x10 word; the
/// signed comparator remains the established Rust seam. Dead ABI slack
/// arguments and stack scratch stores are omitted.
///
/// # Safety
///
/// `tree`, `key`, and `out_node` must meet
/// [`signed_key_tree_find_node_copy`]'s target-layout pointer requirements.
#[cfg_attr(
    target_os = "none",
    link_section = ".text.signed_key_tree_find_node_f908_copy"
)]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_key_tree_find_node_f908_copy(
    out_node: *mut u32,
    tree: *const SignedKeyTree,
    key: *const i32,
) {
    let header = addr_of!((*tree).header).read();
    let mut node = (header as usize as *const u32).add(1).read();
    let mut candidate = header;
    let comparator = tree.cast::<u8>().add(0x19);
    while node != 0 {
        let node_words = node as usize as *const u32;
        if crate::cxx::templates::less_signed(
            comparator,
            node_words.add(4).cast::<i32>(),
            key,
        ) != 0
        {
            node = node_words.add(3).read();
        } else {
            candidate = node;
            node = node_words.add(2).read();
        }
    }
    if candidate == header
        || crate::cxx::templates::less_signed(
            comparator,
            key,
            (candidate as usize as *const i32).add(4),
        ) != 0
    {
        out_node.write(header);
    } else {
        out_node.write(candidate);
    }
}


/// signed_key_tree_find_value — original: `FUN_0839bccc` @ `0x0839bccc`
/// (84 bytes; 8 direct, unconditional `bl` call sites).
///
/// Looks up signed `key` in `tree`. On a match, stores the target-width value
/// word at the selected node's +0x14 slot into `out_value` and returns 1. On a
/// miss, leaves `out_value` untouched and returns 0.
///
/// # Safety
///
/// `tree` must designate a readable [`SignedKeyTree`], `out_value` must be
/// writable on a non-header result, and every reachable node must satisfy
/// [`signed_key_tree_find_node_copy`]'s pointer requirements. A selected
/// node must have a readable aligned word at +0x14. As in the original,
/// none of these pointers is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_key_tree_find_value(
    tree: *const SignedKeyTree,
    key: i32,
    out_value: *mut u32,
) -> u32 {
    let mut candidate = 0u32;
    signed_key_tree_find_node_copy(addr_of_mut!(candidate), tree, addr_of!(key));

    let header = addr_of!((*tree).header).read();
    if candidate == header {
        return 0;
    }

    out_value.write((candidate as usize as *const u32).add(5).read());
    1
}
/// signed_key_tree_find_value_copy — original: `FUN_0839bbd0` @ `0x0839bbd0`
/// (84 bytes, `0x0839bbd0..0x0839bc20`; the separately linked sibling begins
/// at `0x0839bc24`; 8 direct, unconditional `bl` call sites).
///
/// Looks up signed `key` in `tree` through
/// [`signed_key_tree_find_node_f8a8_copy`]. A non-header result stores its
/// target-width value word at node + 0x14 through `out_value` and returns 1.
/// A header result preserves `out_value` and returns 0.
///
/// Deliberate deviation: the original's `equal_deref` copy @ 0x083cf8a8 is
/// represented by the equivalent direct candidate/header comparison.
///
/// # Safety
///
/// `tree` must designate a readable [`SignedKeyTree`], `out_value` must be
/// writable on a match, and every reachable node must satisfy
/// [`signed_key_tree_find_node_f8a8_copy`]'s target-layout pointer
/// requirements. A matching node must have a readable aligned word at +0x14.
/// As in the original, none of these pointers is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_key_tree_find_value_copy(
    tree: *const SignedKeyTree,
    key: i32,
    out_value: *mut u32,
) -> u32 {
    let mut candidate = 0u32;
    signed_key_tree_find_node_f8a8_copy(addr_of_mut!(candidate), tree, addr_of!(key));

    let header = addr_of!((*tree).header).read();
    if candidate == header {
        return 0;
    }

    out_value.write((candidate as usize as *const u32).add(5).read());
    1
}



/// signed_key_tree_find_node — original: `FUN_083dbf00` @ `0x083dbf00`
/// (180 bytes, `0x083dbf00..0x083dbfb4`; the separately linked next function
/// opens with `push {r1,r2,r3,lr}` at `0x083dbfb4`; exactly 4 direct,
/// unconditional `bl` call sites — 0x08101388, 0x081016dc, 0x08175210,
/// 0x081775a8 — and no predicated calls).
///
/// `std::_Rb_tree<int, ...>::find(const int &key)`: descends from the
/// header's root word (+0x4) comparing node keys at node+0x10 through
/// `less_signed` @ 0x083d7580, remembering the last not-less node; a less
/// node walks to its right child (+0xc), otherwise to its left child (+0x8).
/// The candidate is compared against the header word through the
/// `equal_deref` copy @ 0x083cf9b0; equal means empty/exhausted and the
/// header is returned. Otherwise the node's key address (retail helper
/// `FUN_083b6b4c`, `add r0, r0, #0x10; bx lr`) is fed to a second
/// `less_signed(key, node_key)`: a strictly-less key is a miss returning the
/// header, and anything else returns the found node.
///
/// Deliberate deviations: the 8-byte node-key accessor `FUN_083b6b4c` is
/// inlined as `candidate + 0x10` (its exact body), and the original's two
/// slack argument registers plus stacked zero on the first `less_signed`
/// call are not reproduced (the callee ignores them).
///
/// # Safety
///
/// `tree` must designate a readable [`SignedKeyTree`], `key` a readable
/// aligned `i32`, and every reachable tree node must expose readable aligned
/// words at +0x4 (root, header only), +0x8 (left), +0xc (right), and +0x10
/// (key). As in the original, no pointer is NULL-checked and a malformed
/// tree loops forever or faults.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_key_tree_find_node(
    tree: *const SignedKeyTree,
    key: *const i32,
) -> u32 {
    let header = addr_of!((*tree).header).read();
    let mut node = (header as usize as *const u32).add(1).read();
    let mut candidate = header;
    let comparator = tree.cast::<u8>().add(0x19);
    while node != 0 {
        let node_words = node as usize as *const u32;
        if crate::cxx::templates::less_signed(
            comparator,
            node_words.add(4).cast::<i32>(),
            key,
        ) != 0
        {
            node = node_words.add(3).read();
        } else {
            candidate = node;
            node = node_words.add(2).read();
        }
    }
    if crate::cxx::templates::equal_deref(addr_of!(candidate), addr_of!((*tree).header))
        != 0
    {
        return candidate;
    }
    if crate::cxx::templates::less_signed(
        comparator,
        key,
        (candidate as usize as *const i32).add(4),
    ) != 0
    {
        addr_of!((*tree).header).read()
    } else {
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn find_node_f8a8_copy_walks_signed_tree_and_value_copy_preserves_misses() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::SIGNED_KEY_TREE_LOWER_BOUND,
            0x1000,
        ) else {
            return;
        };
        let base = slab as usize;
        let word = |offset: usize| (base + offset) as u32;
        let (header, root, left, right) = (word(0), word(0x40), word(0x60), word(0x80));
        let write = |offset: usize, value: u32| unsafe {
            ((base + offset) as *mut u32).write(value)
        };
        write(0x04, root);
        write(0x48, left);
        write(0x4c, right);
        write(0x50, 10);
        write(0x54, 0xdead_beef);
        write(0x68, 0);
        write(0x6c, 0);
        write(0x70, 5);
        write(0x88, 0);
        write(0x8c, 0);
        write(0x90, 20);
        let tree = SignedKeyTree { opaque_prefix: [0; 4], header };
        let find = |key: i32| {
            let mut selected = 0;
            unsafe { signed_key_tree_find_node_f8a8_copy(&mut selected, &tree, &key) };
            selected
        };

        assert_eq!(find(i32::MIN), header);
        assert_eq!(find(5), left);
        assert_eq!(find(7), header);
        assert_eq!(find(10), root);
        assert_eq!(find(20), right);
        assert_eq!(find(i32::MAX), header);

        let mut output = 0;
        assert_eq!(unsafe { signed_key_tree_find_value_copy(&tree, 10, &mut output) }, 1);
        assert_eq!(output, 0xdead_beef);
        output = 0xa5a5_5a5a;
        assert_eq!(unsafe { signed_key_tree_find_value_copy(&tree, 7, &mut output) }, 0);
        assert_eq!(output, 0xa5a5_5a5a);
        write(0x04, 0);
        output = 0xa5a5_5a5a;
        assert_eq!(unsafe { signed_key_tree_find_value_copy(&tree, 0, &mut output) }, 0);
        assert_eq!(output, 0xa5a5_5a5a);
    }


    #[test]
    fn find_node_walks_signed_tree_and_reports_misses() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::SIGNED_KEY_TREE_FIND_NODE,
            0x1000,
        ) else {
            return;
        };
        let base = slab as usize;
        let word = |off: usize| (base + off) as u32;
        // Node layout: +0x8 left, +0xc right, +0x10 key; header root at +0x4.
        let (header, root, left, right) = (word(0x00), word(0x40), word(0x60), word(0x80));
        let w = |off: usize, v: u32| unsafe { ((base + off) as *mut u32).write(v) };
        w(0x04, root); // header->root
        // root: key 10, children left/right
        w(0x48, left);
        w(0x4c, right);
        w(0x50, 10);
        // left: key 5, no children
        w(0x68, 0);
        w(0x6c, 0);
        w(0x70, 5);
        // right: key 20, no children
        w(0x88, 0);
        w(0x8c, 0);
        w(0x90, 20);
        let tree = SignedKeyTree { opaque_prefix: [0; 4], header };
        let find = |key: i32| unsafe { signed_key_tree_find_node(&tree, &key) };

        assert_eq!(find(10), root, "root hit");
        assert_eq!(find(5), left, "left-leaf hit");
        assert_eq!(find(20), right, "right-leaf hit");
        assert_eq!(find(7), header, "between keys: lower_bound key 10 is strictly greater");
        assert_eq!(find(25), header, "past maximum: candidate stays the header");
        assert_eq!(find(i32::MIN), header, "signed: MIN is less than every node key");
        assert_eq!(find(i32::MAX), header, "past maximum from the right spine");

        // Empty tree: the header has no root, so the candidate is the header.
        w(0x04, 0);
        assert_eq!(find(10), header, "empty tree returns the header");
    }
}
