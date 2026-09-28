//! Red-black tree in-order iterator increment — original: `FUN_083b580c` @
//! `0x083b580c`.
//!
//! Raw `osos.dec` runs for **88 bytes**, `0x083b580c..0x083b5860`; the next
//! separately linked sibling begins at `0x083b5864`. Decoding every ARM B/BL
//! word finds exactly **6 direct, unconditional `bl` callers** at 0x0825b890,
//! 0x0825b940, 0x0825bb30, 0x0825bbc8, 0x0825bc70, and 0x0825bcec. There are
//! no predicated calls, direct `b` transfers, or aligned data-word references.
//!
//! The function returns the original node held by `cursor` and advances the
//! cursor to its in-order successor. A right child selects that subtree's
//! leftmost node. Otherwise it climbs parent links while leaving right-child
//! edges, then selects the first ancestor reached from a left-child edge; the
//! sentinel case is preserved by the final right-link comparison.
//!
//! Deliberate deviations: none. Links remain target-width `u32` words, rather
//! than host pointers, so their 32-bit `repr(C)` layout and host fixtures match
//! the firmware exactly.
//!
//! `FUN_083b5ea4` at load address `0x083b5ea4` is a byte-identical, 84-byte
//! (21-word) copy of the `red_black_tree_advance_cursor` body ported below,
//! ending with `bx lr` at `0x083b5ef4`; the separately linked sibling begins
//! at `0x083b5ef8`. A complete aligned ARM B/BL decode verifies exactly four
//! direct inbound calls, all unconditional `bl` at `0x08147398`,
//! `0x08147514`, `0x083c85a0`, and `0x083c8a70`; there are no predicated
//! calls, direct tail-`B` transfers, or aligned data-word references. Like
//! the primary copy, it leaves r0 unchanged, so the cursor address is
//! returned. This alias reuses the established dispatch seam and shared host
//! tests; deliberate deviations: none.
//!
//! `FUN_083b5ef8` at load address `0x083b5ef8` is a byte-identical, 84-byte
//! (21-word) copy of `red_black_tree_advance_cursor`, ending with `bx lr` at
//! `0x083b5f48`; the next separately linked sibling begins at `0x083b5f4c`.
//! Complete aligned A32 B/BL-immediate decoding finds two inbound
//! unconditional plain `bl` calls at 0x083c8fe4 and 0x083c94b4, zero
//! predicated BL calls, and no outbound calls. It advances the target-width
//! cursor to the red-black-tree in-order successor: descend through the right
//! subtree's left spine, or climb parent links while leaving right-child
//! edges, retaining the header sentinel. This exact duplicate deliberately
//! reuses the established dispatch seam and shared host tests; deliberate
//! deviations: none.
//!
//!
//! `FUN_083b5e50` at load address `0x083b5e50` is an 84-byte (21-word) copy
//! of `red_black_tree_advance_cursor`, through `bx lr` at `0x083b5ea0`; the
//! next separately linked sibling begins at `0x083b5ea4`. Aligned ARM B/BL
//! decoding verifies three direct inbound calls, all unconditional `bl` at
//! `0x083c7a50`, `0x083c7f20`, and `0x083c801c`; there are no predicated BL
//! calls and the body itself contains no calls. Its raw bytes are identical to
//! the port at `0x083b609c`, so it deliberately reuses this implementation and
//! its host tests. The function leaves r0 unchanged and returns the cursor
//! address; deliberate deviations: none.
//!
//! `FUN_083b5dfc` at load address `0x083b5dfc` is a byte-identical,
//! 84-byte (21-word) copy of `red_black_tree_advance_cursor`, ending with
//! `bx lr` at `0x083b5e48`; the next independently entered function starts at
//! `0x083b5e50`. Complete aligned A32 B/BL-immediate decoding finds exactly
//! two inbound plain unconditional `bl` calls at 0x083c700c and 0x083c74dc,
//! zero predicated `bl` calls, and no outbound calls. It advances an in-order
//! cursor to its successor by descending the right subtree's left spine, or
//! climbing parent links while leaving right-child edges, retaining the header
//! sentinel. This exact duplicate deliberately reuses the established dispatch
//! seam and host tests covering each successor path; deliberate deviations:
//! none.
//!
//!
//! `FUN_083b5c04` at load address `0x083b5c04` is an 84-byte (21-word)
//! byte-identical copy of `red_black_tree_advance_cursor`, ending with `bx lr`
//! at `0x083b5c54`; the next independently entered function begins at
//! `0x083b5c58`. Complete aligned A32 B/BL-immediate decoding finds two
//! inbound unconditional plain `bl` instructions at 0x083c2398 and
//! 0x083c2870, zero predicated `bl` instructions, and no outbound calls. It
//! advances the target-width cursor to its in-order successor: descend through
//! the right subtree's left spine, or climb parent links while leaving
//! right-child edges, retaining the header sentinel. This exact duplicate
//! deliberately reuses the established dispatch seam; its dedicated host test
//! covers the sibling-successor path. Deliberate deviations: none.
//!
//! `FUN_083b5c58` at load address `0x083b5c58` is an 84-byte (21-word)
//! byte-identical copy of `red_black_tree_advance_cursor`, through `bx lr` at
//! `0x083b5ca8`; the next separately linked sibling begins at `0x083b5cac`.
//! Complete aligned raw A32 B/BL-immediate decoding finds two inbound plain,
//! unconditional `bl` instructions at 0x083c37a8 and 0x083c3c80, zero
//! predicated `bl` instructions, and no outbound calls. It leaves r0
//! unchanged while advancing the target-width cursor to the red-black-tree
//! in-order successor: descend through the right subtree's left spine, or
//! climb parent links while leaving right-child edges, retaining the header
//! sentinel. This exact duplicate deliberately reuses the established dispatch
//! seam and shared host tests; deliberate deviations: none.
//!
//! `FUN_083b5cac` at load address `0x083b5cac` is a third byte-identical,
//! 84-byte (21-word) copy of the same `red_black_tree_advance_cursor` body,
//! ending with `bx lr` at `0x083b5cfc`; the separately linked sibling begins
//! at `0x083b5d00`. A complete aligned ARM B/BL decode verifies exactly four
//! direct inbound calls, all unconditional `bl` at `0x08101e48`,
//! `0x083c426c`, `0x083c4740`, and `0x083c483c`; there are no predicated
//! calls, direct tail-`B` transfers, or aligned data-word references. Ghidra
//! reports the matching 84-byte size. This copy likewise leaves r0 unchanged
//! and returns the cursor address. It reuses the same exported
//! [`red_black_tree_advance_cursor`] symbol and shared host tests;
//! deliberate deviations: none.
//!
//! `FUN_083b58b8` at load address `0x083b58b8` is a byte-identical, 84-byte
//! (21-word) copy of `red_black_tree_advance_cursor`, through `bx lr` at
//! `0x083b5908`; the next independently linked function starts at
//! `0x083b590c`. Complete aligned ARM B/BL decoding finds three inbound
//! direct calls, all unconditional plain `bl` at 0x08211b50, 0x083b6e9c, and
//! 0x083b7374; there are no predicated BL calls or outbound calls. It
//! deliberately reuses this dispatch seam and its host tests because its
//! target code and ABI are identical; deliberate deviations: none.
//!
//! `FUN_083b5664` at load address `0x083b5664` is a byte-identical, 84-byte
//! (21-word) copy of `red_black_tree_advance_cursor`, ending with `bx lr` at
//! `0x083b56b4`; the next separately linked function begins at `0x083b56b8`.
//! Complete aligned ARM B/BL decoding finds three inbound calls, all plain
//! `bl` at 0x083be03c, 0x083be50c, and 0x083be608, with zero predicated BL
//! calls and no outbound calls. It advances an in-order cursor to its
//! successor by descending the right subtree's left spine or climbing parent
//! links from right-child edges, preserving the header sentinel. The
//! byte-identical body deliberately reuses this dispatch seam and shared host
//! tests; deliberate deviations: none.
//!
//! `FUN_083b55bc` at load address `0x083b55bc` is a byte-identical, 84-byte
//! (21-word) copy of `red_black_tree_advance_cursor`, ending with `bx lr` at
//! `0x083b560c`; the next separately linked sibling begins at `0x083b5610`.
//! Raw full-image A32 branch decoding establishes three inbound plain `bl`
//! calls and zero predicated `bl` calls; the body has no calls. It returns the
//! cursor address unchanged while advancing its target-width node word to the
//! in-order successor. This exact duplicate deliberately reuses the exported
//! `red_black_tree_advance_cursor` seam and its host tests; no deviations.
//!
//! `FUN_083b5514` at load address `0x083b5514` is a byte-identical 84-byte
//! (21-word) copy of `red_black_tree_advance_cursor`, through `bx lr` at
//! `0x083b5564`; the next independently linked function begins at
//! `0x083b5568`. Full-image A32 branch decoding finds three inbound plain
//! `bl` calls at 0x083bab54, 0x083bb024, and 0x083bb120, with zero predicated
//! `bl` calls; the body itself makes no calls. It returns the cursor address
//! unchanged while advancing its target-width node word to its in-order
//! successor by descending the right subtree's left edge or climbing parent
//! links to the first left-child ancestor, preserving the header sentinel.
//! This exact duplicate deliberately reuses the exported
//! `red_black_tree_advance_cursor` seam and its host tests; deliberate
//! deviations: none.
//!
//! `FUN_083b6198` at load address `0x083b6198` is a byte-identical,
//! 84-byte (21-word) copy of `red_black_tree_advance_cursor`, ending with
//! `bx lr` at `0x083b61e8`; the next separately linked function begins at
//! `0x083b61ec`. Raw A32 decoding confirms its two inbound calls are plain,
//! unconditional `bl` instructions at 0x083cc36c and 0x083cc83c, with zero
//! predicated `bl` calls; the body itself contains no calls. It advances an
//! in-order cursor by descending the right subtree's left spine or climbing
//! parent links from right-child edges, retaining the header sentinel. The
//! byte-identical body deliberately reuses this dispatch seam and its shared
//! host tests; deliberate deviations: none.
//!
//! `FUN_083b5ff4` at load address `0x083b5ff4` is a byte-identical 84-byte
//! (21-word) copy of `red_black_tree_advance_cursor`, ending with `bx lr` at
//! `0x083b6044`; the next separately entered function begins at `0x083b6048`.
//! Whole-image A32 B/BL-immediate decoding finds two inbound plain,
//! unconditional `bl` sites (`0x083caedc` and `0x083cb3b0`) and zero
//! predicated `bl` sites; the body has no outbound calls. It returns the
//! cursor address while advancing the target-width cursor to its in-order
//! successor: descend the right subtree's left spine, or climb parent links
//! from right-child edges through the header sentinel. The byte-identical body
//! deliberately reuses this implementation and its shared host tests;
//! deliberate deviations: none.
//!
//! `FUN_083b5fa0` at load address `0x083b5fa0` is a byte-identical 84-byte
//! (21-word) copy of `red_black_tree_advance_cursor`, ending with `bx lr` at
//! `0x083b5ff0`; the next separately entered function begins at `0x083b5ff4`.
//! Raw A32 decoding verifies its two inbound calls are unconditional plain
//! `bl` instructions at `0x083ca46c` and `0x083ca93c`, with zero predicated
//! `bl` instructions and no outbound calls. It returns the cursor address
//! while advancing the target-width cursor to its in-order successor: descend
//! the right subtree's left spine, or climb parent links from right-child edges
//! through the header sentinel. The byte-identical body deliberately reuses
//! this implementation and its shared host tests; deliberate deviations: none.
//!
//! `FUN_083b5f4c` at load address `0x083b5f4c` is a byte-identical 84-byte
//! (21-word) copy of `red_black_tree_advance_cursor`, ending with `bx lr` at
//! `0x083b5f9c`; the next independently entered function begins at
//! `0x083b5fa0`. Raw full-image A32 B/BL-immediate decoding finds two inbound
//! unconditional plain `bl` sites at 0x083c9a28 and 0x083c9ef8, zero
//! predicated `bl` sites, and no outbound calls. It returns the cursor address
//! while advancing the target-width cursor to its in-order successor: descend
//! the right subtree's left spine, or climb parent links from right-child edges
//! through the header sentinel. This byte-identical copy deliberately reuses
//! the established dispatch seam and shared host tests; deliberate deviations:
//! none.




/// Base node layout used by the C++ red-black tree implementation.
///
/// The color word is opaque here. The remaining fields are target-width
/// addresses: parent at +0x04, left child at +0x08, and right child at +0x0c.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreeNode {
    pub color: u32,
    pub parent: u32,
    pub left: u32,
    pub right: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreeNode, parent)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreeNode, left)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreeNode, right)];
const _: [u8; 0x10] = [0; core::mem::size_of::<RedBlackTreeNode>()];

#[inline(always)]
unsafe fn node_from_word(address: u32) -> *mut RedBlackTreeNode {
    address as usize as *mut RedBlackTreeNode
}

/// Advances `cursor` to the next node in red-black-tree in-order traversal.
/// Original: `FUN_083b580c` @ `0x083b580c` (88 bytes; 6 direct,
/// unconditional `bl` callers).
///
/// Returns the node that was in `*cursor` before the advance.
///
/// # Safety
///
/// `cursor` must be writable and initially contain a valid non-NULL
/// [`RedBlackTreeNode`] address. Every link traversed by the normal tree and
/// sentinel invariants must likewise designate a readable aligned node. This
/// matches the original's absence of NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_increment(cursor: *mut u32) -> u32 {
    let original = cursor.read();
    let mut current = node_from_word(original);
    let mut next = (*current).right;

    if next != 0 {
        cursor.write(next);
        current = node_from_word(next);
        next = (*current).left;
        while next != 0 {
            cursor.write(next);
            current = node_from_word(next);
            next = (*current).left;
        }
    } else {
        cursor.write(original);
        next = (*current).parent;
        loop {
            current = node_from_word(next);
            if (*current).right != cursor.read() {
                break;
            }
            cursor.write(next);
            next = (*current).parent;
        }
        current = node_from_word(cursor.read());
        if (*current).right != next {
            cursor.write(next);
        }
    }

    original
}
///
/// `FUN_083b5b04` at load address `0x083b5b04` is a byte-identical,
/// 84-byte (21-word) copy of `red_black_tree_advance_cursor`, ending with
/// `bx lr` at `0x083b5b54`; the next separately linked function begins at
/// `0x083b5b58`. Complete aligned A32 B/BL-immediate decoding finds exactly
/// two direct inbound plain unconditional `bl` instructions at 0x083bcb1c and
/// 0x083bcfec, zero predicated BL instructions, and no outbound calls. It
/// advances the target-width cursor to the red-black-tree in-order successor:
/// descend through the right subtree's left spine, or climb parent links while
/// leaving right-child edges, retaining the header sentinel. This exact
/// duplicate deliberately reuses the established dispatch seam; target links
/// remain `u32` words to preserve the retail four-byte layout on hosts.
/// Deliberate deviations: none.
///

/// `FUN_083b5bb0` at load address `0x083b5bb0` is a byte-identical 84-byte
/// (21-word) copy ending with `bx lr` at `0x083b5c00`; the next independently
/// entered function begins at `0x083b5c04`. Raw A32 decoding finds two inbound
/// unconditional plain `bl` calls at 0x083c1814 and 0x083c1ce4, zero
/// predicated BL calls, and no outbound calls. It advances the target-width
/// cursor to its in-order successor by descending the right subtree's left
/// spine or climbing parent links while leaving right-child edges, retaining
/// the header sentinel. This exact duplicate deliberately reuses the exported
/// `red_black_tree_advance_cursor` implementation and shared host tests;
/// deliberate deviations: none.
///
/// Advances an in-order red-black-tree cursor and returns the cursor address.
/// Original: `FUN_083b609c` @ `0x083b609c` (84 bytes; 5 direct,
/// unconditional `bl` callers).
///
/// Raw `osos.dec` establishes the 84-byte extent `0x083b609c..0x083b60ec`;
/// the separately linked sibling starts at `0x083b60f0`. Exhaustive decoding
/// of aligned ARM B/BL-immediate words finds five inbound calls, all
/// unconditional `bl` instructions at 0x081f04a4, 0x081f11a4, 0x081f11bc,
/// 0x083ccdd0, and 0x083cd2a4; there are no predicated calls or direct
/// tail branches. Deliberate deviations: none.
///
/// `FUN_083b5da8` at load address `0x083b5da8` is a byte-identical 84-byte
/// (21-word) copy ending in `bx lr` at `0x083b5df8`; the next independently
/// entered function begins at `0x083b5dfc`. Raw aligned A32 B/BL-immediate
/// decoding verifies two inbound unconditional plain `bl` calls at
/// 0x083c65c0 and 0x083c6a94, zero predicated `bl` calls, and no outbound
/// calls. It advances the target-width cursor to its in-order successor by
/// descending the right subtree's left spine, or climbing parent links while
/// leaving right-child edges, retaining the header sentinel. The exact duplicate
/// deliberately reuses this dispatch seam and shared host tests; deliberate
/// deviations: none.
///
/// `FUN_083b61ec` at load address `0x083b61ec` is a byte-identical,
/// 84-byte (21-word) copy of `red_black_tree_advance_cursor`, ending with
/// `bx lr` at `0x083b623c`; the next separately linked function begins at
/// `0x083b6240`. Raw A32 decoding confirms its two inbound calls are plain,
/// unconditional `bl` instructions at 0x083cedb0 and 0x083cf280, with zero
/// predicated `bl` calls; the body itself makes no calls. It advances an
/// in-order cursor by descending the right subtree's left spine or climbing
/// parent links from right-child edges, retaining the header sentinel. The
/// byte-identical body deliberately reuses this dispatch seam and its shared
/// host tests; deliberate deviations: none.
///
/// `FUN_083b60f0` at load address `0x083b60f0` is a fourth byte-identical,
/// 84-byte (21-word) copy of `red_black_tree_advance_cursor`, through `bx lr`
/// at `0x083b6140`; the next separately linked sibling starts at `0x083b6144`.
/// Complete aligned ARM B/BL decoding finds its three inbound calls are plain
/// `bl` at 0x083cd828, 0x083cdcfc, and 0x083cdddc, with zero predicated `bl`
/// calls and no outbound calls. It deliberately reuses this symbol and its
/// host tests because target code and ABI are identical; no behavior changes.
///
/// `FUN_083b6144` at load address `0x083b6144` is a byte-identical,
/// 84-byte (21-word) copy of `red_black_tree_advance_cursor`, ending with
/// `bx lr` at `0x083b6194`; the next separately linked function begins at
/// `0x083b6198`. Raw A32 decoding confirms its two inbound calls are plain,
/// unconditional `bl` instructions at 0x083ce36c and 0x083ce83c, with zero
/// predicated `bl` calls; the body itself makes no calls. It advances an
/// in-order cursor by descending the right subtree's left spine or climbing
/// parent links from right-child edges, retaining the header sentinel. The
/// byte-identical body deliberately reuses this dispatch seam and its shared
/// host tests; deliberate deviations: none.
///
/// `FUN_083b590c` at load address `0x083b590c` is a byte-identical, 84-byte
/// (21-word) copy of `red_black_tree_advance_cursor`, through `bx lr` at
/// `0x083b595c`; the next separately linked function begins at `0x083b5960`.
/// Complete aligned ARM B/BL decoding finds three inbound calls, all plain
/// `bl` at 0x083b7550, 0x083b79b4, and 0x083b7a94; there are no predicated
/// BL calls or outbound calls. It deliberately reuses this dispatch seam and
/// shared host tests because its target code and ABI are identical; no
/// behavior deviations.
///
/// `FUN_083b5960` at load address `0x083b5960` is a byte-identical, 84-byte
/// (21-word) copy of `red_black_tree_advance_cursor`, ending with `bx lr` at
/// `0x083b59b0`; the next separately linked function begins at `0x083b59b4`.
/// Complete aligned ARM B/BL decoding finds three inbound plain `bl` calls at
/// 0x083b8174, 0x083b8644, and 0x083daff0, with no predicated BL calls and no
/// outbound calls. It advances an in-order cursor to its successor by taking
/// the right subtree's leftmost node or climbing parent links from right-child
/// edges, retaining the header sentinel. The byte-identical body deliberately
/// reuses this dispatch seam and its host tests; deliberate deviations: none.
///
/// A right child selects that subtree's leftmost node. Otherwise the walk
/// climbs parent links while leaving right-child edges, then selects the first
/// ancestor reached from a left-child edge. The final right-link comparison
/// retains the header sentinel.
///
/// # Safety
///
/// `cursor` must be writable and initially contain a valid non-NULL
/// [`RedBlackTreeNode`] address. Every traversed link must designate a readable
/// aligned node. This matches the retail function's absence of NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_advance_cursor")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_advance_cursor(cursor: *mut u32) -> *mut u32 {
    let mut current = node_from_word(cursor.read());
    let mut next = (*current).right;

    if next != 0 {
        loop {
            cursor.write(next);
            current = node_from_word(next);
            next = (*current).left;
            if next == 0 {
                return cursor;
            }
        }
    }

    next = (*current).parent;
    while (*node_from_word(next)).right == cursor.read() {
        cursor.write(next);
        next = (*node_from_word(next)).parent;
    }
    if (*node_from_word(cursor.read())).right != next {
        cursor.write(next);
    }
    cursor
}

/// Moves `cursor` to the previous node in red-black-tree in-order traversal.
/// Original: `FUN_083b59b4` @ `0x083b59b4` (84 bytes; 3 direct,
/// unconditional `bl` callers).
///
/// Raw `osos.dec` establishes the 84-byte extent `0x083b59b4..0x083b5a04`;
/// the next separately linked sibling begins at `0x083b5a08`. Complete aligned
/// ARM B/BL decoding finds three inbound calls, all plain `bl` at 0x08259b98,
/// 0x083b8c60, and 0x083b9130; there are no predicated BL calls. The body has
/// no outbound calls.
///
/// `FUN_083b570c` at load address `0x083b570c` is a byte-identical,
/// 84-byte (21-word) copy of `red_black_tree_advance_cursor`, ending with
/// `bx lr` at `0x083b575c`; the next separately linked function begins at
/// `0x083b5760`. Complete aligned ARM B/BL decoding verifies three direct
/// inbound calls, all plain `bl` at 0x083bf620, 0x083bfaec, and 0x083bfbe8;
/// there are no predicated BL calls or outbound calls. It moves an in-order
/// red-black-tree cursor to its successor by descending the right subtree's
/// left spine or climbing parent links from right-child edges, preserving the
/// header sentinel. Its raw body is byte-identical to this implementation, so
/// it deliberately reuses this dispatch seam and its host tests; deliberate
/// deviations: none.
///
/// A left child selects that subtree's rightmost node. Otherwise the walk
/// climbs parent links while leaving left-child edges, then selects the first
/// ancestor reached from a right-child edge. The final left-link comparison
/// retains the header sentinel. Deliberate deviations: none.
///
/// # Safety
///
/// `cursor` must be writable and initially contain a valid non-NULL
/// [`RedBlackTreeNode`] address. Every traversed link must designate a readable
/// aligned node. This matches the retail function's absence of NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_decrement_cursor(cursor: *mut u32) -> *mut u32 {
    let mut current = node_from_word(cursor.read());
    let mut previous = (*current).left;

    if previous != 0 {
        loop {
            cursor.write(previous);
            current = node_from_word(previous);
            previous = (*current).right;
            if previous == 0 {
                return cursor;
            }
        }
    }

    previous = (*current).parent;
    while (*node_from_word(previous)).left == cursor.read() {
        cursor.write(previous);
        previous = (*node_from_word(previous)).parent;
    }
    if (*node_from_word(cursor.read())).left != previous {
        cursor.write(previous);
    }
    cursor
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{red_black_tree_advance_cursor, red_black_tree_decrement_cursor, red_black_tree_increment, RedBlackTreeNode};
    use core::ptr;
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::RED_BLACK_TREE_INCREMENT, 0x1000)
            .map(|p| p as usize)
    });

    static ADVANCE_CURSOR_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_ADVANCE_CURSOR,
            0x1000,
        )
        .map(|p| p as usize)
    });

    static ADVANCE_CURSOR_083B5C04_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_ADVANCE_CURSOR_083B5C04,
            0x1000,
        )
        .map(|p| p as usize)
    });

    static ADVANCE_CURSOR_083B5BB0_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_ADVANCE_CURSOR_083B5BB0,
            0x1000,
        )
        .map(|p| p as usize)
    });

    static ADVANCE_CURSOR_083B5B04_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_ADVANCE_CURSOR_083B5B04,
            0x1000,
        )
        .map(|p| p as usize)
    });

    static DECREMENT_CURSOR_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_DECREMENT_CURSOR,
            0x1000,
        )
        .map(|p| p as usize)
    });

    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|p| p as *mut u8)
    }

    fn try_advance_cursor_slab() -> Option<*mut u8> {
        (*ADVANCE_CURSOR_SLAB).map(|p| p as *mut u8)
    }

    fn try_advance_cursor_083b5c04_slab() -> Option<*mut u8> {
        (*ADVANCE_CURSOR_083B5C04_SLAB).map(|p| p as *mut u8)
    }

    fn try_advance_cursor_083b5b04_slab() -> Option<*mut u8> {
        (*ADVANCE_CURSOR_083B5B04_SLAB).map(|p| p as *mut u8)
    }

    fn try_decrement_cursor_slab() -> Option<*mut u8> {
        (*DECREMENT_CURSOR_SLAB).map(|p| p as *mut u8)
    }

    fn try_advance_cursor_083b5bb0_slab() -> Option<*mut u8> {
        (*ADVANCE_CURSOR_083B5BB0_SLAB).map(|p| p as *mut u8)
    }

    unsafe fn node(base: *mut u8, index: usize) -> *mut RedBlackTreeNode {
        base.add(0x100 + index * core::mem::size_of::<RedBlackTreeNode>()).cast()
    }

    unsafe fn reset(base: *mut u8) {
        ptr::write_bytes(base, 0, 0x1000);
    }

    unsafe fn initialize(
        node: *mut RedBlackTreeNode,
        parent: *mut RedBlackTreeNode,
        left: *mut RedBlackTreeNode,
        right: *mut RedBlackTreeNode,
    ) {
        node.write(RedBlackTreeNode {
            color: 0x5a5a_5a5a,
            parent: parent as usize as u32,
            left: left as usize as u32,
            right: right as usize as u32,
        });
    }

    #[test]
    fn advances_through_right_subtrees_parent_edges_and_sentinel() {
        let Some(base) = try_slab() else {
            crate::testing::note_missing_u32_fixture("red_black_tree_increment");
            return;
        };

        unsafe {
            // Right-subtree case: select the leftmost node in the right subtree.
            reset(base);
            let current = node(base, 0);
            let right = node(base, 1);
            let leftmost = node(base, 2);
            initialize(current, ptr::null_mut(), ptr::null_mut(), right);
            initialize(right, current, leftmost, ptr::null_mut());
            initialize(leftmost, right, ptr::null_mut(), ptr::null_mut());
            let mut cursor = current as usize as u32;
            assert_eq!(red_black_tree_increment(&mut cursor), current as usize as u32);
            assert_eq!(cursor, leftmost as usize as u32);
            assert_eq!((*current).color, 0x5a5a_5a5a);

            // Left-child case: the first parent is the successor.
            reset(base);
            let current = node(base, 0);
            let parent = node(base, 1);
            let sibling = node(base, 2);
            initialize(parent, ptr::null_mut(), current, sibling);
            initialize(current, parent, ptr::null_mut(), ptr::null_mut());
            initialize(sibling, parent, ptr::null_mut(), ptr::null_mut());
            cursor = current as usize as u32;
            assert_eq!(red_black_tree_increment(&mut cursor), current as usize as u32);
            assert_eq!(cursor, parent as usize as u32);

            // Repeated right-child climbs stop at the header sentinel.
            reset(base);
            let header = node(base, 0);
            let root = node(base, 1);
            let ancestor = node(base, 2);
            let maximum = node(base, 3);
            initialize(header, root, ptr::null_mut(), maximum);
            initialize(root, header, ptr::null_mut(), ancestor);
            initialize(ancestor, root, ptr::null_mut(), maximum);
            initialize(maximum, ancestor, ptr::null_mut(), ptr::null_mut());
            cursor = maximum as usize as u32;
            assert_eq!(red_black_tree_increment(&mut cursor), maximum as usize as u32);
            assert_eq!(cursor, header as usize as u32);

            // The sentinel's right-link equality preserves it as the result.
            reset(base);
            let header = node(base, 0);
            let root = node(base, 1);
            initialize(header, root, ptr::null_mut(), root);
            initialize(root, header, ptr::null_mut(), ptr::null_mut());
            cursor = root as usize as u32;
            assert_eq!(red_black_tree_increment(&mut cursor), root as usize as u32);
            assert_eq!(cursor, header as usize as u32);
        }
    }
    #[test]
    fn advance_cursor_returns_its_address_after_all_successor_paths() {
        let Some(base) = try_advance_cursor_slab() else {
            crate::testing::note_missing_u32_fixture("red_black_tree_advance_cursor");
            return;
        };

        unsafe {
            // Right-subtree case: select the leftmost node in the right subtree.
            reset(base);
            let current = node(base, 0);
            let right = node(base, 1);
            let leftmost = node(base, 2);
            initialize(current, ptr::null_mut(), ptr::null_mut(), right);
            initialize(right, current, leftmost, ptr::null_mut());
            initialize(leftmost, right, ptr::null_mut(), ptr::null_mut());
            let mut cursor = current as usize as u32;
            let cursor_address = &mut cursor as *mut u32;
            assert_eq!(red_black_tree_advance_cursor(cursor_address), cursor_address);
            assert_eq!(cursor, leftmost as usize as u32);

            // The first ancestor reached from a left-child edge is selected.
            reset(base);
            let current = node(base, 0);
            let parent = node(base, 1);
            let sibling = node(base, 2);
            initialize(parent, ptr::null_mut(), current, sibling);
            initialize(current, parent, ptr::null_mut(), ptr::null_mut());
            initialize(sibling, parent, ptr::null_mut(), ptr::null_mut());
            cursor = current as usize as u32;
            let cursor_address = &mut cursor as *mut u32;
            assert_eq!(red_black_tree_advance_cursor(cursor_address), cursor_address);
            assert_eq!(cursor, parent as usize as u32);

            // Repeated right-child climbs end at the header sentinel.
            reset(base);
            let header = node(base, 0);
            let root = node(base, 1);
            let ancestor = node(base, 2);
            let maximum = node(base, 3);
            initialize(header, root, ptr::null_mut(), maximum);
            initialize(root, header, ptr::null_mut(), ancestor);
            initialize(ancestor, root, ptr::null_mut(), maximum);
            initialize(maximum, ancestor, ptr::null_mut(), ptr::null_mut());
            cursor = maximum as usize as u32;
            let cursor_address = &mut cursor as *mut u32;
            assert_eq!(red_black_tree_advance_cursor(cursor_address), cursor_address);
            assert_eq!(cursor, header as usize as u32);
        }
    }

    #[test]
    fn advance_cursor_083b5c04_selects_the_first_left_edge_ancestor() {
        let Some(base) = try_advance_cursor_083b5c04_slab() else {
            crate::testing::note_missing_u32_fixture("red_black_tree_advance_cursor_083b5c04");
            return;
        };

        unsafe {
            reset(base);
            let header = node(base, 0);
            let ancestor = node(base, 1);
            let current = node(base, 2);
            let sibling = node(base, 3);
            initialize(header, ptr::null_mut(), ancestor, ptr::null_mut());
            initialize(ancestor, header, current, sibling);
            initialize(current, ancestor, ptr::null_mut(), ptr::null_mut());
            initialize(sibling, ancestor, ptr::null_mut(), ptr::null_mut());
            let mut cursor = current as usize as u32;
            let cursor_address = &mut cursor as *mut u32;

            assert_eq!(red_black_tree_advance_cursor(cursor_address), cursor_address);
            assert_eq!(cursor, ancestor as usize as u32);
        }
    }

    #[test]
    fn advance_cursor_083b5bb0_preserves_the_header_successor() {
        let Some(base) = try_advance_cursor_083b5bb0_slab() else {
            crate::testing::note_missing_u32_fixture("red_black_tree_advance_cursor_083b5bb0");
            return;
        };

        unsafe {
            reset(base);
            let header = node(base, 0);
            let maximum = node(base, 1);
            initialize(header, maximum, ptr::null_mut(), maximum);
            initialize(maximum, header, ptr::null_mut(), ptr::null_mut());
            let mut cursor = maximum as usize as u32;
            let cursor_address = &mut cursor as *mut u32;

            assert_eq!(red_black_tree_advance_cursor(cursor_address), cursor_address);
            assert_eq!(cursor, header as usize as u32);
        }
    }

    #[test]
    fn advance_cursor_083b5b04_descends_the_right_subtree_left_spine() {
        let Some(base) = try_advance_cursor_083b5b04_slab() else {
            crate::testing::note_missing_u32_fixture("red_black_tree_advance_cursor_083b5b04");
            return;
        };

        unsafe {
            reset(base);
            let current = node(base, 0);
            let right = node(base, 1);
            let middle = node(base, 2);
            let leftmost = node(base, 3);
            initialize(current, ptr::null_mut(), ptr::null_mut(), right);
            initialize(right, current, middle, ptr::null_mut());
            initialize(middle, right, leftmost, ptr::null_mut());
            initialize(leftmost, middle, ptr::null_mut(), ptr::null_mut());
            let mut cursor = current as usize as u32;
            let cursor_address = &mut cursor as *mut u32;

            assert_eq!(red_black_tree_advance_cursor(cursor_address), cursor_address);
            assert_eq!(cursor, leftmost as usize as u32);
        }
    }

    #[test]
    fn decrement_cursor_returns_its_address_after_all_predecessor_paths() {
        let Some(base) = try_decrement_cursor_slab() else {
            crate::testing::note_missing_u32_fixture("red_black_tree_decrement_cursor");
            return;
        };

        unsafe {
            reset(base);
            let current = node(base, 0);
            let left = node(base, 1);
            let rightmost = node(base, 2);
            initialize(current, ptr::null_mut(), left, ptr::null_mut());
            initialize(left, current, ptr::null_mut(), rightmost);
            initialize(rightmost, left, ptr::null_mut(), ptr::null_mut());
            let mut cursor = current as usize as u32;
            let cursor_address = &mut cursor as *mut u32;
            assert_eq!(red_black_tree_decrement_cursor(cursor_address), cursor_address);
            assert_eq!(cursor, rightmost as usize as u32);

            reset(base);
            let current = node(base, 0);
            let parent = node(base, 1);
            let sibling = node(base, 2);
            initialize(parent, ptr::null_mut(), sibling, current);
            initialize(current, parent, ptr::null_mut(), ptr::null_mut());
            initialize(sibling, parent, ptr::null_mut(), ptr::null_mut());
            cursor = current as usize as u32;
            let cursor_address = &mut cursor as *mut u32;
            assert_eq!(red_black_tree_decrement_cursor(cursor_address), cursor_address);
            assert_eq!(cursor, parent as usize as u32);

            reset(base);
            let header = node(base, 0);
            let root = node(base, 1);
            let ancestor = node(base, 2);
            let minimum = node(base, 3);
            initialize(header, root, minimum, ptr::null_mut());
            initialize(root, header, ancestor, ptr::null_mut());
            initialize(ancestor, root, minimum, ptr::null_mut());
            initialize(minimum, ancestor, ptr::null_mut(), ptr::null_mut());
            cursor = minimum as usize as u32;
            let cursor_address = &mut cursor as *mut u32;
            assert_eq!(red_black_tree_decrement_cursor(cursor_address), cursor_address);
            assert_eq!(cursor, header as usize as u32);
        }
    }
}
