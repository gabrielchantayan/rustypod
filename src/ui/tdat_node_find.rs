//! The 'tdat' UI element's node-list lookup by 64-bit identifier.
//!
//! - `ui_tdat_find_node_by_id` — original: `FUN_08050d10` @ 0x08050d10
//!   (116 bytes; 5 direct `bl` call sites, 0 predicated, verified by
//!   decoding every B/BL word in `osos.dec`).
//! - `ui_tdat_find_node_by_alt_id` — original: `FUN_08050c9c` @ 0x08050c9c
//!   (116 bytes; 5 direct `bl` call sites, 0 predicated, verified by
//!   decoding every B/BL word in `osos.dec`).

use crate::ui::tdat_class_check::ui_element_is_tdat_class;
use crate::ui::tdat_node_list_head::tdat_node_list_head;

/// Byte offset of the compared identifier low word on each list node
/// (`ldr r0, [r4, #0x110]`).
const ID_LO_OFFSET: usize = 0x110;

/// Byte offset of the compared identifier high word on each list node
/// (`ldr r1, [r4, #0x114]`).
const ID_HI_OFFSET: usize = 0x114;

/// Byte offset of the compared alternate-identifier low word on each list
/// node (`ldr r0, [r4, #0x118]`).
const ALT_ID_LO_OFFSET: usize = 0x118;

/// Byte offset of the compared alternate-identifier high word on each list
/// node (`ldr r1, [r4, #0x11c]`).
const ALT_ID_HI_OFFSET: usize = 0x11c;

/// Node prefix: owner pointer at target +0, successor word at target +4.
/// Host builds widen only the owner pointer.
#[repr(C)]
pub struct TdatNodeLink {
    pub owner_element: *const u8,
    pub next: u32,
}

/// `tdat_node_next` — `FUN_08053d54` at 0x08053d54, exactly 24 bytes.
///
/// Raw words: e1a02000 e52de004 eb005dab e1b00000 15920004 e49df004.
/// The next real function starts at 0x08053d6c with `push {r4,r5,r6,lr}`.
/// Two plain BL callers (0x08050cfc, 0x08050d70), zero predicated BL
/// callers; the body has one plain BL to 0x0806b410 and no predicated BL.
/// Validate the node's owner using `scoped_context_owner_validity`, then
/// return its successor word, or zero on rejection without reading the link.
/// Deliberate deviations: call the existing Rust predicate; use a C-layout
/// prefix so the owner pointer and successor remain distinct on 64-bit hosts.
///
/// # Safety
/// `node` may be NULL. Otherwise its owner pointer must be readable and
/// satisfy the owner predicate's contract. Accepted nodes must also have
/// a readable, aligned successor word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tdat_node_next(node: *const u8) -> u32 {
    if crate::app::scoped_context::scoped_context_owner_validity(node.cast()) == 0 {
        return 0;
    }
    (*node.cast::<TdatNodeLink>()).next
}

/// ui_tdat_find_node_by_id — original: `FUN_08050d10` @ 0x08050d10 (116 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x08050d10..0x08050d84`; the next function's `push {r4, r5, r6, lr}`
/// prologue at `0x08050d84` confirms Ghidra's 116-byte extent exactly:
///
/// ```text
/// 08050d10  push {r4, r5, r6, lr}
/// 08050d14  mov r6, r3            ; id_hi
/// 08050d18  mov r5, r2            ; id_lo
/// 08050d1c  mov r4, r0            ; element
/// 08050d20  bl 0x0806aa3c         ; ui_element_is_tdat_class
/// 08050d24  cmp r0, #0
/// 08050d28  beq 0x08050d40        ; -> return 0
/// 08050d2c  cmp r6, #0
/// 08050d30  mov r2, #0
/// 08050d34  mov r0, r5
/// 08050d38  cmpeq r0, r2
/// 08050d3c  bne 0x08050d48        ; id != 0 -> search
/// 08050d40  mov r0, #0
/// 08050d44  pop {r4, r5, r6, pc}
/// 08050d48  mov r0, r4
/// 08050d4c  bl 0x080522fc         ; node = list_head(element)
/// 08050d50  b 0x08050d74
/// 08050d54  ldr r1, [r4, #0x114]  ; <- loop
/// 08050d58  ldr r0, [r4, #0x110]
/// 08050d5c  cmp r1, r6
/// 08050d60  mov r2, r5
/// 08050d64  cmpeq r0, r2
/// 08050d68  beq 0x08050d7c        ; match -> return node
/// 08050d6c  mov r0, r4
/// 08050d70  bl 0x08053d54         ; node = next(node)
/// 08050d74  movs r4, r0
/// 08050d78  bne 0x08050d54
/// 08050d7c  mov r0, r4
/// 08050d80  pop {r4, r5, r6, pc}
/// ```
///
/// Algorithm: validate `element` as a 'tdat' UI element and reject the
/// all-zero identifier, then walk the node list whose head is the word at
/// element+0x28 (via [`tdat_node_list_head`]) and whose successor
/// step is the validity-gated word at node+0x4 via [`tdat_node_next`].
/// Return the first node whose 64-bit identifier word pair
/// at node+0x110/+0x114 equals `(id_lo, id_hi)` — the high word is
/// compared first, the low word only on a high-word match. Return zero
/// when the class check fails, the identifier is zero, or the list
/// exhausts. Callers pass a split 64-bit identifier: 0x080ab120 passes
/// `(int)id, (int)(id >> 32)` of a local u64, and 0x0816ec28/0x082a5f7c
/// pass `*p, p[1]` word pairs.
///
/// Call count verified by decoding every B/BL word in osos.dec: 5
/// unconditional `bl` sites (0x08051344, 0x08094c9c, 0x080ab39c,
/// 0x0813e44c, 0x082a5fd4), zero predicated forms. The function itself
/// contains 3 unconditional `bl` instructions and zero predicated ones.
///
/// Deliberate deviations: head, successor and class checks call the existing
/// Rust ports directly. Aligned word loads and return-zero semantics are unchanged.
///
/// # Safety
///
/// `element` may be NULL. A non-NULL pointer must be readable through +0x7
/// for the class predicate, and accepted elements through +0x2b for the head;
/// list nodes must be readable through +0x117, matching the original's `ldr` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_tdat_find_node_by_id")]
#[inline(never)]
pub unsafe extern "C" fn ui_tdat_find_node_by_id(
    element: *const u8,
    id_lo: u32,
    id_hi: u32,
) -> u32 {
    if ui_element_is_tdat_class(element) == 0 {
        return 0;
    }
    if id_hi == 0 && id_lo == 0 {
        return 0;
    }

    let mut node = tdat_node_list_head(element);
    while node != 0 {
        let words = node as usize as *const u8;
        if words.add(ID_HI_OFFSET).cast::<u32>().read() == id_hi
            && words.add(ID_LO_OFFSET).cast::<u32>().read() == id_lo
        {
            return node;
        }
        node = tdat_node_next(words);
    }
    0
}

/// ui_tdat_find_node_by_alt_id — original: `FUN_08050c9c` @ 0x08050c9c (116 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x08050c9c..0x08050d10`; the sibling lookup's `push {r4, r5, r6, lr}`
/// prologue at `0x08050d10` confirms Ghidra's 116-byte extent exactly:
///
/// ```text
/// 08050c9c  push {r4, r5, r6, lr}
/// 08050ca0  mov r6, r3            ; id_hi
/// 08050ca4  mov r5, r2            ; id_lo
/// 08050ca8  mov r4, r0            ; element
/// 08050cac  bl 0x0806aa3c         ; ui_element_is_tdat_class
/// 08050cb0  cmp r0, #0
/// 08050cb4  beq 0x08050ccc        ; -> return 0
/// 08050cb8  cmp r6, #0
/// 08050cbc  mov r2, #0
/// 08050cc0  mov r0, r5
/// 08050cc4  cmpeq r0, r2
/// 08050cc8  bne 0x08050cd4        ; id != 0 -> search
/// 08050ccc  mov r0, #0
/// 08050cd0  pop {r4, r5, r6, pc}
/// 08050cd4  mov r0, r4
/// 08050cd8  bl 0x080522fc         ; node = list_head(element)
/// 08050cdc  b 0x08050d00
/// 08050ce0  ldr r1, [r4, #0x11c]  ; <- loop
/// 08050ce4  ldr r0, [r4, #0x118]
/// 08050ce8  cmp r1, r6
/// 08050cec  mov r2, r5
/// 08050cf0  cmpeq r0, r2
/// 08050cf4  beq 0x08050d08        ; match -> return node
/// 08050cf8  mov r0, r4
/// 08050cfc  bl 0x08053d54         ; node = next(node)
/// 08050d00  movs r4, r0
/// 08050d04  bne 0x08050ce0
/// 08050d08  mov r0, r4
/// 08050d0c  pop {r4, r5, r6, pc}
/// ```
///
/// Algorithm: identical control flow to `ui_tdat_find_node_by_id`, but the
/// compared identifier word pair lives at node+0x118/+0x11c (alternate
/// key) instead of node+0x110/+0x114 (primary key). Validate `element` as
/// a 'tdat' UI element and reject the all-zero identifier, then walk the
/// node list whose head is the word at element+0x28 (via
/// [`tdat_node_list_head`]) and whose successor step is the validity-gated
/// word at node+0x4 via [`tdat_node_next`]. Return the
/// first node whose alternate 64-bit identifier equals `(id_lo, id_hi)` —
/// the high word is compared first, the low word only on a high-word
/// match. Return zero when the class check fails, the identifier is zero,
/// or the list exhausts. Caller `0x0816ed0c` finds a node by this
/// alternate key and then reads the primary id pair at node+0x110/+0x114
/// out of the result, confirming the two keys are distinct fields.
///
/// Call count verified by decoding every B/BL word in osos.dec: 5
/// unconditional `bl` call sites (0x081598cc, 0x0815991c, 0x08159a58,
/// 0x0816edb4, 0x0816eed4), zero predicated forms. The function itself
/// contains 3 unconditional `bl` instructions and zero predicated ones
/// (Ghidra's "5 bl call sites" counts the callers).
///
/// Deliberate deviations: head, successor and class checks call Rust ports
/// directly. Aligned identifier loads and return-zero semantics are unchanged.
///
/// # Safety
///
/// `element` may be NULL. A non-NULL pointer must be readable through +0x7
/// for the class predicate, and accepted elements through +0x2b for the head;
/// list nodes must be readable through +0x11f, matching the original's `ldr` pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_tdat_find_node_by_alt_id")]
#[inline(never)]
pub unsafe extern "C" fn ui_tdat_find_node_by_alt_id(
    element: *const u8,
    id_lo: u32,
    id_hi: u32,
) -> u32 {
    if ui_element_is_tdat_class(element) == 0 {
        return 0;
    }
    if id_hi == 0 && id_lo == 0 {
        return 0;
    }

    let mut node = tdat_node_list_head(element);
    while node != 0 {
        let words = node as usize as *const u8;
        if words.add(ALT_ID_HI_OFFSET).cast::<u32>().read() == id_hi
            && words.add(ALT_ID_LO_OFFSET).cast::<u32>().read() == id_lo
        {
            return node;
        }
        node = tdat_node_next(words);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const TDAT_CLASS_TAG: u32 = 0x7464_6174;
    const FIXTURE_BYTES: usize = 0x2000;
    /// Three fixture nodes, each 0x120 bytes so +0x114 reads stay in bounds.
    const NODE_STRIDE: usize = 0x120;

    struct Fixture {
        base: *mut u8,
    }

    impl Fixture {
        fn map() -> Option<usize> {
            try_map_u32_slab(hints::TDAT_NODE_FIND, FIXTURE_BYTES).map(|p| p as usize)
        }

        /// Build a tdat element plus up to three nodes with the given
        /// identifiers, linked head-first in array order.
        fn new(ids: &[(u32, u32)]) -> Option<Fixture> {
            let base = Self::map()? as *mut u8;
            unsafe {
                ptr::write_bytes(base, 0, FIXTURE_BYTES);
                // element at +0x400: 'tdat' tag word at +0x4.
                let element = base.add(0x400);
                element.add(4).cast::<u32>().write(TDAT_CLASS_TAG);
                let node_base = base.add(0x800);
                for (i, &(lo, hi)) in ids.iter().enumerate() {
                    let node = node_base.add(i * NODE_STRIDE);
                    node.add(ID_LO_OFFSET).cast::<u32>().write(lo);
                    node.add(ID_HI_OFFSET).cast::<u32>().write(hi);
                    let next = if i + 1 < ids.len() {
                        node_base.add((i + 1) * NODE_STRIDE) as u32
                    } else {
                        0
                    };
                    node.cast::<TdatNodeLink>().write(TdatNodeLink {
                        owner_element: element,
                        next,
                    });
                }
                element.add(0x28).cast::<u32>().write(
                    if ids.is_empty() { 0 } else { node_base as u32 }
                );
                Some(Fixture { base })
            }
        }

        fn element(&self) -> *mut u8 {
            unsafe { self.base.add(0x400) }
        }

        fn node(&self, index: usize) -> u32 {
            unsafe { self.base.add(0x800 + index * NODE_STRIDE) as u32 }
        }

    }


    #[test]
    fn successor_checks_owner_and_preserves_all_link_bits() {
        let tdat = [0u32, TDAT_CLASS_TAG];
        let other = [0u32, 0x706c_7374];
        let mut node = TdatNodeLink { owner_element: ptr::null(), next: u32::MAX };
        unsafe {
            assert_eq!(tdat_node_next(ptr::null()), 0);
            assert_eq!(tdat_node_next((&node as *const TdatNodeLink).cast()), 0);
            node.owner_element = other.as_ptr().cast();
            assert_eq!(tdat_node_next((&node as *const TdatNodeLink).cast()), 0);
            node.owner_element = tdat.as_ptr().cast();
            for next in [0, 1, 0x0805_3d54, 0x8000_0000, u32::MAX] {
                node.next = next;
                assert_eq!(tdat_node_next((&node as *const TdatNodeLink).cast()), next);
            }
        }
    }

    #[test]
    fn null_element_returns_zero() {
        assert_eq!(unsafe { ui_tdat_find_node_by_id(ptr::null(), 1, 1) }, 0);
    }

    #[test]
    fn wrong_class_tag_returns_zero() {
        let Some(f) = Fixture::new(&[(7, 8)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find"));
            return;
        };
        unsafe { f.element().add(4).cast::<u32>().write(0x706c_7374) };
        assert_eq!(unsafe { ui_tdat_find_node_by_id(f.element(), 7, 8) }, 0);
    }

    #[test]
    fn zero_identifier_returns_zero_without_touching_list() {
        let Some(f) = Fixture::new(&[(0, 0)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find"));
            return;
        };
        assert_eq!(unsafe { ui_tdat_find_node_by_id(f.element(), 0, 0) }, 0);
    }

    #[test]
    fn empty_list_returns_zero() {
        let Some(f) = Fixture::new(&[]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find"));
            return;
        };
        assert_eq!(unsafe { ui_tdat_find_node_by_id(f.element(), 1, 0) }, 0);
    }

    #[test]
    fn first_node_match_returns_head() {
        let Some(f) = Fixture::new(&[(0x1122_3344, 0x5566_7788), (9, 9)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find"));
            return;
        };
        assert_eq!(
            unsafe { ui_tdat_find_node_by_id(f.element(), 0x1122_3344, 0x5566_7788) },
            f.node(0)
        );
    }

    #[test]
    fn later_node_match_walks_the_chain() {
        let Some(f) = Fixture::new(&[(1, 2), (3, 4), (0xdead_beef, 0xcafe_f00d)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find"));
            return;
        };
        assert_eq!(
            unsafe { ui_tdat_find_node_by_id(f.element(), 0xdead_beef, 0xcafe_f00d) },
            f.node(2)
        );
    }

    #[test]
    fn high_word_alone_is_not_a_match() {
        // Second node matches id_hi but not id_lo; lookup must skip it.
        let Some(f) = Fixture::new(&[(1, 1), (0xaaaa_aaaa, 5), (0xbbbb_bbbb, 5)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find"));
            return;
        };
        assert_eq!(
            unsafe { ui_tdat_find_node_by_id(f.element(), 0xbbbb_bbbb, 5) },
            f.node(2)
        );
    }

    #[test]
    fn absent_identifier_returns_zero() {
        let Some(f) = Fixture::new(&[(1, 2), (3, 4)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find"));
            return;
        };
        assert_eq!(unsafe { ui_tdat_find_node_by_id(f.element(), 9, 9) }, 0);
    }

    // --- ui_tdat_find_node_by_alt_id (node+0x118/+0x11c alternate key) ---

    impl Fixture {
        /// Build a tdat element plus up to three nodes whose *alternate*
        /// identifier pair (+0x118/+0x11c) takes the given values; the
        /// primary pair (+0x110/+0x114) stays zero.
        fn new_alt(ids: &[(u32, u32)]) -> Option<Fixture> {
            let base = try_map_u32_slab(hints::TDAT_NODE_FIND_ALT_ID, FIXTURE_BYTES)? as *mut u8;
            unsafe {
                ptr::write_bytes(base, 0, FIXTURE_BYTES);
                let element = base.add(0x400);
                element.add(4).cast::<u32>().write(TDAT_CLASS_TAG);
                let node_base = base.add(0x800);
                for (i, &(lo, hi)) in ids.iter().enumerate() {
                    let node = node_base.add(i * NODE_STRIDE);
                    node.add(ALT_ID_LO_OFFSET).cast::<u32>().write(lo);
                    node.add(ALT_ID_HI_OFFSET).cast::<u32>().write(hi);
                    let next = if i + 1 < ids.len() {
                        node_base.add((i + 1) * NODE_STRIDE) as u32
                    } else {
                        0
                    };
                    node.cast::<TdatNodeLink>().write(TdatNodeLink {
                        owner_element: element,
                        next,
                    });
                }
                element.add(0x28).cast::<u32>().write(
                    if ids.is_empty() { 0 } else { node_base as u32 }
                );
                Some(Fixture { base })
            }
        }
    }

    #[test]
    fn alt_null_element_returns_zero() {
        assert_eq!(unsafe { ui_tdat_find_node_by_alt_id(ptr::null(), 1, 1) }, 0);
    }

    #[test]
    fn alt_wrong_class_tag_returns_zero() {
        let Some(f) = Fixture::new_alt(&[(7, 8)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find alt"));
            return;
        };
        unsafe { f.element().add(4).cast::<u32>().write(0x706c_7374) };
        assert_eq!(unsafe { ui_tdat_find_node_by_alt_id(f.element(), 7, 8) }, 0);
    }

    #[test]
    fn alt_zero_identifier_returns_zero_without_touching_list() {
        let Some(f) = Fixture::new_alt(&[(0, 0)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find alt"));
            return;
        };
        assert_eq!(unsafe { ui_tdat_find_node_by_alt_id(f.element(), 0, 0) }, 0);
    }

    #[test]
    fn alt_empty_list_returns_zero() {
        let Some(f) = Fixture::new_alt(&[]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find alt"));
            return;
        };
        assert_eq!(unsafe { ui_tdat_find_node_by_alt_id(f.element(), 1, 0) }, 0);
    }

    #[test]
    fn alt_first_node_match_returns_head() {
        let Some(f) = Fixture::new_alt(&[(0x1122_3344, 0x5566_7788), (9, 9)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find alt"));
            return;
        };
        assert_eq!(
            unsafe { ui_tdat_find_node_by_alt_id(f.element(), 0x1122_3344, 0x5566_7788) },
            f.node(0)
        );
    }

    #[test]
    fn alt_later_node_match_walks_the_chain() {
        let Some(f) = Fixture::new_alt(&[(1, 2), (3, 4), (0xdead_beef, 0xcafe_f00d)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find alt"));
            return;
        };
        assert_eq!(
            unsafe { ui_tdat_find_node_by_alt_id(f.element(), 0xdead_beef, 0xcafe_f00d) },
            f.node(2)
        );
    }

    #[test]
    fn alt_high_word_alone_is_not_a_match() {
        // Second node matches id_hi but not id_lo; lookup must skip it.
        let Some(f) = Fixture::new_alt(&[(1, 1), (0xaaaa_aaaa, 5), (0xbbbb_bbbb, 5)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find alt"));
            return;
        };
        assert_eq!(
            unsafe { ui_tdat_find_node_by_alt_id(f.element(), 0xbbbb_bbbb, 5) },
            f.node(2)
        );
    }

    #[test]
    fn alt_absent_identifier_returns_zero() {
        let Some(f) = Fixture::new_alt(&[(1, 2), (3, 4)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find alt"));
            return;
        };
        assert_eq!(unsafe { ui_tdat_find_node_by_alt_id(f.element(), 9, 9) }, 0);
    }

    #[test]
    fn alt_key_is_distinct_from_primary_key() {
        // Node carries the wanted pair only in its primary id fields; the
        // alternate-key lookup must not match on them.
        let Some(f) = Fixture::new_alt(&[(0, 0)]) else {
            assert!(note_missing_u32_fixture("ui/tdat_node_find alt"));
            return;
        };
        unsafe {
            let node = f.node(0) as usize as *mut u8;
            node.add(ID_LO_OFFSET).cast::<u32>().write(0x1357_9bdf);
            node.add(ID_HI_OFFSET).cast::<u32>().write(0x2468_ace0);
        }
        assert_eq!(
            unsafe { ui_tdat_find_node_by_alt_id(f.element(), 0x1357_9bdf, 0x2468_ace0) },
            0
        );
    }
}
