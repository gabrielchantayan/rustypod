//! The 'plst' UI element's successor selector.
//!
//! - `ui_plst_next` — original: `FUN_08053bd0` @ 0x08053bd0
//!   (80 bytes; 14 direct `bl` call sites, 0 predicated, verified by
//!   decoding every B/BL word in `osos.dec`).

use crate::ui::plst_class_check::ui_element_is_plst_class;

/// Byte offset of the explicit successor word, consulted first
/// (`ldr r0,[r4,#0x24]`). Returned verbatim when nonzero.
const SUCCESSOR_OFFSET: usize = 0x24;

/// Byte offset of the linked-successor word, the fallback when the
/// explicit successor is zero (`ldreq r0,[r4,#0x14]`). Every auxiliary
/// chain node carries its own candidate element word at this same
/// offset (`ldr r0,[r1,#0x14]`).
const LINKED_OFFSET: usize = 0x14;

/// Byte offset of the auxiliary chain-node pointer, walked only when
/// both direct successor words are zero (`ldr r1,[r4,#0x10]`). Each
/// chain node links onward through the same offset
/// (`ldr r1,[r1,#0x10]`).
const CHAIN_NODE_OFFSET: usize = 0x10;

/// ui_plst_next — original: `FUN_08053bd0` @ 0x08053bd0 (80 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x08053bd0..0x08053c20`; the sibling function's `push {r4-r8,lr}`
/// prologue at 0x08053c20 confirms Ghidra's 80-byte extent exactly:
///
/// ```text
/// 08053bd0  push {r4, lr}
/// 08053bd4  mov r4, r0
/// 08053bd8  bl 0x080613e0        ; ui_element_is_plst_class
/// 08053bdc  cmp r0, #0
/// 08053be0  popeq {r4, pc}
/// 08053be4  ldr r0, [r4, #0x24]
/// 08053be8  cmp r0, #0
/// 08053bec  ldreq r0, [r4, #0x14]
/// 08053bf0  cmpeq r0, #0
/// 08053bf4  popne {r4, pc}
/// 08053bf8  ldr r1, [r4, #0x10]
/// 08053bfc  cmp r1, #0
/// 08053c00  popeq {r4, pc}
/// 08053c04  ldr r0, [r1, #0x14]  ; <- loop
/// 08053c08  cmp r0, #0
/// 08053c0c  popne {r4, pc}
/// 08053c10  ldr r1, [r1, #0x10]
/// 08053c14  cmp r1, #0
/// 08053c18  bne 0x08053c04
/// 08053c1c  pop {r4, pc}
/// ```
///
/// Algorithm: the successor selector for the linked 'plst' sequence
/// that hangs off a 'tdat' UI element (the first link is
/// `ui_tdat_first_plst` @ 0x080522d4, the word at element+0x34).
/// Validates `element` as a 'plst'-class object, then picks its
/// successor in strict order: the explicit successor word at +0x24,
/// else the linked-successor word at +0x14, else the first nonzero
/// +0x14 word found by walking the auxiliary chain of link nodes that
/// starts at +0x10 (each node: candidate element at +0x14, next node
/// at +0x10). Every selected word is returned verbatim — callers treat
/// it as the next 'plst' element pointer. Returns 0 when the class
/// check fails or no successor exists. This is the iteration step of
/// the sequence walk in callers 0x08050ae0, 0x08066854, 0x08054724 and
/// 0x080561b4 (`for (p = first; p != 0; p = FUN_08053bd0(p))`), and of
/// the teardown in 0x0806a994 which saves the successor before
/// destroying each element.
///
/// Call count verified by decoding every B/BL word in osos.dec: 14
/// unconditional `bl` sites (0x08050b24, 0x08054750, 0x080561e0,
/// 0x0806126c, 0x08066890, 0x08066b2c, 0x080689e8, 0x0806a9d0,
/// 0x0806aa28, 0x0806c1e4, 0x0806c2fc, 0x0806c348, 0x080ca77c,
/// 0x080ce5f4), zero predicated forms — the internal class guard is
/// what every caller relies on. No data word in osos references
/// 0x08053bd0, so it is never dispatched virtually.
///
/// Ghidra defects: the decompiled C declares a `void` return and drops
/// the result entirely — every caller depends on the r0 return value.
/// Its 80-byte extent is exact, however.
///
/// Deviations: none structural. The port calls the already-ported
/// `ui_element_is_plst_class` directly instead of branching to stock
/// 0x080613e0; all field reads are aligned word loads exactly like the
/// original's `ldr`s, and the return value is the raw selected word
/// (or 0) in every path, matching the original's r0.
///
/// # Safety
///
/// `element` may be NULL (guarded by the class predicate, like the
/// original). A non-NULL 'plst'-tagged element must be readable
/// through +0x27, and every auxiliary chain node reachable from +0x10
/// must be readable through +0x17.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_plst_next(element: *const u8) -> u32 {
    if ui_element_is_plst_class(element) == 0 {
        return 0;
    }
    let successor = element.add(SUCCESSOR_OFFSET).cast::<u32>().read();
    if successor != 0 {
        return successor;
    }
    let linked = element.add(LINKED_OFFSET).cast::<u32>().read();
    if linked != 0 {
        return linked;
    }
    let mut node = element.add(CHAIN_NODE_OFFSET).cast::<u32>().read();
    while node != 0 {
        let node_ptr = node as *const u8;
        let linked = node_ptr.add(LINKED_OFFSET).cast::<u32>().read();
        if linked != 0 {
            return linked;
        }
        node = node_ptr.add(CHAIN_NODE_OFFSET).cast::<u32>().read();
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing;

    // Slab layout: the 'plst' element @ +0x0000 (0x28 bytes used),
    // auxiliary chain nodes from +0x1000 in 0x100 strides.
    const ELEMENT_OFF: usize = 0x0000;
    const CHAIN_REGION: usize = 0x1000;
    const CHAIN_STRIDE: usize = 0x100;
    const SLAB_BYTES: usize = 0x4000;

    const PLST_TAG: u32 = 0x706c7374;

    unsafe fn map_slab() -> *mut u8 {
        match testing::try_map_u32_slab(testing::hints::PLST_NEXT, SLAB_BYTES) {
            Some(p) => p,
            None => core::ptr::null_mut(),
        }
    }

    unsafe fn write_word(addr: *mut u8, value: u32) {
        addr.cast::<u32>().write(value);
    }

    /// Zeroes the slab, stamps the 'plst' class tag at element+0x4 and
    /// returns the element pointer.
    unsafe fn make_element(base: *mut u8) -> *mut u8 {
        core::ptr::write_bytes(base, 0, SLAB_BYTES);
        let element = base.add(ELEMENT_OFF);
        write_word(element.add(0x4), PLST_TAG);
        element
    }

    unsafe fn chain_node(base: *mut u8, n: usize) -> *mut u8 {
        base.add(CHAIN_REGION + n * CHAIN_STRIDE)
    }

    #[test]
    fn null_element_returns_zero() {
        assert_eq!(unsafe { ui_plst_next(core::ptr::null()) }, 0);
    }

    #[test]
    fn non_plst_class_returns_zero_even_with_links() {
        let base = unsafe { map_slab() };
        if base.is_null() && testing::note_missing_u32_fixture("ui/plst_next") {
            return;
        }
        unsafe {
            let element = make_element(base);
            write_word(element.add(0x4), 0x74646174); // the 'tdat' tag
            write_word(element.add(SUCCESSOR_OFFSET), 0x0bad_c0de);
            write_word(element.add(LINKED_OFFSET), 0x0bad_f00d);
            assert_eq!(ui_plst_next(element.cast_const()), 0);
        }
    }

    #[test]
    fn explicit_successor_is_returned_first() {
        let base = unsafe { map_slab() };
        if base.is_null() && testing::note_missing_u32_fixture("ui/plst_next") {
            return;
        }
        unsafe {
            let element = make_element(base);
            // All three sources populated: +0x24 must win.
            write_word(element.add(SUCCESSOR_OFFSET), 0x0805_1111);
            write_word(element.add(LINKED_OFFSET), 0x0805_2222);
            write_word(element.add(CHAIN_NODE_OFFSET), chain_node(base, 0) as u32);
            write_word(chain_node(base, 0).add(LINKED_OFFSET), 0x0805_3333);
            assert_eq!(ui_plst_next(element.cast_const()), 0x0805_1111);
        }
    }

    #[test]
    fn linked_successor_when_no_explicit_successor() {
        let base = unsafe { map_slab() };
        if base.is_null() && testing::note_missing_u32_fixture("ui/plst_next") {
            return;
        }
        unsafe {
            let element = make_element(base);
            write_word(element.add(LINKED_OFFSET), 0x0805_2222);
            write_word(element.add(CHAIN_NODE_OFFSET), chain_node(base, 0) as u32);
            write_word(chain_node(base, 0).add(LINKED_OFFSET), 0x0805_3333);
            assert_eq!(ui_plst_next(element.cast_const()), 0x0805_2222);
        }
    }

    #[test]
    fn no_successor_anywhere_returns_zero() {
        let base = unsafe { map_slab() };
        if base.is_null() && testing::note_missing_u32_fixture("ui/plst_next") {
            return;
        }
        unsafe {
            let element = make_element(base);
            assert_eq!(ui_plst_next(element.cast_const()), 0);
        }
    }

    #[test]
    fn first_chain_node_candidate_is_returned() {
        let base = unsafe { map_slab() };
        if base.is_null() && testing::note_missing_u32_fixture("ui/plst_next") {
            return;
        }
        unsafe {
            let element = make_element(base);
            let node0 = chain_node(base, 0);
            write_word(element.add(CHAIN_NODE_OFFSET), node0 as u32);
            write_word(node0.add(LINKED_OFFSET), 0x0805_4444);
            assert_eq!(ui_plst_next(element.cast_const()), 0x0805_4444);
        }
    }

    #[test]
    fn walk_skips_chain_nodes_with_empty_candidate() {
        let base = unsafe { map_slab() };
        if base.is_null() && testing::note_missing_u32_fixture("ui/plst_next") {
            return;
        }
        unsafe {
            let element = make_element(base);
            let node0 = chain_node(base, 0);
            let node1 = chain_node(base, 1);
            write_word(element.add(CHAIN_NODE_OFFSET), node0 as u32);
            // node0: empty candidate, links to node1.
            write_word(node0.add(CHAIN_NODE_OFFSET), node1 as u32);
            // node1: candidate set, no onward link.
            write_word(node1.add(LINKED_OFFSET), 0x0805_5555);
            assert_eq!(ui_plst_next(element.cast_const()), 0x0805_5555);
        }
    }

    #[test]
    fn exhausted_chain_returns_zero() {
        let base = unsafe { map_slab() };
        if base.is_null() && testing::note_missing_u32_fixture("ui/plst_next") {
            return;
        }
        unsafe {
            let element = make_element(base);
            let node0 = chain_node(base, 0);
            let node1 = chain_node(base, 1);
            write_word(element.add(CHAIN_NODE_OFFSET), node0 as u32);
            write_word(node0.add(CHAIN_NODE_OFFSET), node1 as u32);
            // Both candidates empty; node1 has no onward link.
            assert_eq!(ui_plst_next(element.cast_const()), 0);
        }
    }

    #[test]
    fn successor_word_is_returned_verbatim() {
        let base = unsafe { map_slab() };
        if base.is_null() && testing::note_missing_u32_fixture("ui/plst_next") {
            return;
        }
        unsafe {
            let element = make_element(base);
            for value in [1u32, 0x2200_aed8, 0xdead_beef, u32::MAX] {
                write_word(element.add(SUCCESSOR_OFFSET), value);
                assert_eq!(ui_plst_next(element.cast_const()), value);
            }
        }
    }
}
