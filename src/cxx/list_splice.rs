//! `std::list` node-range splice — the C++ runtime primitive behind
//! `list::splice(pos, other, first, last)`, ported from the checked-
//! iterator cluster @ 0x083d5d20..0x083d5e9f:
//!
//! - `list_splice` — original: `FUN_083d5d20` @ 0x083d5d20 (316 bytes;
//!   3 `bl` call sites @ 0x0818adb0, 0x0818ae34 and 0x0818b1a0, the
//!   last inside heap/block_mgr.rs's `take_blocks_body`). See the
//!   function's doc header for the algorithm.
//! - `iter_owner` — original: `FUN_083d5e5c` @ 0x083d5e5c (20 bytes):
//!   iterator's node's owning-list identity word, NULL in -> 0 out.
//!   Ported in place (private), the block_mgr.rs `iter_advance`
//!   rationale.
//! - `iter_equal` — original: `FUN_083d5e70` @ 0x083d5e70 (24 bytes):
//!   iterator pointee comparison, 1 on equal. Ported in place.
//! - `iter_advance` — original: `FUN_083d5e88` @ 0x083d5e88 (24 bytes),
//!   the same advance heap/block_mgr.rs ports in place for its own
//!   walks; duplicated privately here rather than exported.
//!
//! The list layout recovered from this cluster (the ADS C++ library's
//! checked `std::list`): the list object carries an identity word at
//! +0x0 (what every node of the list points back at), a head word at
//! +0x4 (never touched by the splice itself) and the node count at
//! +0x10; each node carries the owning-list identity at +0x0, next at
//! +0x4, prev at +0x8 and the element pointer at +0xc. Lists are
//! circular through a sentinel node — `end()` is the sentinel, never
//! NULL, and the re-link arithmetic below is the textbook circular
//! splice.
//!
//! `splice_blocks` is the crate adapter the heap/block_mgr.rs
//! `BLOCK_MANAGER_OPS.splice_blocks` slot ships as its wired default:
//! the real splice with the 0/1 verdict discarded, exactly like the
//! original body's caller (the `bl` @ 0x0818b1a0 ignores r0).

use crate::heap::veneers::heap_panic;

/// Byte offset of the owning-list identity word inside a node
/// (original: the `str r0, [r1, #0x0]` re-stamp in the adopt walk).
pub const NODE_OWNER_OFFSET: usize = 0x0;

/// Byte offset of the next pointer inside a node (original: `ldr r1,
/// [r1, #0x4]` inside the 0x083d5e88 advance).
pub const NODE_NEXT_OFFSET: usize = 0x4;

/// Byte offset of the prev pointer inside a node (original: `ldr r0,
/// [r0, #0x8]` for the range's last node).
pub const NODE_PREV_OFFSET: usize = 0x8;

/// Byte offset of the list object's own identity word (original: `ldr
/// r4, [r0, #0x0]` ahead of the first ownership compare).
pub const LIST_SELF_OFFSET: usize = 0x0;

/// Byte offset of the node-count word inside a list object (original:
/// `ldr r0, [r5, #0x10]` ahead of the dead validation, and the two
/// count fixups at the tail).
pub const LIST_COUNT_OFFSET: usize = 0x10;

/// Reads one u32 word of the opaque list/node layout (the objects are
/// unported-ctor layouts — literal byte offsets, `read_unaligned` for
/// the host, the heap/block_mgr.rs idiom).
#[inline(always)]
unsafe fn word(object: *mut u8, offset: usize) -> u32 {
    (object.add(offset) as *const u32).read_unaligned()
}

/// Reads one u32 target pointer of the opaque layout, zero-extended
/// (exact on the 32-bit target; host fixtures live below 4 GiB).
#[inline(always)]
unsafe fn ptr_word(object: *mut u8, offset: usize) -> *mut u8 {
    word(object, offset) as usize as *mut u8
}

/// Writes one u32 word of the opaque layout (target pointers truncate
/// to u32; host fixtures live below 4 GiB).
#[inline(always)]
unsafe fn set_word(object: *mut u8, offset: usize, value: u32) {
    (object.add(offset) as *mut u32).write_unaligned(value);
}

/// iter_owner — original: `FUN_083d5e5c` @ 0x083d5e5c (20 bytes),
/// ported in place.
///
/// The owning-list identity word of the node iterator `it` points at:
/// `**it`, NULL node in -> 0 out (`moveq r0, #0`).
#[inline(never)]
unsafe fn iter_owner(it: *mut *mut u8) -> *mut u8 {
    let node = *it;
    if node.is_null() {
        core::ptr::null_mut()
    } else {
        ptr_word(node, NODE_OWNER_OFFSET)
    }
}

/// iter_equal — original: `FUN_083d5e70` @ 0x083d5e70 (24 bytes),
/// ported in place.
///
/// 1 when both iterators point at the same node, 0 otherwise.
#[inline(never)]
unsafe fn iter_equal(a: *mut *mut u8, b: *mut *mut u8) -> i32 {
    if *a == *b {
        1
    } else {
        0
    }
}

/// iter_advance — original: `FUN_083d5e88` @ 0x083d5e88 (24 bytes),
/// ported in place (same as heap/block_mgr.rs's private copy).
///
/// Advances a single-word list iterator to the node's +0x4 next; a
/// NULL current node is fatal (`bleq 0x08030f44`, heap/veneers.rs's
/// `heap_panic`, non-returning).
#[inline(never)]
unsafe fn iter_advance(it: *mut *mut u8) {
    let node = *it;
    if node.is_null() {
        heap_panic();
    }
    *it = ptr_word(node, NODE_NEXT_OFFSET);
}

/// list_splice — original: `FUN_083d5d20` @ 0x083d5d20 (316 bytes; the
/// `bl` @ 0x0818b1a0 inside heap/block_mgr.rs's `take_blocks_body` and
/// two more @ 0x0818adb0 / 0x0818ae34, binary-scanned).
///
/// Moves the node range [first, last) out of `src_list` into
/// `dst_list` ahead of `pos` — `std::list::splice(pos, other, first,
/// last)` from the ADS checked-iterator C++ library. Algorithm:
///
/// 1. Ownership validation (the library's iterator-debug checks,
///   asserts compiled down to a refusal): the node `pos` points at
///   must carry `dst_list`'s identity word, and the nodes `first` and
///   `last` point at must carry `src_list`'s. Any mismatch (a NULL
///   node yields owner 0) returns 0 with nothing touched.
/// 2. Dead validation: when the source list's count word is nonzero
///   the original compares `first` against an iterator pointing at
///   the list object itself (`blne 0x083d5e70`) and discards the
///   verdict. Reproduced for fidelity; it has no observable effect.
/// 3. Adopt walk: from `first` until `last` (exclusive, the
///   0x083d5e70 comparison), re-stamp each node's +0x0 owner word
///   with `dst_list`'s identity, count the nodes, and advance
///   (0x083d5e88 — a NULL current node panics, unreachable in a valid
///   range).
/// 4. A NULL `last` node is fatal (`bleq 0x08030f44`, non-returning;
///   with a circular list `last` is at worst the sentinel).
/// 5. Re-link, `range_last = last->prev`: `first->prev->next = last`,
///   `last->prev = first->prev` (range out of the source), then
///   `first->prev = pos->prev`, `range_last->next = pos`,
///   `pos->prev->next = first`, `pos->prev = range_last` (range in
///   ahead of `pos`) — in exactly the original's order; `first->prev`
///   is read before it is overwritten and `pos->prev` before it is.
/// 6. `dst_list` count += moved, `src_list` count -= moved, return 1.
///
/// Deviation note: the original has NO empty-range guard — with
/// `first == last` the walk moves zero nodes but the re-link still
/// runs, which swaps the predecessor links between the two lists (the
/// quirk the `empty_range_keeps_counts_and_swaps_predecessors` test
/// pins down). Faithful, not a bug in the port. List pointer fields
/// are u32 target pointers zero-extended on read / truncated on write
/// (exact on target; host fixtures live below 4 GiB — the
/// heap/client_populate.rs idiom). The original re-loads `*dst_list`
/// on every adopt-walk iteration; the port does the same.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_splice(
    dst_list: *mut u8,
    dst_pos: *mut *mut u8,
    src_list: *mut u8,
    src_first: *mut *mut u8,
    src_last: *mut *mut u8,
) -> i32 {
    // 1. Ownership validation (each compare re-reads the list's
    // identity word, like the original's `ldr r4, [rN, #0x0]`).
    if iter_owner(dst_pos) != ptr_word(dst_list, LIST_SELF_OFFSET) {
        return 0;
    }
    if iter_owner(src_first) != ptr_word(src_list, LIST_SELF_OFFSET) {
        return 0;
    }
    if iter_owner(src_last) != ptr_word(src_list, LIST_SELF_OFFSET) {
        return 0;
    }
    // 2. Dead validation (verdict discarded in the original too).
    if word(src_list, LIST_COUNT_OFFSET) != 0 {
        let mut probe: *mut u8 = src_list;
        iter_equal(src_first, &mut probe);
    }
    // 3. Adopt walk: re-own and count [first, last).
    let mut cursor: *mut u8 = *src_first;
    let mut moved: u32 = 0;
    while iter_equal(src_last, &mut cursor) == 0 {
        let owner = ptr_word(dst_list, LIST_SELF_OFFSET);
        set_word(cursor, NODE_OWNER_OFFSET, owner as u32);
        moved += 1;
        iter_advance(&mut cursor);
    }
    // 4. A NULL `last` is fatal, exactly like the original's
    // `bleq 0x08030f44` (non-returning).
    if cursor.is_null() {
        heap_panic();
    }
    // 5. Re-link (in the original's store order).
    let range_last: *mut u8 = ptr_word(cursor, NODE_PREV_OFFSET);
    let first: *mut u8 = *src_first;
    let last: *mut u8 = *src_last;
    let pos: *mut u8 = *dst_pos;
    set_word(ptr_word(first, NODE_PREV_OFFSET), NODE_NEXT_OFFSET, last as u32);
    set_word(last, NODE_PREV_OFFSET, word(first, NODE_PREV_OFFSET));
    set_word(first, NODE_PREV_OFFSET, word(pos, NODE_PREV_OFFSET));
    set_word(range_last, NODE_NEXT_OFFSET, pos as u32);
    set_word(ptr_word(pos, NODE_PREV_OFFSET), NODE_NEXT_OFFSET, first as u32);
    set_word(pos, NODE_PREV_OFFSET, range_last as u32);
    // 6. Count fixups and the granted verdict.
    set_word(
        dst_list,
        LIST_COUNT_OFFSET,
        word(dst_list, LIST_COUNT_OFFSET) + moved,
    );
    set_word(
        src_list,
        LIST_COUNT_OFFSET,
        word(src_list, LIST_COUNT_OFFSET) - moved,
    );
    1
}

/// `BLOCK_MANAGER_OPS.splice_blocks` wired default (heap/block_mgr.rs):
/// the real [`list_splice`] with the 0/1 verdict discarded, exactly
/// like the original body's caller (the `bl` @ 0x0818b1a0 ignores r0).
/// Not a firmware function — a crate adapter, so no export.
pub unsafe extern "C" fn splice_blocks(
    dst_list: *mut u8,
    dst_pos: *mut *mut u8,
    src_list: *mut u8,
    src_first: *mut *mut u8,
    src_last: *mut *mut u8,
) {
    list_splice(dst_list, dst_pos, src_list, src_first, src_last);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the tests: they share one fixture slab (the
    /// block_mgr.rs MGR_LOCK precedent).
    static LIST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        LIST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The list/node words are u32 target pointers, so the fixtures
    /// must live below 4 GiB (the client_populate.rs slab lesson).
    /// One low mmap holds everything; distinct hint from the other
    /// modules' slabs.
    fn slab() -> *mut u8 {
        use std::sync::OnceLock;
        static SLAB: OnceLock<usize> = OnceLock::new();
        *SLAB.get_or_init(|| {
            extern "C" {
                fn mmap(
                    addr: usize,
                    len: usize,
                    prot: i32,
                    flags: i32,
                    fd: i32,
                    offset: i64,
                ) -> usize;
            }
            #[cfg(target_os = "macos")]
            const MAP_PRIVATE_ANON: i32 = 0x1002;
            #[cfg(target_os = "linux")]
            const MAP_PRIVATE_ANON: i32 = 0x22;
            const PROT_READ_WRITE: i32 = 3;
            let p = unsafe { mmap(0x0d00_0000, 0x1000, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0) };
            assert!(p != usize::MAX && (p | (p + 0xfff)) & 0x8000_0000 == 0);
            p
        }) as *mut u8
    }

    /// List A's object (+0x0 identity = its own address, +0x10 count).
    unsafe fn list_a() -> *mut u8 {
        slab()
    }

    /// List B's object.
    unsafe fn list_b() -> *mut u8 {
        slab().add(0x100)
    }

    /// List A's sentinel node (the circular end()).
    unsafe fn sentinel_a() -> *mut u8 {
        slab().add(0x40)
    }

    /// List B's sentinel node.
    unsafe fn sentinel_b() -> *mut u8 {
        slab().add(0x140)
    }

    /// List A element node `i` (up to 4).
    unsafe fn node_a(i: usize) -> *mut u8 {
        slab().add(0x80 + i * 0x10)
    }

    /// List B element node `i` (up to 4).
    unsafe fn node_b(i: usize) -> *mut u8 {
        slab().add(0x180 + i * 0x10)
    }

    /// Builds one circular list: identity word = the list object's own
    /// address, `count` element nodes threaded through the sentinel,
    /// every node's owner word pointing at the list.
    unsafe fn build_list(
        list: *mut u8,
        sentinel: *mut u8,
        node: unsafe fn(usize) -> *mut u8,
        count: usize,
    ) {
        set_word(list, LIST_SELF_OFFSET, list as u32);
        set_word(list, LIST_COUNT_OFFSET, count as u32);
        set_word(sentinel, NODE_OWNER_OFFSET, list as u32);
        for i in 0..count {
            let prev = if i == 0 { sentinel } else { node(i - 1) };
            let next = if i + 1 == count { sentinel } else { node(i + 1) };
            set_word(node(i), NODE_OWNER_OFFSET, list as u32);
            set_word(node(i), NODE_PREV_OFFSET, prev as u32);
            set_word(node(i), NODE_NEXT_OFFSET, next as u32);
        }
        let first = if count == 0 { sentinel } else { node(0) };
        let last = if count == 0 { sentinel } else { node(count - 1) };
        set_word(sentinel, NODE_NEXT_OFFSET, first as u32);
        set_word(sentinel, NODE_PREV_OFFSET, last as u32);
    }

    /// Builds both lists.
    unsafe fn build(a: usize, b: usize) {
        build_list(list_a(), sentinel_a(), node_a, a);
        build_list(list_b(), sentinel_b(), node_b, b);
    }

    /// Collects the nodes forward from the sentinel (validates the
    /// circular walk terminates within 16 steps).
    unsafe fn forward(sentinel: *mut u8) -> Vec<*mut u8> {
        let mut out = Vec::new();
        let mut cur = ptr_word(sentinel, NODE_NEXT_OFFSET);
        while cur != sentinel && out.len() < 16 {
            out.push(cur);
            cur = ptr_word(cur, NODE_NEXT_OFFSET);
        }
        out
    }

    /// Collects the nodes backward from the sentinel.
    unsafe fn backward(sentinel: *mut u8) -> Vec<*mut u8> {
        let mut out = Vec::new();
        let mut cur = ptr_word(sentinel, NODE_PREV_OFFSET);
        while cur != sentinel && out.len() < 16 {
            out.push(cur);
            cur = ptr_word(cur, NODE_PREV_OFFSET);
        }
        out
    }

    /// A snapshot of the whole fixture slab, for the refusal tests.
    unsafe fn snapshot() -> Vec<u8> {
        std::slice::from_raw_parts(slab(), 0x1000).to_vec()
    }

    #[test]
    fn a_middle_range_moves_links_counts_and_owners() {
        let _guard = lock();
        unsafe {
            build(3, 3);
            let mut pos: *mut u8 = node_a(2);
            let mut first: *mut u8 = node_b(0);
            let mut last: *mut u8 = node_b(2);
            assert_eq!(
                list_splice(list_a(), &mut pos, list_b(), &mut first, &mut last),
                1,
                "[b0, b2) splices ahead of a2"
            );
            assert_eq!(word(list_a(), LIST_COUNT_OFFSET), 5);
            assert_eq!(word(list_b(), LIST_COUNT_OFFSET), 1);
            assert_eq!(
                forward(sentinel_a()),
                std::vec![node_a(0), node_a(1), node_b(0), node_b(1), node_a(2)],
                "the range sits ahead of the position, in order"
            );
            let mut back = backward(sentinel_a());
            back.reverse();
            assert_eq!(back, forward(sentinel_a()), "prev links mirror next links");
            assert_eq!(
                forward(sentinel_b()),
                std::vec![node_b(2)],
                "the source keeps exactly the un-moved tail"
            );
            assert_eq!(backward(sentinel_b()), std::vec![node_b(2)]);
            // The adopt walk re-stamps only the moved nodes.
            assert_eq!(ptr_word(node_b(0), NODE_OWNER_OFFSET), list_a());
            assert_eq!(ptr_word(node_b(1), NODE_OWNER_OFFSET), list_a());
            assert_eq!(ptr_word(node_b(2), NODE_OWNER_OFFSET), list_b());
        }
    }

    #[test]
    fn the_whole_source_splices_onto_the_dst_end_via_the_sentinel() {
        let _guard = lock();
        unsafe {
            build(2, 3);
            // pos = dst sentinel (append at end), range = [b0, bS) —
            // the whole source, end() being the sentinel is what keeps
            // the `last` NULL panic unreachable.
            let mut pos: *mut u8 = sentinel_a();
            let mut first: *mut u8 = node_b(0);
            let mut last: *mut u8 = sentinel_b();
            assert_eq!(
                list_splice(list_a(), &mut pos, list_b(), &mut first, &mut last),
                1
            );
            assert_eq!(word(list_a(), LIST_COUNT_OFFSET), 5);
            assert_eq!(word(list_b(), LIST_COUNT_OFFSET), 0);
            assert_eq!(
                forward(sentinel_a()),
                std::vec![node_a(0), node_a(1), node_b(0), node_b(1), node_b(2)]
            );
            assert_eq!(forward(sentinel_b()), std::vec![], "source left empty");
            assert_eq!(
                ptr_word(sentinel_b(), NODE_NEXT_OFFSET),
                sentinel_b(),
                "an emptied source's sentinel self-links"
            );
            assert_eq!(ptr_word(sentinel_b(), NODE_PREV_OFFSET), sentinel_b());
        }
    }

    #[test]
    fn a_foreign_position_is_refused_and_nothing_moves() {
        let _guard = lock();
        unsafe {
            build(2, 2);
            let before = snapshot();
            // dst_pos points at a B node: owner word != *list_a.
            let mut pos: *mut u8 = node_b(0);
            let mut first: *mut u8 = node_b(0);
            let mut last: *mut u8 = node_b(1);
            assert_eq!(
                list_splice(list_a(), &mut pos, list_b(), &mut first, &mut last),
                0
            );
            assert_eq!(snapshot(), before, "a refusal touches nothing");
        }
    }

    #[test]
    fn a_foreign_first_is_refused_and_nothing_moves() {
        let _guard = lock();
        unsafe {
            build(2, 2);
            let before = snapshot();
            let mut pos: *mut u8 = node_a(0);
            let mut first: *mut u8 = node_a(1); // an A node, not B's
            let mut last: *mut u8 = node_b(1);
            assert_eq!(
                list_splice(list_a(), &mut pos, list_b(), &mut first, &mut last),
                0
            );
            assert_eq!(snapshot(), before);
        }
    }

    #[test]
    fn a_foreign_last_is_refused_and_nothing_moves() {
        let _guard = lock();
        unsafe {
            build(2, 2);
            let before = snapshot();
            let mut pos: *mut u8 = node_a(0);
            let mut first: *mut u8 = node_b(0);
            let mut last: *mut u8 = node_a(1); // an A node, not B's
            assert_eq!(
                list_splice(list_a(), &mut pos, list_b(), &mut first, &mut last),
                0
            );
            assert_eq!(snapshot(), before);
        }
    }

    #[test]
    fn an_empty_range_keeps_counts_and_swaps_predecessors() {
        let _guard = lock();
        unsafe {
            build(2, 2);
            // first == last: the original has NO empty-range guard —
            // the walk moves zero nodes (counts untouched) but the
            // re-link still runs, exchanging the predecessor links of
            // `first` and `pos` (range_last = first->prev = sentinelB).
            let mut pos: *mut u8 = node_a(1);
            let mut first: *mut u8 = node_b(0);
            let mut last: *mut u8 = node_b(0);
            assert_eq!(
                list_splice(list_a(), &mut pos, list_b(), &mut first, &mut last),
                1
            );
            assert_eq!(word(list_a(), LIST_COUNT_OFFSET), 2, "zero nodes moved");
            assert_eq!(word(list_b(), LIST_COUNT_OFFSET), 2);
            assert_eq!(ptr_word(node_b(0), NODE_PREV_OFFSET), node_a(0));
            assert_eq!(ptr_word(node_a(0), NODE_NEXT_OFFSET), node_b(0));
            assert_eq!(ptr_word(sentinel_b(), NODE_NEXT_OFFSET), node_a(1));
            assert_eq!(ptr_word(node_a(1), NODE_PREV_OFFSET), sentinel_b());
        }
    }

    #[test]
    fn the_slot_adapter_runs_the_splice_and_discards_the_verdict() {
        let _guard = lock();
        unsafe {
            build(1, 2);
            let mut pos: *mut u8 = sentinel_a();
            let mut first: *mut u8 = node_b(0);
            let mut last: *mut u8 = sentinel_b();
            splice_blocks(list_a(), &mut pos, list_b(), &mut first, &mut last);
            assert_eq!(word(list_a(), LIST_COUNT_OFFSET), 3);
            assert_eq!(word(list_b(), LIST_COUNT_OFFSET), 0);
            assert_eq!(
                forward(sentinel_a()),
                std::vec![node_a(0), node_b(0), node_b(1)]
            );
            // And a refusal through the adapter is silent too.
            let before = snapshot();
            let mut bad: *mut u8 = node_a(0);
            splice_blocks(list_b(), &mut pos, list_b(), &mut bad, &mut last);
            assert_eq!(snapshot(), before, "refused splices stay no-ops");
        }
    }
}
