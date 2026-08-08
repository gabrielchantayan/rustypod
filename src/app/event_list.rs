//! Lazily-built event tree of a retailOS view's event source object.
//!
//! Two halves of one protocol, ported from the pair @ 0x081e04b0 /
//! 0x081e054c. [`event_list_acquire`] builds the collection on demand and
//! [`event_list_release`] clears it after its consumer has copied it out.
//! The collection's historical name is "event list", but its 28-byte ADS
//! implementation is a libstdc++ red-black tree.
//!
//! # The object
//!
//! The source object embeds the tree at +0x38 (+0x38..+0x53) and has a
//! one-byte "tree is built" flag at +0x54. The tree header pointer is at
//! tree+0x10 (therefore source+0x48), and its live-node count is at +0x14.
//! The header's parent/root, leftmost/begin, and rightmost links are +0x4,
//! +0x8, and +0xc respectively. Thus the release half obtains `begin()`
//! from header+0x8 and `end()` from the header pointer itself.
//!
//! Nodes use the normal libstdc++ `_Rb_tree_node_base` links: parent +0x4,
//! left +0x8, right +0xc. The range erase at 0x083c1c3c recognizes a full
//! range (`first == header->left` and `last == header`), delegates its
//! post-order value destruction/recycling to 0x083c1f10, then restores the
//! empty-header invariants. Other ranges advance before erasing each node,
//! so their iterator remains valid across the single-node erase.
//!
//! # The pairing
//!
//! The canonical view method @ 0x0839f838 performs registry lookup,
//! `event_list_acquire`, a collection assignment, and
//! `event_list_release`. This is acquire / copy-out / release, not a lock:
//! every release clears the transient collection so the next acquire rebuilds
//! against fresh registry state.
//!
//! The builder @ 0x081e0280 remains unported because it resolves registry
//! values keyed by `'TEVT'` and `'CEVT'`; it alone remains behind the
//! [`EVENT_LIST_OPS`] dispatch boundary. The range-erase port calls its
//! three lower, still-unported tree-runtime dependencies through that same
//! boundary: iterator increment @ 0x083b5bb0, single-node erase @
//! 0x083c17d8, and subtree destruction/recycling @ 0x083c1f10.

/// Byte offset of the embedded event tree inside the source object
/// (original: `add r0, r4, #56` @ 0x081e04d4).
pub const EVENT_LIST_OFFSET: usize = 0x38;

/// Byte offset of the "tree has been built" flag
/// (original: `ldrb r0, [r0, #84]` @ 0x081e04b8).
pub const EVENT_LIST_BUILT_OFFSET: usize = 0x54;

/// Byte offset of the tree header pointer — its `end()` iterator.
pub const TREE_HEADER_OFFSET: usize = 0x10;
/// Byte offset of the tree's live-node count.
pub const TREE_NODE_COUNT_OFFSET: usize = 0x14;

/// Header/node link offsets in this libstdc++ `_Rb_tree` specialization.
pub const TREE_ROOT_OFFSET: usize = 0x4;
pub const TREE_LEFTMOST_OFFSET: usize = 0x8;
pub const TREE_RIGHTMOST_OFFSET: usize = 0xc;

/// Reads one u32 word of the opaque target layout. Tree pointers are
/// 32-bit, so host fixtures backing them must sit below 4 GiB
/// (`crate::testing::try_map_u32_slab`).
#[inline(always)]
unsafe fn word(at: *const u8) -> u32 {
    unsafe { at.cast::<u32>().read() }
}

/// Lower runtime dependencies that are still unported. `build` is the
/// separate event-build seam. The other slots are the direct callees of
/// [`event_list_tree_erase_range`], not a replacement erase seam.
#[derive(Clone, Copy)]
pub struct EventListOps {
    /// Original 0x081e0280: populate the source's event tree from the
    /// registry. Runs once per acquire/release cycle.
    pub build: unsafe extern "C" fn(source: *mut u8),
    /// Original 0x083b5bb0: advance the one-word in-order iterator.
    pub advance_iterator: unsafe extern "C" fn(iterator: *mut u32),
    /// Original 0x083c17d8: rebalance, destroy, recycle, and decrement for
    /// one node. `out` receives the successor iterator.
    pub erase_node: unsafe extern "C" fn(out: *mut u32, tree: *mut u8, node: *mut u32),
    /// Original 0x083c1f10: post-order tree destruction, including the
    /// allocator/value cleanup performed by 0x083c1648 for each node.
    pub destroy_subtree: unsafe extern "C" fn(tree: *mut u8, root: u32),
}

/// Default boundary before 0x081e0280 is ported. Building needs the registry
/// that does not exist on the host; an empty tree is the honest stand-in.
unsafe extern "C" fn missing_event_list_build(_source: *mut u8) {}

/// Defaults for lower tree-runtime dependencies. They deliberately do no
/// ownership work: their production implementations remain unported.
unsafe extern "C" fn missing_advance_iterator(_iterator: *mut u32) {}
unsafe extern "C" fn missing_erase_node(out: *mut u32, _tree: *mut u8, _node: *mut u32) {
    unsafe { out.write(0) };
}
unsafe extern "C" fn missing_destroy_subtree(_tree: *mut u8, _root: u32) {}

/// Wired defaults for [`EVENT_LIST_OPS`].
pub const DEFAULT_EVENT_LIST_OPS: EventListOps = EventListOps {
    build: missing_event_list_build,
    advance_iterator: missing_advance_iterator,
    erase_node: missing_erase_node,
    destroy_subtree: missing_destroy_subtree,
};

/// Active model for the separate build seam and the erase port's lower
/// runtime dependencies. Tests replace these slots to observe the exact
/// protocol.
pub static mut EVENT_LIST_OPS: EventListOps = DEFAULT_EVENT_LIST_OPS;

#[inline(always)]
unsafe fn build_op() -> unsafe extern "C" fn(*mut u8) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_LIST_OPS.build)) }
}

#[inline(always)]
unsafe fn advance_iterator_op() -> unsafe extern "C" fn(*mut u32) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_LIST_OPS.advance_iterator)) }
}

#[inline(always)]
unsafe fn erase_node_op() -> unsafe extern "C" fn(*mut u32, *mut u8, *mut u32) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_LIST_OPS.erase_node)) }
}

#[inline(always)]
unsafe fn destroy_subtree_op() -> unsafe extern "C" fn(*mut u8, u32) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_LIST_OPS.destroy_subtree)) }
}

/// event_list_acquire — original: `FUN_081e04b0` @ 0x081e04b0 (44 bytes,
/// 125 `bl` call sites).
///
/// Builds the source's event tree if the flag byte at +0x54 is clear, then
/// raises the flag and returns the tree at +0x38. Any non-zero flag means
/// built. `source` is dereferenced unchecked, as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_list_acquire(source: *mut u8) -> *mut u8 {
    let built = unsafe { source.add(EVENT_LIST_BUILT_OFFSET) };
    if unsafe { built.read() } == 0 {
        unsafe { (build_op())(source) };
        unsafe { built.write(1) };
    }
    unsafe { source.add(EVENT_LIST_OFFSET) }
}

/// event_list_tree_erase_range — original: `FUN_083c1c3c` @ 0x083c1c3c
/// (224 bytes).
///
/// Erases `[first, last)` from the event collection's libstdc++ red-black
/// tree. It first writes the header iterator to `out` and returns that same
/// sret pointer. A non-empty whole-tree range destroys/recycles the root
/// subtree, then sets root to null, leftmost/rightmost to the header, and
/// count to zero. Otherwise it saves each current node, advances `first`
/// before invalidating it, performs the single-node erase, and forwards that
/// erase's successor through `out`. Empty and non-whole ranges leave header
/// bookkeeping to the lower operation exactly as the ARM code does.
///
/// The iterator increment, single-node RB-tree erase, and payload/allocator
/// destruction are still explicit lower-runtime seams; this function owns
/// their ordering and all full-range header bookkeeping.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_list_tree_erase_range(
    out: *mut u32,
    tree: *mut u8,
    first: *mut u32,
    last: *mut u32,
) -> *mut u32 {
    let header = unsafe { word(tree.add(TREE_HEADER_OFFSET)) };
    unsafe { out.write(header) };

    let begin = unsafe {
        word((header as usize as *const u8).add(TREE_LEFTMOST_OFFSET))
    };
    if unsafe { first.read() } == begin
        && unsafe { last.read() } == header
        && unsafe { word(tree.add(TREE_NODE_COUNT_OFFSET)) } != 0
    {
        let root = unsafe {
            word((header as usize as *const u8).add(TREE_ROOT_OFFSET))
        };
        unsafe { (destroy_subtree_op())(tree, root) };
        unsafe {
            let header_ptr = header as usize as *mut u8;
            header_ptr.add(TREE_LEFTMOST_OFFSET).cast::<u32>().write(header);
            header_ptr.add(TREE_ROOT_OFFSET).cast::<u32>().write(0);
            header_ptr
                .add(TREE_RIGHTMOST_OFFSET)
                .cast::<u32>()
                .write(header);
            tree.add(TREE_NODE_COUNT_OFFSET).cast::<u32>().write(0);
            out.write(header);
        }
        return out;
    }

    while unsafe { first.read() } != unsafe { last.read() } {
        let mut node = unsafe { first.read() };
        unsafe { (advance_iterator_op())(first) };
        let mut successor = 0;
        unsafe { (erase_node_op())(&mut successor, tree, &mut node) };
        unsafe { out.write(successor) };
    }
    out
}

/// event_list_release — original: `FUN_081e054c` @ 0x081e054c (80 bytes,
/// 125 `bl` call sites).
///
/// Empties the source's event tree with `erase(begin(), end())` and clears
/// the built flag so the next acquire rebuilds. The flag is cleared
/// unconditionally, including a release that follows no acquire.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_list_release(source: *mut u8) {
    let tree = unsafe { source.add(EVENT_LIST_OFFSET) };
    let header = unsafe { word(tree.add(TREE_HEADER_OFFSET)) };
    let mut first = unsafe {
        word((header as usize as *const u8).add(TREE_LEFTMOST_OFFSET))
    };
    let mut last = header;
    let mut erased: u32 = 0;

    unsafe { event_list_tree_erase_range(&mut erased, tree, &mut first, &mut last) };
    unsafe { source.add(EVENT_LIST_BUILT_OFFSET).write(0) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut BUILD_CALLS: u32 = 0;
    static mut BUILD_SOURCE: usize = 0;
    static mut EVENTS: Vec<Call> = Vec::new();

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Advance(u32),
        Erase { tree: usize, node: u32 },
        Destroy { tree: usize, root: u32 },
    }

    unsafe extern "C" fn recording_build(source: *mut u8) {
        unsafe {
            BUILD_CALLS += 1;
            BUILD_SOURCE = source as usize;
        }
    }

    unsafe extern "C" fn recording_advance_iterator(iterator: *mut u32) {
        let node = unsafe { iterator.read() };
        unsafe {
            EVENTS.push(Call::Advance(node));
            iterator.write(word(
                (node as usize as *const u8).add(TREE_RIGHTMOST_OFFSET),
            ));
        }
    }

    unsafe extern "C" fn recording_erase_node(out: *mut u32, tree: *mut u8, node: *mut u32) {
        let current = unsafe { node.read() };
        unsafe {
            EVENTS.push(Call::Erase {
                tree: tree as usize,
                node: current,
            });
            // The right-chain fixture's successor is its right child.
            out.write(word(
                (current as usize as *const u8).add(TREE_RIGHTMOST_OFFSET),
            ));
        }
    }

    unsafe extern "C" fn recording_destroy_subtree(tree: *mut u8, root: u32) {
        unsafe {
            EVENTS.push(Call::Destroy {
                tree: tree as usize,
                root,
            });
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { EVENT_LIST_OPS = DEFAULT_EVENT_LIST_OPS };
        }
    }

    fn bench() -> Bench {
        let lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            BUILD_CALLS = 0;
            BUILD_SOURCE = 0;
            EVENTS.clear();
            EVENT_LIST_OPS = EventListOps {
                build: recording_build,
                advance_iterator: recording_advance_iterator,
                erase_node: recording_erase_node,
                destroy_subtree: recording_destroy_subtree,
            };
        }
        Bench { _lock: lock }
    }

    fn events() -> Vec<Call> {
        unsafe { EVENTS.clone() }
    }

    /// The acquire half never follows target pointers, so it needs no
    /// below-4-GiB backing allocation.
    fn source_object() -> Vec<u8> {
        std::vec![0u8; EVENT_LIST_BUILT_OFFSET + 1]
    }

    #[test]
    fn acquire_builds_once_and_raises_the_flag() {
        let _bench = bench();
        let mut object = source_object();
        let source = object.as_mut_ptr();

        let tree = unsafe { event_list_acquire(source) };

        assert_eq!(tree, unsafe { source.add(EVENT_LIST_OFFSET) });
        assert_eq!(unsafe { BUILD_CALLS }, 1);
        assert_eq!(unsafe { BUILD_SOURCE }, source as usize);
        assert_eq!(object[EVENT_LIST_BUILT_OFFSET], 1);
        unsafe { event_list_acquire(source) };
        assert_eq!(unsafe { BUILD_CALLS }, 1, "a non-zero flag skips the builder");
    }

    #[test]
    fn acquire_treats_every_nonzero_flag_as_built() {
        let _bench = bench();
        let mut object = source_object();
        object[EVENT_LIST_BUILT_OFFSET] = 0xff;

        unsafe { event_list_acquire(object.as_mut_ptr()) };

        assert_eq!(unsafe { BUILD_CALLS }, 0);
        assert_eq!(object[EVENT_LIST_BUILT_OFFSET], 0xff, "the flag is not normalized");
    }

    const SLAB_HINT: usize = crate::testing::hints::EVENT_LIST;
    const SLAB_LEN: usize = 0x1000;
    const HEADER_AT: usize = 0x100;
    const NODE_AT: [usize; 3] = [0x200, 0x300, 0x400];
    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(SLAB_HINT, SLAB_LEN).map(|p| p as usize));

    /// One low mapping serves every target-pointer fixture. The lock held by
    /// each test makes reuse safe.
    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|p| p as *mut u8)
    }

    unsafe fn put_word(at: *mut u8, value: u32) {
        unsafe { at.cast::<u32>().write(value) };
    }

    unsafe fn tree_header(slab: *mut u8) -> u32 {
        unsafe { word(slab.add(EVENT_LIST_OFFSET + TREE_HEADER_OFFSET)) }
    }

    unsafe fn node(slab: *mut u8, index: usize) -> u32 {
        unsafe { slab.add(NODE_AT[index]) as usize as u32 }
    }

    /// Installs an empty tree or an in-order right chain. The chain is a
    /// valid iterator fixture: A -> B -> C, and its header retains the
    /// target's root/leftmost/rightmost/count layout.
    unsafe fn install_tree(slab: *mut u8, count: usize) {
        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            let tree = slab.add(EVENT_LIST_OFFSET);
            let header = slab.add(HEADER_AT);
            put_word(tree.add(TREE_HEADER_OFFSET), header as usize as u32);
            put_word(tree.add(TREE_NODE_COUNT_OFFSET), count as u32);
            put_word(header.add(TREE_ROOT_OFFSET), 0);
            put_word(header.add(TREE_LEFTMOST_OFFSET), header as usize as u32);
            put_word(header.add(TREE_RIGHTMOST_OFFSET), header as usize as u32);
            for index in 0..count {
                let current = slab.add(NODE_AT[index]);
                let parent = if index == 0 {
                    header as usize as u32
                } else {
                    node(slab, index - 1)
                };
                let right = if index + 1 == count {
                    0
                } else {
                    node(slab, index + 1)
                };
                put_word(current.add(TREE_ROOT_OFFSET), parent);
                put_word(current.add(TREE_LEFTMOST_OFFSET), 0);
                put_word(current.add(TREE_RIGHTMOST_OFFSET), right);
            }
            if count != 0 {
                put_word(header.add(TREE_ROOT_OFFSET), node(slab, 0));
                put_word(header.add(TREE_LEFTMOST_OFFSET), node(slab, 0));
                put_word(header.add(TREE_RIGHTMOST_OFFSET), node(slab, count - 1));
            }
            slab.add(EVENT_LIST_BUILT_OFFSET).write(1);
        }
    }

    fn fixture(count: usize) -> Option<*mut u8> {
        let slab = try_slab()?;
        unsafe { install_tree(slab, count) };
        Some(slab)
    }

    #[test]
    fn erase_empty_range_returns_header_without_runtime_calls() {
        let _bench = bench();
        let Some(slab) = fixture(0) else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        let tree = unsafe { slab.add(EVENT_LIST_OFFSET) };
        let header = unsafe { tree_header(slab) };
        let mut first = header;
        let mut last = header;
        let mut out = 0;

        let returned = unsafe { event_list_tree_erase_range(&mut out, tree, &mut first, &mut last) };

        assert_eq!(returned, core::ptr::addr_of_mut!(out));
        assert_eq!(out, header);
        assert!(events().is_empty());
        assert_eq!(unsafe { word(tree.add(TREE_NODE_COUNT_OFFSET)) }, 0);
        assert_eq!(
            unsafe { word((header as usize as *const u8).add(TREE_LEFTMOST_OFFSET)) },
            header
        );
    }

    #[test]
    fn erase_one_middle_node_advances_before_the_lower_erase() {
        let _bench = bench();
        let Some(slab) = fixture(3) else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        let tree = unsafe { slab.add(EVENT_LIST_OFFSET) };
        let mut first = unsafe { node(slab, 1) };
        let last = unsafe { node(slab, 2) };
        let mut last_slot = last;
        let mut out = 0;

        unsafe { event_list_tree_erase_range(&mut out, tree, &mut first, &mut last_slot) };

        assert_eq!(first, last, "the iterator advances before its node is invalidated");
        assert_eq!(out, last, "single-node erase returns its successor");
        assert_eq!(
            events(),
            std::vec![
                Call::Advance(unsafe { node(slab, 1) }),
                Call::Erase {
                    tree: tree as usize,
                    node: unsafe { node(slab, 1) },
                },
            ]
        );
        assert_eq!(
            unsafe { word(tree.add(TREE_NODE_COUNT_OFFSET)) },
            3,
            "the lower single-node erase owns partial-range bookkeeping"
        );
    }

    #[test]
    fn erase_multiple_partial_range_repeats_advance_then_erase() {
        let _bench = bench();
        let Some(slab) = fixture(3) else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        let tree = unsafe { slab.add(EVENT_LIST_OFFSET) };
        let mut first = unsafe { node(slab, 0) };
        let last = unsafe { node(slab, 2) };
        let mut last_slot = last;
        let mut out = 0;

        unsafe { event_list_tree_erase_range(&mut out, tree, &mut first, &mut last_slot) };

        assert_eq!(first, last);
        assert_eq!(out, last);
        assert_eq!(
            events(),
            std::vec![
                Call::Advance(unsafe { node(slab, 0) }),
                Call::Erase {
                    tree: tree as usize,
                    node: unsafe { node(slab, 0) },
                },
                Call::Advance(unsafe { node(slab, 1) }),
                Call::Erase {
                    tree: tree as usize,
                    node: unsafe { node(slab, 1) },
                },
            ]
        );
    }

    #[test]
    fn erase_whole_single_node_tree_destroys_before_resetting_header() {
        let _bench = bench();
        let Some(slab) = fixture(1) else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        let tree = unsafe { slab.add(EVENT_LIST_OFFSET) };
        let header = unsafe { tree_header(slab) };
        let root = unsafe { node(slab, 0) };
        let mut first = root;
        let mut last = header;
        let mut out = 0;

        unsafe { event_list_tree_erase_range(&mut out, tree, &mut first, &mut last) };

        assert_eq!(
            events(),
            std::vec![Call::Destroy {
                tree: tree as usize,
                root,
            }],
            "subtree destruction owns the node value and allocator release"
        );
        assert_eq!(out, header);
        assert_eq!(unsafe { word(tree.add(TREE_NODE_COUNT_OFFSET)) }, 0);
        assert_eq!(unsafe { word((header as usize as *const u8).add(TREE_ROOT_OFFSET)) }, 0);
        assert_eq!(
            unsafe { word((header as usize as *const u8).add(TREE_LEFTMOST_OFFSET)) },
            header
        );
        assert_eq!(
            unsafe { word((header as usize as *const u8).add(TREE_RIGHTMOST_OFFSET)) },
            header
        );
    }

    #[test]
    fn release_clears_a_whole_multiple_node_tree_and_rearms_the_builder() {
        let _bench = bench();
        let Some(slab) = fixture(3) else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        let tree = unsafe { slab.add(EVENT_LIST_OFFSET) };
        let root = unsafe { node(slab, 0) };

        unsafe { event_list_release(slab) };

        assert_eq!(
            events(),
            std::vec![Call::Destroy {
                tree: tree as usize,
                root,
            }]
        );
        assert_eq!(unsafe { word(tree.add(TREE_NODE_COUNT_OFFSET)) }, 0);
        assert_eq!(unsafe { slab.add(EVENT_LIST_BUILT_OFFSET).read() }, 0);
        unsafe { event_list_acquire(slab) };
        assert_eq!(unsafe { BUILD_CALLS }, 1, "release made the next acquire rebuild");
    }
}
