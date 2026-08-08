//! Lazily-built event tree of a retailOS view's event source object.
//!
//! The source owns an event declaration collection and a transient
//! libstdc++ red-black tree. [`event_list_populate_from_registry`] resolves
//! each declaration through the application registry and materializes the
//! descriptors in that tree. [`event_list_acquire`] builds it on demand and
//! [`event_list_release`] clears it after its consumer has copied it out.
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

/// Byte offset of the source's mandatory single event declaration.
pub const EVENT_SOURCE_PRIMARY_EVENT_OFFSET: usize = 0x08;
/// Byte offsets of the contiguous `void *` declaration vector.
pub const EVENT_SOURCE_EVENT_BEGIN_OFFSET: usize = 0x10;
pub const EVENT_SOURCE_EVENT_END_OFFSET: usize = 0x14;
/// Byte offset of a declaration object's lookup value.
pub const EVENT_DECLARATION_VALUE_OFFSET: usize = 0x08;
/// Byte offset of the optional supplementary declaration object.
pub const EVENT_SOURCE_OPTIONAL_EVENT_OFFSET: usize = 0x58;
/// Byte offset of that supplementary object's lookup value.
pub const OPTIONAL_EVENT_VALUE_OFFSET: usize = 0x04;

/// Multi-character registry keys stored in the literal pool at
/// 0x081e04a4..0x081e04ac. They are native-endian ARM `u32` values, so
/// `0x5445_5654` is the bytes `TEVT` in memory.
pub const EVENT_DECLARATION_KEY: u32 = 0x5445_5654; // 'TEVT'
pub const EVENT_SOURCE_KEY: u32 = 0x5345_5654; // 'SEVT'
pub const OPTIONAL_EVENT_KEY: u32 = 0x4345_5654; // 'CEVT'

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

/// Registry operations below the one function ported here.
///
/// A resolver returns the descriptor's bytes and writes their byte length to
/// `length_out`; NULL means that no descriptor exists. The concrete resolver
/// is `app_string_resolver_resolve` at 0x0811ca58, whose lower provider
/// table remains independently opaque. Appending owns the temporary
/// descriptor/string construction, insertion, and destruction sequence
/// below 0x081e0280.
#[derive(Clone, Copy)]
pub struct EventListBuildOps {
    pub registry: unsafe extern "C" fn() -> *mut u8,
    pub resolve: unsafe extern "C" fn(*mut u8, u32, u32, *mut u32) -> *const u8,
    pub append: unsafe extern "C" fn(*mut u8, *const u8, u32),
    /// RetailOS's 0x08030f44 does not return. Host test replacements may
    /// return, in which case the builder stops at the failed lookup.
    pub fail: unsafe extern "C" fn(),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_event_registry() -> *mut u8 {
    let getter: unsafe extern "C" fn() -> *mut u8 = unsafe { core::mem::transmute(0x0819_fdb0usize) };
    unsafe { getter() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_event_registry() -> *mut u8 {
    panic!("event_list_populate_from_registry requires registry getter 0x0819fdb0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_event_resolve(
    registry: *mut u8,
    key: u32,
    value: u32,
    length_out: *mut u32,
) -> *const u8 {
    let resolve: unsafe extern "C" fn(*mut u8, u32, u32, *mut u32) -> *const u8 =
        unsafe { core::mem::transmute(0x0811_ca58usize) };
    unsafe { resolve(registry, key, value, length_out) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_event_resolve(
    _registry: *mut u8,
    _key: u32,
    _value: u32,
    _length_out: *mut u32,
) -> *const u8 {
    panic!("event_list_populate_from_registry requires resolver 0x0811ca58")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_append_event_descriptor(
    event_list: *mut u8,
    bytes: *const u8,
    length: u32,
) {
    #[repr(C, align(4))]
    struct EventDescriptor([u8; 0x7c]);
    #[repr(C, align(4))]
    struct EventDescriptorTree([u8; 0x1c]);

    let construct_tree: unsafe extern "C" fn(*mut u8, *mut u8) =
        unsafe { core::mem::transmute(0x083d_b2d4usize) };
    let construct_descriptor: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> *mut u8 =
        unsafe { core::mem::transmute(0x082a_7dacusize) };
    let store_descriptor: unsafe extern "C" fn(*mut u8, *mut u8) =
        unsafe { core::mem::transmute(0x082a_af10usize) };
    let append_tree: unsafe extern "C" fn(*mut u8, *mut u8) =
        unsafe { core::mem::transmute(0x080e_40c8usize) };
    let destroy_descriptor: unsafe extern "C" fn(*mut u8, u32, u32) =
        unsafe { core::mem::transmute(0x082a_7e10usize) };
    let destroy_tree: unsafe extern "C" fn(*mut u8) =
        unsafe { core::mem::transmute(0x082a_7fd8usize) };

    let mut comparator = 0u8;
    let mut temporary_tree = EventDescriptorTree([0; 0x1c]);
    let mut descriptor = EventDescriptor([0; 0x7c]);
    let mut string = core::ptr::null_mut();

    unsafe {
        construct_tree(temporary_tree.0.as_mut_ptr(), &mut comparator);
        crate::cxx::string::cxx_string_from_buffer(&mut string, bytes, length);
        let stored = construct_descriptor(descriptor.0.as_mut_ptr(), string, 12);
        crate::cxx::string::cxx_string_release(&mut string);
        store_descriptor(stored, temporary_tree.0.as_mut_ptr());
        append_tree(temporary_tree.0.as_mut_ptr(), event_list);
        destroy_descriptor(descriptor.0.as_mut_ptr(), 2, 0);
        destroy_tree(temporary_tree.0.as_mut_ptr());
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_append_event_descriptor(
    _event_list: *mut u8,
    _bytes: *const u8,
    _length: u32,
) {
    panic!("event_list_populate_from_registry requires event descriptor insertion")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_event_list_fail() {
    let fail: unsafe extern "C" fn() -> ! = unsafe { core::mem::transmute(0x0803_0f44usize) };
    unsafe { fail() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_event_list_fail() {
    panic!("event_list_populate_from_registry encountered an unresolved event")
}

/// Active registry and descriptor operations for
/// [`event_list_populate_from_registry`]. Host tests replace this table;
/// retailOS defaults invoke its remaining firmware dependencies directly.
#[cfg(target_os = "none")]
pub static mut EVENT_LIST_BUILD_OPS: EventListBuildOps = EventListBuildOps {
    registry: firmware_event_registry,
    resolve: firmware_event_resolve,
    append: firmware_append_event_descriptor,
    fail: firmware_event_list_fail,
};

#[cfg(not(target_os = "none"))]
pub static mut EVENT_LIST_BUILD_OPS: EventListBuildOps = EventListBuildOps {
    registry: missing_event_registry,
    resolve: missing_event_resolve,
    append: missing_append_event_descriptor,
    fail: missing_event_list_fail,
};

#[inline(always)]
unsafe fn build_ops() -> EventListBuildOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_LIST_BUILD_OPS)) }
}

/// Lower tree-runtime dependencies used only by
/// [`event_list_tree_erase_range`].
#[derive(Clone, Copy)]
pub struct EventListOps {
    /// Original 0x083b5bb0: advance the one-word in-order iterator.
    pub advance_iterator: unsafe extern "C" fn(iterator: *mut u32),
    /// Original 0x083c17d8: rebalance, destroy, recycle, and decrement for
    /// one node. `out` receives the successor iterator.
    pub erase_node: unsafe extern "C" fn(out: *mut u32, tree: *mut u8, node: *mut u32),
    /// Original 0x083c1f10: post-order tree destruction, including the
    /// allocator/value cleanup performed by 0x083c1648 for each node.
    pub destroy_subtree: unsafe extern "C" fn(tree: *mut u8, root: u32),
}

/// Defaults for lower tree-runtime dependencies. They deliberately do no
/// ownership work: their production implementations remain unported.
unsafe extern "C" fn missing_advance_iterator(_iterator: *mut u32) {}
unsafe extern "C" fn missing_erase_node(out: *mut u32, _tree: *mut u8, _node: *mut u32) {
    unsafe { out.write(0) };
}
unsafe extern "C" fn missing_destroy_subtree(_tree: *mut u8, _root: u32) {}

/// Wired defaults for [`EVENT_LIST_OPS`].
pub const DEFAULT_EVENT_LIST_OPS: EventListOps = EventListOps {
    advance_iterator: missing_advance_iterator,
    erase_node: missing_erase_node,
    destroy_subtree: missing_destroy_subtree,
};

/// Active model for the erase port's lower runtime dependencies. Tests
/// replace these slots to observe the exact protocol.
pub static mut EVENT_LIST_OPS: EventListOps = DEFAULT_EVENT_LIST_OPS;

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

/// event_list_populate_from_registry — original: `FUN_081e0280` @
/// 0x081e0280 (548 bytes).
///
/// Clears the transient event tree, then resolves the source's declaration
/// vector under `'TEVT'`, its mandatory +0x08 declaration under `'SEVT'`,
/// and (when non-NULL) the +0x58 object's +0x04 declaration under `'CEVT'`.
/// Each successful resolution is a `{ byte_length, bytes }` descriptor;
/// its bytes are copied into a temporary owned descriptor, inserted into a
/// temporary tree, appended to the source's tree, and then destroyed. A
/// failed lookup calls retailOS's non-returning error path immediately:
/// later declarations are not considered. The function itself returns no
/// value and retains no borrow of the resolved descriptor.
///
/// Sources: raw ARM at `ipod-decomp/decomp/osos.asm` 0x081e0280; reference C
/// at `decomp/c/020/081e0280_FUN_081e0280.c`; resolver 0x0811ca58; string
/// construction 0x083d8bac; descriptor insertion sequence 0x083db2d4 /
/// 0x082a7dac / 0x082aaf10 / 0x080e40c8 / 0x082a7e10 / 0x082a7fd8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_list_populate_from_registry(source: *mut u8) {
    let ops = unsafe { build_ops() };
    let tree = unsafe { source.add(EVENT_LIST_OFFSET) };
    let header = unsafe { word(tree.add(TREE_HEADER_OFFSET)) };
    let mut first = unsafe { word((header as usize as *const u8).add(TREE_LEFTMOST_OFFSET)) };
    let mut last = header;
    let mut erased = 0;
    unsafe { event_list_tree_erase_range(&mut erased, tree, &mut first, &mut last) };

    let registry = unsafe { (ops.registry)() };
    let mut declaration = unsafe { word(source.add(EVENT_SOURCE_EVENT_BEGIN_OFFSET)) };
    let declaration_end = unsafe { word(source.add(EVENT_SOURCE_EVENT_END_OFFSET)) };
    while declaration != declaration_end {
        let value = unsafe {
            word((word(declaration as usize as *const u8) as usize as *const u8)
                .add(EVENT_DECLARATION_VALUE_OFFSET))
        };
        if !unsafe { event_list_append_resolved(tree, registry, EVENT_DECLARATION_KEY, value, ops) } {
            return;
        }
        declaration = declaration.wrapping_add(4);
    }

    let primary = unsafe { word(source.add(EVENT_SOURCE_PRIMARY_EVENT_OFFSET)) };
    if !unsafe { event_list_append_resolved(tree, registry, EVENT_SOURCE_KEY, primary, ops) } {
        return;
    }

    let optional = unsafe { word(source.add(EVENT_SOURCE_OPTIONAL_EVENT_OFFSET)) };
    if optional != 0 {
        let value = unsafe {
            word((optional as usize as *const u8).add(OPTIONAL_EVENT_VALUE_OFFSET))
        };
        unsafe { event_list_append_resolved(tree, registry, OPTIONAL_EVENT_KEY, value, ops) };
    }
}

#[inline(always)]
unsafe fn event_list_append_resolved(
    tree: *mut u8,
    registry: *mut u8,
    key: u32,
    value: u32,
    ops: EventListBuildOps,
) -> bool {
    let mut length = 0;
    let bytes = unsafe { (ops.resolve)(registry, key, value, &mut length) };
    if bytes.is_null() {
        unsafe { (ops.fail)() };
        return false;
    }
    unsafe { (ops.append)(tree, bytes, length) };
    true
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
        unsafe { event_list_populate_from_registry(source) };
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
    static mut EVENTS: Vec<Call> = Vec::new();
    static mut FAIL_VALUE: u32 = 0;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Registry,
        Resolve { key: u32, value: u32 },
        Append { tree: usize, bytes: usize, length: u32 },
        Fail,
        Advance(u32),
        Erase { tree: usize, node: u32 },
        Destroy { tree: usize, root: u32 },
    }

    unsafe extern "C" fn recording_registry() -> *mut u8 {
        unsafe {
            EVENTS.push(Call::Registry);
            0x1111_0000usize as *mut u8
        }
    }

    unsafe extern "C" fn recording_resolve(
        registry: *mut u8,
        key: u32,
        value: u32,
        length_out: *mut u32,
    ) -> *const u8 {
        assert_eq!(registry as usize, 0x1111_0000);
        unsafe {
            EVENTS.push(Call::Resolve { key, value });
            if value == FAIL_VALUE {
                return core::ptr::null();
            }
            length_out.write(value.wrapping_add(0x40));
            (0x2222_0000usize.wrapping_add(value as usize)) as *const u8
        }
    }

    unsafe extern "C" fn recording_append(tree: *mut u8, bytes: *const u8, length: u32) {
        unsafe {
            EVENTS.push(Call::Append {
                tree: tree as usize,
                bytes: bytes as usize,
                length,
            });
        }
    }

    unsafe extern "C" fn recording_fail() {
        unsafe { EVENTS.push(Call::Fail) };
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
            unsafe {
                EVENT_LIST_BUILD_OPS = EventListBuildOps {
                    registry: missing_event_registry,
                    resolve: missing_event_resolve,
                    append: missing_append_event_descriptor,
                    fail: missing_event_list_fail,
                };
                EVENT_LIST_OPS = DEFAULT_EVENT_LIST_OPS;
            }
        }
    }

    fn bench() -> Bench {
        let lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FAIL_VALUE = u32::MAX;
            EVENTS.clear();
            EVENT_LIST_BUILD_OPS = EventListBuildOps {
                registry: recording_registry,
                resolve: recording_resolve,
                append: recording_append,
                fail: recording_fail,
            };
            EVENT_LIST_OPS = EventListOps {
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

    /// Builds a source with an empty tree, a vector of declaration pointers,
    /// its mandatory event value, and optionally the supplementary object.
    unsafe fn install_build_source(slab: *mut u8, declarations: &[u32], optional: bool) {
        unsafe {
            install_tree(slab, 0);
            let vector = slab.add(0x500);
            put_word(
                slab.add(EVENT_SOURCE_EVENT_BEGIN_OFFSET),
                vector as usize as u32,
            );
            put_word(
                slab.add(EVENT_SOURCE_EVENT_END_OFFSET),
                vector.add(declarations.len() * 4) as usize as u32,
            );
            for (index, &value) in declarations.iter().enumerate() {
                let declaration = slab.add(0x600 + index * 0x10);
                put_word(vector.add(index * 4), declaration as usize as u32);
                put_word(declaration.add(EVENT_DECLARATION_VALUE_OFFSET), value);
            }
            put_word(slab.add(EVENT_SOURCE_PRIMARY_EVENT_OFFSET), 0x30);
            if optional {
                let extra = slab.add(0x700);
                put_word(slab.add(EVENT_SOURCE_OPTIONAL_EVENT_OFFSET), extra as usize as u32);
                put_word(extra.add(OPTIONAL_EVENT_VALUE_OFFSET), 0x40);
            }
        }
    }

    #[test]
    fn populate_empty_declaration_vector_keeps_the_mandatory_source_event() {
        let _bench = bench();
        let Some(slab) = try_slab() else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        unsafe {
            install_build_source(slab, &[], false);
            event_list_populate_from_registry(slab);
        }

        assert_eq!(
            events(),
            std::vec![
                Call::Registry,
                Call::Resolve {
                    key: EVENT_SOURCE_KEY,
                    value: 0x30,
                },
                Call::Append {
                    tree: unsafe { slab.add(EVENT_LIST_OFFSET) } as usize,
                    bytes: 0x2222_0030,
                    length: 0x70,
                },
            ]
        );
    }

    #[test]
    fn populate_walks_multiple_declarations_then_source_and_optional_event() {
        let _bench = bench();
        let Some(slab) = try_slab() else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        unsafe {
            install_build_source(slab, &[0x11, 0x22], true);
            event_list_populate_from_registry(slab);
        }

        let tree = unsafe { slab.add(EVENT_LIST_OFFSET) } as usize;
        assert_eq!(
            events(),
            std::vec![
                Call::Registry,
                Call::Resolve {
                    key: EVENT_DECLARATION_KEY,
                    value: 0x11,
                },
                Call::Append {
                    tree,
                    bytes: 0x2222_0011,
                    length: 0x51,
                },
                Call::Resolve {
                    key: EVENT_DECLARATION_KEY,
                    value: 0x22,
                },
                Call::Append {
                    tree,
                    bytes: 0x2222_0022,
                    length: 0x62,
                },
                Call::Resolve {
                    key: EVENT_SOURCE_KEY,
                    value: 0x30,
                },
                Call::Append {
                    tree,
                    bytes: 0x2222_0030,
                    length: 0x70,
                },
                Call::Resolve {
                    key: OPTIONAL_EVENT_KEY,
                    value: 0x40,
                },
                Call::Append {
                    tree,
                    bytes: 0x2222_0040,
                    length: 0x80,
                },
            ]
        );
    }

    #[test]
    fn populate_stops_at_the_first_unresolved_declaration() {
        let _bench = bench();
        let Some(slab) = try_slab() else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        unsafe {
            install_build_source(slab, &[0x11, 0x22], true);
            FAIL_VALUE = 0x22;
            event_list_populate_from_registry(slab);
        }

        let tree = unsafe { slab.add(EVENT_LIST_OFFSET) } as usize;
        assert_eq!(
            events(),
            std::vec![
                Call::Registry,
                Call::Resolve {
                    key: EVENT_DECLARATION_KEY,
                    value: 0x11,
                },
                Call::Append {
                    tree,
                    bytes: 0x2222_0011,
                    length: 0x51,
                },
                Call::Resolve {
                    key: EVENT_DECLARATION_KEY,
                    value: 0x22,
                },
                Call::Fail,
            ],
            "the retail error path is reached before later vector, source, or optional entries"
        );
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
        assert_eq!(
            events(),
            std::vec![
                Call::Destroy {
                    tree: tree as usize,
                    root,
                },
                Call::Registry,
                Call::Resolve {
                    key: EVENT_SOURCE_KEY,
                    value: 0,
                },
                Call::Append {
                    tree: tree as usize,
                    bytes: 0x2222_0000,
                    length: 0x40,
                },
            ],
            "release made the next acquire populate the source again"
        );
    }
}
