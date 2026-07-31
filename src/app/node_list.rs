//! The view-list singleton and its walker.
//!
//! Ports:
//! - [`node_list_construct`] — original: `FUN_0811000c` @ 0x0811000c
//!   (52 bytes) — constructs the view-list singleton in place.
//! - [`node_list_get`] — original: `FUN_0810fa30` @ 0x0810fa30 (72
//!   bytes; 168 `bl` call sites, binary-verified) — the singleton's
//!   accessor, a textbook ADS function-local-static initializer.
//! - [`list_count_until_match`] — original: `FUN_0810fa90` @ 0x0810fa90
//!   (84 bytes; 125 `bl` call sites, binary-scanned).
//!
//! `list_count_until_match` walks the singly-linked node list hanging
//! off a list object and returns how many nodes it visited. When the
//! object carries a nonzero *stop key* the walk ends at (and counts)
//! the first node whose vtable slot +0x68 returns that key, so the
//! result is the node's 1-based position; with a zero stop key nothing
//! can match and the result is the full node count.
//!
//! The list object is a C++ singleton — its accessor `FUN_0810fa30` is
//! a function-local-static initializer (guard word @ 0x089cc834, ADS
//! guard helpers @ 0x082ab31c / 0x082ab338) that returns the fixed
//! object @ 0x08a79c74, and the getter @ 0x0810fa88 hands out its head
//! pointer. The 125 callers are view classes in the 0x0839xxxx block,
//! all of the form `list_walk_begin(); depth = list_count_until_match();
//! this->field_c4 = depth;`. Its sibling `FUN_0810fb48` drains the same
//! list, dispatching the same +0x68 slot against the same stop key.
//!
//! ```text
//! list +0x00  vtable            (dispatched by FUN_0810fb48, not here)
//! list +0x04  head node
//! list +0x08  stop key          0 = walk the whole list
//! node +0x00  vtable            (+0x68 = the node's key accessor)
//! node +0x14  next node
//! ```
//!
//! Faithful details:
//! - The counter is bumped *before* the key test, so a matching node is
//!   included in the result.
//! - The stop key is re-read from the list on both sides of the virtual
//!   call — the original does two `ldr r0, [r5, #8]` — so a callee that
//!   rewrites it is honored. Reproduced.
//! - The dispatch goes through the node's own vtable pointer, not a
//!   crate-level hook table, so subclass (and test) vtables work.
//! - Fields are typed struct members, never literal byte offsets: the
//!   32-bit target layout is exact (asserted in `layout_checks`) while a
//!   64-bit host keeps the fields disjoint.

/// The node's vtable, modeled down to the one slot this walk
/// dispatches (+0x68).
#[repr(C)]
pub struct NodeVtable {
    /// Slots +0x00..+0x64: not dispatched here.
    pub unresolved: [usize; 26],
    /// Slot +0x68: the node's key, compared against the list's stop key.
    pub key: unsafe extern "C" fn(this: *mut Node) -> u32,
}

/// A list node, modeled down to its vtable pointer and its link.
#[repr(C)]
pub struct Node {
    /// +0x00: the node's vtable.
    pub vtable: *const NodeVtable,
    /// +0x04..+0x13: not read by this walk.
    pub opaque: [u32; 4],
    /// +0x14: next node, NULL at the end.
    pub next: *mut Node,
}

/// The list object (the singleton @ 0x08a79c74 on device).
#[repr(C)]
pub struct NodeList {
    /// +0x00: the list's own vtable — dispatched by the drain function
    /// @ 0x0810fb48, never here.
    pub vtable: *const u8,
    /// +0x04: first node.
    pub head: *mut Node,
    /// +0x08: stop key; 0 means "count everything".
    pub stop_key: u32,
}

// Target-exact layout.
#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _: [u8; 0x68] = [0; core::mem::offset_of!(NodeVtable, key)];
    const _: [u8; 0x04] = [0; core::mem::offset_of!(Node, opaque)];
    const _: [u8; 0x14] = [0; core::mem::offset_of!(Node, next)];
    const _: [u8; 0x04] = [0; core::mem::offset_of!(NodeList, head)];
    const _: [u8; 0x08] = [0; core::mem::offset_of!(NodeList, stop_key)];
    const _: [u8; NODE_LIST_SIZE] = [0; core::mem::size_of::<NodeListStorage>()];
}

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// Byte size of the singleton object on target (original: the .bss
/// object @ 0x08a79c74). [`node_list_construct`] writes all fields
/// except the untouched word at +0x24: the [`NodeList`] header
/// (+0x00..+0x0b), the draining flag byte (+0x0c), an embedded
/// sub-object (+0x10), and the drain-callback words (+0x20, +0x28,
/// +0x2c) used by the drain @ 0x0810fb48.
pub const NODE_LIST_SIZE: usize = 0x30;

/// `__dso_handle` — the same literal @ 0x089ca09c every ADS
/// static-initialization site passes to `cxa_atexit` (here: pool word @
/// 0x0810fa80). See runtime/shutdown_chain.rs.
const DSO_HANDLE: i32 = 0x089ca09c;

/// The singleton's storage (original: the fixed object @ 0x08a79c74 in
/// .bss — a function-local static, NOT heap-allocated like the
/// singletons.rs objects). The constructor addresses it as a target
/// layout byte block; [`NodeList`] still models the header consumed by
/// the ported list walker.
#[repr(C, align(4))]
struct NodeListStorage {
    /// +0x00: the list header every ported consumer uses.
    list: NodeList,
    /// +0x0c on: the draining flag, the sub-object, and callbacks.
    opaque: [u8; NODE_LIST_SIZE - core::mem::size_of::<NodeList>()],
}

/// The singleton object (original: .bss @ 0x08a79c74; zero-init is the
/// exact pre-init state — the image holds no initializer there).
static mut NODE_LIST: NodeListStorage = NodeListStorage {
    list: NodeList { vtable: core::ptr::null(), head: core::ptr::null_mut(), stop_key: 0 },
    opaque: [0; NODE_LIST_SIZE - core::mem::size_of::<NodeList>()],
};

/// The one-time-initialization guard word (original: the .bss word @
/// 0x089cc834, reached through pool word @ 0x0810fa78).
static mut NODE_LIST_GUARD: u32 = 0;

/// node_list_construct — original: `FUN_0811000c` @ 0x0811000c (52
/// bytes).
///
/// Reference: `ipod-decomp/decomp/c/010/0811000c_FUN_0811000c.c`;
/// the embedded +0x10 sub-object's effects come from
/// `decomp/c/026/08271cec_FUN_08271cec.c` and
/// `decomp/c/026/08275bb8_FUN_08275bb8.c`.
///
/// Installs the list vtable at +0x00, clears its head and stop key,
/// constructs the embedded drain-callback sub-object at +0x10, clears
/// its flag and callback words, and returns `this`. The stock sequence
/// deliberately does not write the word at +0x24, so this port does not
/// turn the constructor into a whole-object zeroing operation.
const NODE_LIST_VTABLE: u32 = 0x0898_165c;
const NODE_LIST_DRAIN_VTABLE: u32 = 0x089a_5d0c;

#[inline(always)]
unsafe fn node_list_store_word(this: *mut u8, offset: usize, value: u32) {
    this.add(offset).cast::<u32>().write_volatile(value);
}

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn node_list_construct(this: *mut u8) -> *mut u8 {
    // `*param_1 = DAT_08110040; param_1[2] = 0`.
    node_list_store_word(this, 0x00, NODE_LIST_VTABLE);
    node_list_store_word(this, 0x08, 0);

    // `FUN_08271cec(param_1 + 4)`, including its
    // `FUN_08275bb8` base-constructor call.
    node_list_store_word(this, 0x10, NODE_LIST_DRAIN_VTABLE);
    node_list_store_word(this, 0x14, 0);
    node_list_store_word(this, 0x18, 0);
    node_list_store_word(this, 0x1c, 0);

    // The caller's stores relative to the returned +0x10 sub-object.
    node_list_store_word(this, 0x28, 0);
    node_list_store_word(this, 0x2c, 0);
    node_list_store_word(this, 0x04, 0);
    this.add(0x0c).write_volatile(0);
    node_list_store_word(this, 0x20, 0);
    this
}

/// The destructor registered with `cxa_atexit` — original: the shared
/// `mov r0, #1; ldmia sp!, {r4, pc}` stub @ 0x0810516c (pool word @
/// 0x0810fa84; binary-verified). That stub is a shared epilogue for
/// functions that return 1 after pushing {r4, lr} — run as a shutdown
/// handler it would pop a frame it never pushed, so the registration
/// could never actually fire; retailOS never runs `exit`'s chain
/// anyway (runtime/shutdown_chain.rs: the sole runner caller is
/// `exit_stdio_cleanup`). A no-op matches every observable path.
unsafe extern "C" fn node_list_destructor(_object: *mut c_void) {}

/// node_list_get — original: `FUN_0810fa30` @ 0x0810fa30 (72 bytes;
/// 168 `bl` call sites, binary-verified).
///
/// The process-wide view-list singleton's accessor — a textbook ADS
/// function-local static over a fixed .bss object, NOT the
/// `operator_new` cache pattern of the singletons.rs getters:
///
/// ```text
/// ldr r0, =0x089cc834      ; pool @ 0x0810fa78: the guard word
/// ldr r0, [r0]; tst r0, #1
/// bne done                 ; inlined fast path: bit 0 = initialized
/// bl  cxa_guard_acquire    ; 0x082ab31c (ported)
/// cmp r0, #0; beq done
/// ldr r0, =0x08a79c74      ; pool @ 0x0810fa7c: the object
/// bl  0x0811000c           ; the constructor, returns `this` in r0
/// ldr r2, =0x089ca09c      ; pool @ 0x0810fa80: __dso_handle
/// ldr r1, =0x0810516c      ; pool @ 0x0810fa84: the "destructor"
/// bl  cxa_atexit           ; 0x082ab1c8 (ported)
/// bl  cxa_guard_release    ; 0x082ab338 (ported)
/// done:
/// ldr r0, =0x08a79c74      ; reloaded — NOT the ctor's return
/// ```
///
/// The guard pair, `cxa_atexit`, and [`node_list_construct`] are
/// ported and called directly.
///
/// Faithful details:
/// - The return value is always the fixed object's address, reloaded
///   after the init block (the original's second
///   `ldr r0, [0x810fa7c]`) — never the constructor's return. The
///   constructor returns that same in-place address, which is registered
///   with `cxa_atexit`.
/// - The inlined fast path tests bit 0 only (`tst r0, #1`) while
///   [`cxa_guard_acquire`] tests the whole word, so a nonzero guard
///   with bit 0 clear (never produced by this pair) takes the slow
///   path and is still turned away. Reproduced.
/// - A refused acquire (a re-entrant initializer) skips construction
///   and still hands out the object half-built — the guard is spent
///   either way. Inherited from the ported guard pair.
///
/// Deviations:
/// - The guard word and the object are crate statics rather than the
///   .bss words @ 0x089cc834 / 0x08a79c74 (the block_mgr.rs deviation:
///   the 0x089cxxxx RW pages are runtime-initialized and the image's
///   contents there are stale). Both zero-init, the exact pre-init
///   state.
/// - The registered destructor is a module-local no-op; see
///   [`node_list_destructor`] for why that is faithful.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn node_list_get() -> *mut NodeList {
    let guard = core::ptr::addr_of_mut!(NODE_LIST_GUARD);
    let object = core::ptr::addr_of_mut!(NODE_LIST) as *mut u8;
    if (core::ptr::read_volatile(guard) & 1) == 0 {
        if cxa_guard_acquire(guard) != 0 {
            let this = node_list_construct(object);
            cxa_atexit(this as *mut c_void, node_list_destructor, DSO_HANDLE);
            cxa_guard_release(guard);
        }
    }
    object as *mut NodeList
}

/// list_count_until_match — original: `FUN_0810fa90` @ 0x0810fa90
/// (84 bytes).
///
/// Returns the 1-based position of the node matching the list's stop
/// key, or the total node count when the key is 0 or unmatched.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn list_count_until_match(list: *mut NodeList) -> u32 {
    let mut node = (*list).head;
    let mut count: u32 = 0;

    while !node.is_null() {
        count = count.wrapping_add(1);
        if (*list).stop_key != 0 {
            let key = ((*(*node).vtable).key)(node);
            // Re-read: the original reloads list + 8 after the call.
            if key == (*list).stop_key {
                break;
            }
        }
        node = (*node).next;
    }
    count
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// A node whose key accessor returns a stored value and records the
    /// call.
    #[repr(C)]
    struct TestNode {
        vtable: *const NodeVtable,
        opaque: [u32; 4],
        next: *mut Node,
        key: u32,
        /// Shared visit log (raw pointer so the node stays `repr(C)`
        /// compatible past the fields the port reads).
        visits: *mut Vec<u32>,
    }

    unsafe extern "C" fn test_key(this: *mut Node) -> u32 {
        let node = this as *mut TestNode;
        (*(*node).visits).push((*node).key);
        (*node).key
    }

    static TEST_VTABLE: NodeVtable = NodeVtable { unresolved: [0; 26], key: test_key };

    fn node(key: u32, visits: *mut Vec<u32>) -> TestNode {
        TestNode {
            vtable: &TEST_VTABLE,
            opaque: [0; 4],
            next: ptr::null_mut(),
            key,
            visits,
        }
    }

    /// Links the nodes head-to-tail and returns the head.
    fn chain(nodes: &mut [TestNode]) -> *mut Node {
        for i in 0..nodes.len() - 1 {
            nodes[i].next = &mut nodes[i + 1] as *mut TestNode as *mut Node;
        }
        &mut nodes[0] as *mut TestNode as *mut Node
    }

    fn list(head: *mut Node, stop_key: u32) -> NodeList {
        NodeList { vtable: ptr::null(), head, stop_key }
    }

    #[test]
    fn an_empty_list_counts_zero_and_dispatches_nothing() {
        let mut visits: Vec<u32> = Vec::new();
        let mut list = list(ptr::null_mut(), 7);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 0);
        assert!(visits.is_empty(), "no node, no dispatch");
        let _ = &mut visits;
    }

    #[test]
    fn a_zero_stop_key_counts_every_node_without_dispatching() {
        let mut visits = Vec::new();
        let mut nodes = [node(1, &mut visits), node(2, &mut visits), node(3, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 0);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 3);
        assert!(visits.is_empty(), "a zero key short-circuits before the vtable call");
    }

    #[test]
    fn the_matching_node_is_counted_and_the_walk_stops_there() {
        let mut visits = Vec::new();
        let mut nodes =
            [node(10, &mut visits), node(20, &mut visits), node(30, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 20);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 2, "1-based position");
        assert_eq!(visits, std::vec![10, 20], "the third node is never asked");
    }

    #[test]
    fn the_head_matching_returns_one() {
        let mut visits = Vec::new();
        let mut nodes = [node(5, &mut visits), node(6, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 5);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 1);
        assert_eq!(visits, std::vec![5]);
    }

    #[test]
    fn an_unmatched_key_falls_through_to_the_full_count() {
        let mut visits = Vec::new();
        let mut nodes = [node(1, &mut visits), node(2, &mut visits), node(3, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 99);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 3);
        assert_eq!(visits, std::vec![1, 2, 3], "every node is asked");
    }

    #[test]
    fn a_single_node_list_counts_one_either_way() {
        let mut visits = Vec::new();
        let mut nodes = [node(4, &mut visits)];
        let head = chain_single(&mut nodes);
        let mut with_key = list(head, 4);
        assert_eq!(unsafe { list_count_until_match(&mut with_key) }, 1);
        let mut without = list(head, 0);
        assert_eq!(unsafe { list_count_until_match(&mut without) }, 1);
    }

    /// `chain` needs at least two nodes; this is the one-node case.
    fn chain_single(nodes: &mut [TestNode; 1]) -> *mut Node {
        &mut nodes[0] as *mut TestNode as *mut Node
    }

    #[test]
    fn a_key_accessor_that_clears_the_stop_key_ends_the_matching() {
        // The original reloads list + 8 after the call, so a callee
        // that rewrites the key is honored on the very same iteration.
        static mut LIST_UNDER_TEST: *mut NodeList = ptr::null_mut();

        unsafe extern "C" fn clearing_key(this: *mut Node) -> u32 {
            let node = this as *mut TestNode;
            (*(*node).visits).push((*node).key);
            (*(*core::ptr::addr_of!(LIST_UNDER_TEST))).stop_key = 0;
            (*node).key
        }
        static CLEARING_VTABLE: NodeVtable =
            NodeVtable { unresolved: [0; 26], key: clearing_key };

        let mut visits = Vec::new();
        let mut nodes = [node(8, &mut visits), node(9, &mut visits)];
        nodes[0].vtable = &CLEARING_VTABLE;
        nodes[1].vtable = &CLEARING_VTABLE;
        let head = chain(&mut nodes);
        let mut list = list(head, 8);
        unsafe {
            LIST_UNDER_TEST = &mut list;
            // The first node's key is 8 and would have matched, but the
            // accessor zeroed the stop key first, so the reload sees 0.
            assert_eq!(list_count_until_match(&mut list), 2);
        }
        assert_eq!(visits, std::vec![8], "the second node skips the call: key is now 0");
    }

    // --- node_list_get: the function-local-static accessor ---

    /// Serializes the tests below: the guard word, storage, and
    /// process-wide shutdown chain are all global.
    static GETTER_LOCK: Mutex<()> = Mutex::new(());


    /// Box-backed node allocator pair for the shutdown chain (the
    /// shipped defaults are the firmware malloc/free, wrong for host
    /// memory — the shutdown_chain.rs test pattern).
    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: node_list_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(ptr: *mut u8) {
        drop(Box::from_raw(ptr as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(NODE_LIST) as *mut u8
    }

    fn word_at(block: *const u8, offset: usize) -> u32 {
        unsafe { ptr::read_unaligned(block.add(offset).cast::<u32>()) }
    }

    /// Installs the Box allocator pair and resets the guard, storage,
    /// and chain to their pre-init state.
    fn reset_getter() -> MutexGuard<'static, ()> {
        let guard = GETTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            NODE_LIST_GUARD = 0;
            let block = storage();
            for offset in 0..core::mem::size_of::<NodeListStorage>() {
                block.add(offset).write(0xa5);
            }
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = ptr::null_mut();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            // Drain leftover registrations BEFORE restoring the
            // firmware allocator pair, so the nodes are freed by the
            // allocator that made them.
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            NODE_LIST_GUARD = 0;
        }
        drop(guard);
    }

    #[test]
    fn the_first_call_constructs_registers_and_caches() {
        let guard = reset_getter();
        unsafe {
            assert_eq!(node_list_get(), storage() as *mut NodeList);
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(NODE_LIST_GUARD)),
                1,
                "acquire published the flag"
            );
            assert_eq!(word_at(storage(), 0x00), NODE_LIST_VTABLE);
            assert_eq!(word_at(storage(), 0x04), 0);
            assert_eq!(word_at(storage(), 0x08), 0);

            // Exactly one registration: the object, the shared-stub
            // destructor, the __dso_handle key.
            let head = *shutdown_chain_head();
            assert!(!head.is_null(), "the ctor's return was registered");
            assert_eq!((*head).arg as *mut u8, storage());
            assert_eq!((*head).handler as usize, node_list_destructor as usize);
            assert_eq!((*head).key, DSO_HANDLE, "__dso_handle @ 0x089ca09c");
            assert!((*head).next.is_null(), "registered exactly once");

            // The second call takes the bit-0 fast path, preserving a
            // post-construction mutation rather than reconstructing.
            node_list_store_word(storage(), 0x08, 0xfeed_beef);
            assert_eq!(node_list_get(), storage() as *mut NodeList);
            assert_eq!(word_at(storage(), 0x08), 0xfeed_beef, "no reconstruction");
            assert!((*(*shutdown_chain_head())).next.is_null(), "no second registration");
        }
        restore(guard);
    }

    #[test]
    fn a_guard_with_bit0_set_short_circuits_everything() {
        let guard = reset_getter();
        unsafe {
            NODE_LIST_GUARD = 3; // bit 0 set: `tst r0, #1` -> bne done
            assert_eq!(node_list_get(), storage() as *mut NodeList);
            assert_eq!(word_at(storage(), 0x00), 0xa5a5_a5a5, "no construction");
            assert!(shutdown_chain_head().read().is_null(), "no registration");
            assert_eq!(ptr::read_volatile(ptr::addr_of!(NODE_LIST_GUARD)), 3, "untouched");
        }
        restore(guard);
    }

    #[test]
    fn a_nonzero_guard_with_bit0_clear_is_still_turned_away_by_acquire() {
        // The fast path tests bit 0, cxa_guard_acquire the whole word:
        // this state is never produced by the guard pair, but the
        // original's two-level test defines its behavior.
        let guard = reset_getter();
        unsafe {
            NODE_LIST_GUARD = 2;
            assert_eq!(node_list_get(), storage() as *mut NodeList);
            assert_eq!(word_at(storage(), 0x00), 0xa5a5_a5a5, "acquire refused: no construction");
            assert_eq!(ptr::read_volatile(ptr::addr_of!(NODE_LIST_GUARD)), 2, "a refused acquire never writes");
        }
        restore(guard);
    }


    #[test]
    fn the_registration_is_real_and_the_chain_runs_the_noop_destructor() {
        let guard = reset_getter();
        unsafe {
            node_list_get();
            node_list_store_word(storage(), 0x08, 0xa5a5_a5a5);
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null(), "the node ran and was freed");
            assert_eq!(word_at(storage(), 0x08), 0xa5a5_a5a5, "the no-op destructor touched nothing");
        }
        restore(guard);
    }

    #[test]
    fn constructor_writes_only_the_stock_fields_and_returns_this() {
        #[repr(align(4))]
        struct AlignedBlock([u8; NODE_LIST_SIZE]);

        let _guard = GETTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut block = AlignedBlock([0xa5; NODE_LIST_SIZE]);
            let this = block.0.as_mut_ptr();
            assert_eq!(node_list_construct(this), this);
            assert_eq!(word_at(this, 0x00), NODE_LIST_VTABLE);
            assert_eq!(word_at(this, 0x04), 0);
            assert_eq!(word_at(this, 0x08), 0);
            assert_eq!(block.0[0x0c], 0);
            assert_eq!(&block.0[0x0d..0x10], &[0xa5; 3], "only the flag byte is cleared");
            assert_eq!(word_at(this, 0x10), NODE_LIST_DRAIN_VTABLE);
            for offset in [0x14, 0x18, 0x1c, 0x20, 0x28, 0x2c] {
                assert_eq!(word_at(this, offset), 0, "word at +{offset:#x}");
            }
            assert_eq!(&block.0[0x24..0x28], &[0xa5; 4], "+0x24 is untouched");
        }
    }
}
