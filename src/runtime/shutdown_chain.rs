//! The ADS libspace shutdown-handler chain runner.
//!
//! Port:
//! - `lib_shutdown_chain` @ 0x082ab2b0 (108 bytes) — walks the handler
//!   node list hanging off libspace+0x38 (nodes `{next, arg, fn, key}`,
//!   heap-allocated). With `key == 0` every node matches; with a nonzero
//!   `key` only nodes whose key word equals it. Each matching node is
//!   UNLINKED first, then its `fn(arg)` runs, then the node is freed
//!   (`free` @ 0x0802edc8). The head word is snapshotted after the
//!   unlink and re-read after the free: if a handler re-registered (the
//!   head changed), the scan RESTARTS from the head; otherwise it
//!   continues from the same predecessor link. Sole caller in the image
//!   (binary-verified bl scan): `exit_stdio_cleanup` @ 0x08035878, with
//!   key 0 — the keyed removal path is dead in retailOS (nothing in the
//!   image registers or removes by key), but is ported faithfully.
//!   `stream_file.rs`'s `LIB_SHUTDOWN_CHAIN` hook defaults to this port.
//!
//! The registration counterpart (whatever pushes nodes onto
//! libspace+0x38) is not identified in the image; the head cell is
//! exposed via [`shutdown_chain_head`] for a future port and for tests.
//!
//! Deviations:
//! - The chain head lives at libspace+0x38 in the original (one of
//!   errno.rs's `Libspace` reserved words). The committed libspace model
//!   keeps its words as raw `u32`s, which cannot hold host pointers, so
//!   the head is modeled as this module's own pointer-width static —
//!   the same modeling deviation as locale.rs's `LC_SLOTS`.
//! - The node free goes through the module-local [`SHUTDOWN_FREE`] slot,
//!   which DEFAULTS to the ported `free` (malloc_rt.rs) — the firmware
//!   build links the original call graph — so host tests can substitute
//!   an allocator-appropriate free without racing other modules' hook
//!   swaps (house precedent: stream_file.rs's `STDIO_ALLOC`/`STDIO_FREE`).
//! - Ghidra renders the handler call (`mov pc, r1` with `adr lr`) as
//!   `(fn & 0xfffffffc)(arg)`; the firmware is pure ARM, so the
//!   Thumb-bit mask is omitted (house precedent: printf hooks).

use core::ffi::c_void;

/// A registered shutdown handler: called with the node's `arg` word.
pub type ShutdownHandlerFn = unsafe extern "C" fn(arg: *mut c_void);

/// One heap-allocated handler node (16 bytes on target). Offsets pinned
/// by the layout test below; `next` sitting at +0 is load-bearing — the
/// walker advances its predecessor link to the node itself
/// (`mov r5, r4`), i.e. to the node's own `next` field.
#[repr(C)]
pub struct ShutdownNode {
    /// +0x00: next node in the chain (null-terminated).
    pub next: *mut ShutdownNode,
    /// +0x04: opaque argument passed to `handler`.
    pub arg: *mut c_void,
    /// +0x08: the handler function.
    pub handler: ShutdownHandlerFn,
    /// +0x0c: registration key, matched against a nonzero `key` argument.
    pub key: i32,
}

/// See [`FreeFn`] in stream_file.rs — same shape, module-local slot.
pub type FreeFn = unsafe extern "C" fn(ptr: *mut u8);

/// Node-free boundary; defaults to the ported `free` @ 0x0802edc8.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut SHUTDOWN_FREE: FreeFn = crate::malloc_rt::free;

/// The chain head — original: the word at libspace+0x38 (see the module
/// deviations for why it is a module static here).
static mut SHUTDOWN_CHAIN_HEAD: *mut ShutdownNode = core::ptr::null_mut();

/// Address of the chain-head cell (original: libspace+0x38). The future
/// registration port pushes nodes through this; tests seed chains here.
pub fn shutdown_chain_head() -> *mut *mut ShutdownNode {
    unsafe { core::ptr::addr_of_mut!(SHUTDOWN_CHAIN_HEAD) }
}

/// Reads a hook slot. Volatile so a build in which nothing rewrites the
/// slot does not constant-fold the default in and delete the dispatch.
#[inline(always)]
fn hook<T: Copy>(slot: *const T) -> T {
    unsafe { core::ptr::read_volatile(slot) }
}

/// lib_shutdown_chain — original @ 0x082ab2b0 (108 bytes).
///
/// Runs (and removes) shutdown handlers from the libspace+0x38 chain:
/// every node when `key` is 0, only key-matching nodes otherwise. Per
/// matching node, in the original's exact order: unlink, snapshot the
/// head word, call `handler(arg)`, free the node, then re-read the head
/// — a changed head (a handler re-registered) restarts the scan from
/// the head, an unchanged one continues from the same predecessor.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lib_shutdown_chain(key: i32) {
    let head = shutdown_chain_head();
    let free = hook(core::ptr::addr_of!(SHUTDOWN_FREE));
    let mut prev = head;
    loop {
        let node = *prev;
        if node.is_null() {
            return;
        }
        if key != 0 && (*node).key != key {
            // `mov r5, r4`: the node's `next` field (+0) becomes the
            // predecessor link.
            prev = core::ptr::addr_of_mut!((*node).next);
            continue;
        }
        *prev = (*node).next;
        // Original: `ldr r7, [libspace, #0x38]` AFTER the unlink store,
        // BEFORE the handler call.
        let snapshot = *head;
        ((*node).handler)((*node).arg);
        free(node as *mut u8);
        if *head != snapshot {
            prev = head;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests: the chain head, free slot and event log are
    /// process-global.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Event log: ("run", handler tag) / ("free", node address).
    static mut EVENTS: Vec<(&'static str, usize)> = Vec::new();

    fn events() -> Vec<(&'static str, usize)> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    unsafe extern "C" fn logging_handler(arg: *mut c_void) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(("run", arg as usize));
    }

    /// Frees the Box-allocated test nodes for real (the shipped default
    /// is the firmware allocator's `free`, wrong for Box memory).
    unsafe extern "C" fn box_free(ptr: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(("free", ptr as usize));
        drop(Box::from_raw(ptr as *mut ShutdownNode));
    }

    fn lock_and_reset() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            *shutdown_chain_head() = core::ptr::null_mut();
            SHUTDOWN_FREE = box_free;
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
        }
        guard
    }

    /// Pushes a fresh node onto the chain head (LIFO, like a plausible
    /// register function) and returns its address.
    unsafe fn push_node(handler: ShutdownHandlerFn, tag: usize, key: i32) -> usize {
        let node = Box::into_raw(Box::new(ShutdownNode {
            next: *shutdown_chain_head(),
            arg: tag as *mut c_void,
            handler,
            key,
        }));
        *shutdown_chain_head() = node;
        node as usize
    }

    #[test]
    fn key_zero_runs_and_frees_every_node_in_list_order() {
        let _guard = lock_and_reset();
        unsafe {
            // Pushed LIFO: list order is 3, 2, 1.
            push_node(logging_handler, 1, 10);
            push_node(logging_handler, 2, 20);
            let n3 = push_node(logging_handler, 3, 30);
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null(), "chain drained");
            let ev = events();
            // Per node: run then free; nodes in list order (head first).
            assert_eq!(ev[0], ("run", 3));
            assert_eq!(ev[1], ("free", n3));
            assert_eq!(
                ev.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
                std::vec!["run", "free", "run", "free", "run", "free"]
            );
            assert_eq!(
                ev.iter()
                    .filter(|(k, _)| *k == "run")
                    .map(|(_, t)| *t)
                    .collect::<Vec<_>>(),
                std::vec![3, 2, 1]
            );
        }
    }

    #[test]
    fn empty_chain_is_a_no_op() {
        let _guard = lock_and_reset();
        unsafe {
            lib_shutdown_chain(0);
            lib_shutdown_chain(7);
        }
        assert!(events().is_empty());
    }

    #[test]
    fn node_is_unlinked_before_its_handler_runs() {
        let _guard = lock_and_reset();
        /// Records what the chain head pointed at while the handler ran.
        unsafe extern "C" fn head_probe(_arg: *mut c_void) {
            let head = *shutdown_chain_head();
            (*core::ptr::addr_of_mut!(EVENTS)).push(("head_during", head as usize));
        }
        unsafe {
            let n1 = push_node(logging_handler, 1, 0);
            push_node(head_probe, 2, 0);
            lib_shutdown_chain(0);
            // While the head node's handler ran, the head was already its
            // successor (the original stores the unlink before the call).
            assert_eq!(events()[0], ("head_during", n1));
        }
    }

    #[test]
    fn nonzero_key_runs_only_matching_nodes_and_keeps_the_rest() {
        let _guard = lock_and_reset();
        unsafe {
            // List order after LIFO pushes: (3,key1) (2,key2) (1,key1).
            push_node(logging_handler, 1, 1);
            let keep = push_node(logging_handler, 2, 2);
            push_node(logging_handler, 3, 1);
            lib_shutdown_chain(1);
            let ev = events();
            assert_eq!(
                ev.iter()
                    .filter(|(k, _)| *k == "run")
                    .map(|(_, t)| *t)
                    .collect::<Vec<_>>(),
                std::vec![3, 1],
                "only key-1 nodes ran, in list order"
            );
            // The key-2 node survives as the whole chain.
            let head = *shutdown_chain_head();
            assert_eq!(head as usize, keep);
            assert!((*head).next.is_null());
            // Drain it so the test does not leak.
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null());
        }
    }

    #[test]
    fn key_matching_no_node_leaves_the_chain_intact() {
        let _guard = lock_and_reset();
        unsafe {
            push_node(logging_handler, 1, 5);
            let n2 = push_node(logging_handler, 2, 6);
            lib_shutdown_chain(99);
            assert!(events().is_empty(), "nothing ran");
            assert_eq!(*shutdown_chain_head() as usize, n2, "chain untouched");
            lib_shutdown_chain(0); // drain
        }
    }

    #[test]
    fn handler_reregistering_restarts_the_scan_and_runs_the_new_node() {
        let _guard = lock_and_reset();
        /// Pushes a fresh (plain) node onto the head mid-walk.
        unsafe extern "C" fn reregistering_handler(arg: *mut c_void) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(("run", arg as usize));
            push_node(logging_handler, 9, 0);
        }
        unsafe {
            push_node(logging_handler, 1, 0);
            push_node(reregistering_handler, 2, 0);
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null(), "chain drained");
            assert_eq!(
                events()
                    .iter()
                    .filter(|(k, _)| *k == "run")
                    .map(|(_, t)| *t)
                    .collect::<Vec<_>>(),
                std::vec![2, 9, 1],
                "head changed -> restart from head: new node 9 runs before 1"
            );
        }
    }

    /// Raw offsets only hold on the 32-bit ARM target (pointer fields
    /// widen on hosts); all access is by field name.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn node_layout_matches_original() {
        assert_eq!(core::mem::size_of::<ShutdownNode>(), 0x10);
        assert_eq!(core::mem::offset_of!(ShutdownNode, next), 0x00);
        assert_eq!(core::mem::offset_of!(ShutdownNode, arg), 0x04);
        assert_eq!(core::mem::offset_of!(ShutdownNode, handler), 0x08);
        assert_eq!(core::mem::offset_of!(ShutdownNode, key), 0x0c);
    }
}
