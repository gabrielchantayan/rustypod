//! Message-queue node delivery — the consumer-side accept step of the
//! locked message queues drained by `mqueue_receive` (kernel/condvar.rs).
//!
//! - `mqueue_deliver` — original: `FUN_080b4a88` @ 0x080b4a88 (84 bytes;
//!   2 call sites: `mqueue_receive` @ 0x0807f63c and the wrapper loop @
//!   0x0807a330). Takes a node popped off a queue and decides what the
//!   consumer sees:
//!
//!   ```text
//!   if !node->valid      { *out_node = 0; recycle(node); return 0 }
//!   out_data[0] = node->data[0]; out_data[1] = node->data[1];
//!   if node->persistent  { *out_node = node }
//!   else                 { *out_node = 0; recycle(node) }
//!   return 1
//!   ```
//!
//!   `recycle` is `FUN_080ed958` @ 0x080ed958 (not yet ported): under the
//!   owner's lock it pushes the node back onto the owner's free list
//!   (`list_push_back` on owner+5) and signals the owner's semaphores —
//!   the node pool's return path. It NULL-guards its argument itself; this
//!   function performs NO NULL check on `node` before the `valid` load
//!   (faithful — a NULL node faults exactly like the original would).
//!
//! # Layout note
//!
//! The node's linkage word (+0) is the intrusive `ListNode` of
//! kernel/condvar.rs; +4 holds the owner-pool pointer consumed by the
//! recycle helper. Byte offsets are exact on the 32-bit target only; host
//! tests go through field accesses (same caveat as condvar.rs).
//!
//! # Dispatch design
//!
//! The recycle helper is the single unported callee and routes through
//! `MQUEUE_HOOKS` (house pattern; default: no-op — without a node pool
//! there is nothing to return the node to). `read_volatile` prevents LLVM
//! from constant-folding the stub (see sync_sem.rs).
//!
//! Wiring note for condvar.rs: `CONDVAR_HOOKS.deliver` (stock 0x080b4a88)
//! is this function — install it there when the kernel modules get wired;
//! the hook types the node as `*mut ListNode`, cast at install time.

/// Message-queue node (only the fields this function touches are named;
/// original stride unknown here — nodes come from the owner's pool).
#[repr(C)]
pub struct QueueNode {
    /// +0x00: intrusive list linkage (condvar.rs `ListNode`).
    pub next: *mut QueueNode,
    /// +0x04: owner pool descriptor, consumed by the recycle helper.
    pub owner: *mut u32,
    /// +0x08: the 8-byte message payload delivered to the consumer.
    pub data: [u32; 2],
    /// +0x10: nonzero when the node carries a message.
    pub valid: u8,
    /// +0x11: nonzero when the node survives delivery (the consumer gets
    /// the node itself and returns it later); zero -> recycled here.
    pub persistent: u8,
}

/// External services this module depends on.
#[derive(Clone, Copy)]
pub struct MqueueHooks {
    /// Stock 0x080ed958: return a node to its owner pool under the
    /// owner's lock (NULL-safe in the original).
    pub node_recycle: unsafe extern "C" fn(node: *mut QueueNode),
}

/// Default stub: no node pool, nothing to return the node to.
unsafe extern "C" fn missing_node_recycle(_node: *mut QueueNode) {}

/// The active hook table. Written once at init on target; host tests
/// serialize access.
pub static mut MQUEUE_HOOKS: MqueueHooks = MqueueHooks {
    node_recycle: missing_node_recycle,
};

/// Reads the hook table (volatile — see the module header).
#[inline(always)]
fn hooks() -> MqueueHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MQUEUE_HOOKS)) }
}

/// mqueue_deliver — original: `FUN_080b4a88` @ 0x080b4a88 (84 bytes).
///
/// Delivers a popped queue node: copies the payload to `out_data`, hands
/// the node itself to the consumer through `*out_node` when it is
/// persistent (recycling it otherwise), and returns 1. An invalid node
/// is recycled without touching `out_data` and returns 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mqueue_deliver(
    node: *mut QueueNode,
    out_data: *mut u32,
    out_node: *mut *mut QueueNode,
) -> u32 {
    if (*node).valid == 0 {
        *out_node = core::ptr::null_mut();
        (hooks().node_recycle)(node);
        return 0;
    }
    *out_data = (*node).data[0];
    *out_data.add(1) = (*node).data[1];
    if (*node).persistent != 0 {
        *out_node = node;
    } else {
        *out_node = core::ptr::null_mut();
        (hooks().node_recycle)(node);
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::null_mut;
    use std::sync::{Mutex, MutexGuard};
    use std::vec;
    use std::vec::Vec;

    /// Serializes tests that swap the global hook table.
    static HOOKS_LOCK: Mutex<()> = Mutex::new(());

    static RECYCLED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn mock_recycle(node: *mut QueueNode) {
        RECYCLED.lock().unwrap().push(node as usize);
    }

    fn mock_hooks() -> MutexGuard<'static, ()> {
        let guard = HOOKS_LOCK.lock().unwrap();
        unsafe {
            core::ptr::addr_of_mut!(MQUEUE_HOOKS).write(MqueueHooks {
                node_recycle: mock_recycle,
            });
        }
        RECYCLED.lock().unwrap().clear();
        guard
    }

    fn drain_recycled() -> Vec<usize> {
        core::mem::take(&mut *RECYCLED.lock().unwrap())
    }

    fn node(valid: u8, persistent: u8) -> QueueNode {
        QueueNode {
            next: null_mut(),
            owner: null_mut(),
            data: [0x1111_2222, 0x3333_4444],
            valid,
            persistent,
        }
    }

    #[test]
    fn persistent_node_is_handed_to_the_consumer() {
        let _guard = mock_hooks();
        let mut n = node(1, 1);
        let mut data = [0u32; 2];
        let mut out: *mut QueueNode = null_mut();
        let r = unsafe { mqueue_deliver(&mut n, data.as_mut_ptr(), &mut out) };
        assert_eq!(r, 1);
        assert_eq!(data, [0x1111_2222, 0x3333_4444]);
        assert_eq!(out, &mut n as *mut QueueNode, "consumer owns the node");
        assert!(drain_recycled().is_empty(), "persistent nodes are not recycled");
    }

    #[test]
    fn transient_node_is_recycled_after_the_copy() {
        let _guard = mock_hooks();
        let mut n = node(1, 0);
        let mut data = [0u32; 2];
        let mut out: *mut QueueNode = &mut n;
        let r = unsafe { mqueue_deliver(&mut n, data.as_mut_ptr(), &mut out) };
        assert_eq!(r, 1, "the payload was still delivered");
        assert_eq!(data, [0x1111_2222, 0x3333_4444]);
        assert!(out.is_null(), "consumer does not get a transient node");
        assert_eq!(drain_recycled(), vec![&mut n as *mut QueueNode as usize]);
    }

    #[test]
    fn invalid_node_is_recycled_without_touching_the_payload() {
        let _guard = mock_hooks();
        let mut n = node(0, 1);
        let mut data = [0xaaaa_aaaa_u32; 2];
        let mut out: *mut QueueNode = &mut n;
        let r = unsafe { mqueue_deliver(&mut n, data.as_mut_ptr(), &mut out) };
        assert_eq!(r, 0);
        assert_eq!(data, [0xaaaa_aaaa; 2], "out_data untouched on the empty path");
        assert!(out.is_null());
        assert_eq!(drain_recycled(), vec![&mut n as *mut QueueNode as usize]);
    }

    #[test]
    fn flag_bytes_are_tested_as_bytes() {
        // Any nonzero byte counts (the original uses ldrb + cmp #0).
        let _guard = mock_hooks();
        let mut n = node(0x80, 0xff);
        let mut data = [0u32; 2];
        let mut out: *mut QueueNode = null_mut();
        let r = unsafe { mqueue_deliver(&mut n, data.as_mut_ptr(), &mut out) };
        assert_eq!(r, 1);
        assert_eq!(out, &mut n as *mut QueueNode);
    }
}
