//! Port of the block-manager event notification wrapper.
//!
//! `manager_event_notify` — original: `FUN_0818a3b4` @ 0x0818a3b4 (52
//! bytes; 3 plain `bl` instructions and one predicated `bleq`, with four
//! inbound plain `bl` call sites). It allocates a 12-byte event node, invokes
//! its two-argument constructor, panics on a NULL constructor result, then
//! tail-transfers to the manager queue operation with `manager + 0x3c`.
//!
//! # Deliberate deviations
//!
//! The node constructor @ 0x0820768c and queue operation @ 0x08261998 remain
//! unported. They are explicit, target-addressed seams rather than guessed
//! identities. Rust makes the tail transfer a normal call; allocation uses the
//! existing `operator_new` port instead of branching to its retailOS address.

use crate::heap::veneers::{heap_panic, operator_new};

/// Target-addressed boundaries required by `manager_event_notify`.
#[derive(Clone, Copy)]
pub struct ManagerNotificationOps {
    /// Event-node constructor @ 0x0820768c `(storage, event)`.
    pub construct_event_node: unsafe extern "C" fn(storage: *mut u8, event: u32) -> *mut u8,
    /// Queue operation @ 0x08261998 `(manager + 0x3c, node)`.
    pub enqueue_event_node: unsafe extern "C" fn(queue: *mut u8, node: *mut u8) -> i32,
}

unsafe extern "C" fn missing_event_node_constructor(storage: *mut u8, _event: u32) -> *mut u8 {
    storage
}

unsafe extern "C" fn missing_event_enqueue(_queue: *mut u8, _node: *mut u8) -> i32 { 0x14 }

/// Wired defaults preserve the failure code returned by the unported queue
/// boundary while keeping the constructor storage identity intact.
pub const DEFAULT_MANAGER_NOTIFICATION_OPS: ManagerNotificationOps = ManagerNotificationOps {
    construct_event_node: missing_event_node_constructor,
    enqueue_event_node: missing_event_enqueue,
};

/// Active event-node boundaries. Target initialization may replace these;
/// host tests install recorders and restore the defaults.
pub static mut MANAGER_NOTIFICATION_OPS: ManagerNotificationOps = DEFAULT_MANAGER_NOTIFICATION_OPS;

#[inline(always)]
fn notification_ops() -> ManagerNotificationOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MANAGER_NOTIFICATION_OPS)) }
}

/// manager_event_notify — original: `FUN_0818a3b4` @ 0x0818a3b4 (52 bytes).
///
/// Builds an event node for `event`, then queues it through the manager's
/// queue object at byte offset `0x3c`. A NULL constructor result is fatal,
/// exactly as the raw `cmp r0,#0; bleq heap_panic` sequence requires.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn manager_event_notify(manager: *mut u8, event: u32) -> i32 {
    let storage = operator_new(12);
    let node = (notification_ops().construct_event_node)(storage, event);
    if node.is_null() {
        heap_panic();
    }
    (notification_ops().enqueue_event_node)(manager.add(0x3c), node)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::{HeapVeneerOps, DEFAULT_HEAP_OPS, HEAP_OPS};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut NODE: [u8; 12] = [0; 12];
    static mut CONSTRUCT_EVENT: u32 = 0;
    static mut ENQUEUED_QUEUE: *mut u8 = core::ptr::null_mut();
    static mut ENQUEUED_NODE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn alloc(_heap: *mut crate::heap::types::HeapDescriptorDescriptor, size: usize, tag: usize) -> *mut u8 {
        assert_eq!((size, tag), (12, 2));
        core::ptr::addr_of_mut!(NODE).cast()
    }
    unsafe extern "C" fn construct(node: *mut u8, event: u32) -> *mut u8 {
        CONSTRUCT_EVENT = event;
        node
    }
    unsafe extern "C" fn enqueue(queue: *mut u8, node: *mut u8) -> i32 {
        ENQUEUED_QUEUE = queue;
        ENQUEUED_NODE = node;
        7
    }

    #[test]
    fn allocates_constructs_and_enqueues_at_manager_queue_offset() {
        let _guard = LOCK.lock();
        unsafe {
            let old_heap: HeapVeneerOps = HEAP_OPS;
            let old_ops = MANAGER_NOTIFICATION_OPS;
            let mut heap = DEFAULT_HEAP_OPS;
            heap.alloc = alloc;
            HEAP_OPS = heap;
            MANAGER_NOTIFICATION_OPS = ManagerNotificationOps { construct_event_node: construct, enqueue_event_node: enqueue };
            let mut manager = [0_u8; 0x3c];
            assert_eq!(manager_event_notify(manager.as_mut_ptr(), 10), 7);
            assert_eq!(CONSTRUCT_EVENT, 10);
            assert_eq!(ENQUEUED_QUEUE, manager.as_mut_ptr().add(0x3c));
            assert_eq!(ENQUEUED_NODE, core::ptr::addr_of_mut!(NODE).cast());
            HEAP_OPS = old_heap;
            MANAGER_NOTIFICATION_OPS = old_ops;
        }
    }
}
