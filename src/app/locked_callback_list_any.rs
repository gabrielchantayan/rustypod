//! `locked_callback_list_any` — original: `FUN_080a6c0c` @ `0x080a6c0c`.
//!
//! Raw ARM establishes a 108-byte body, `0x080a6c0c..0x080a6c77`; the next
//! separately linked function starts at `0x080a6c78`. The body issues two
//! plain `bl` calls (`sem_wait` and `sem_signal`) and one predicated `blxne`
//! through its callback argument. It waits on the list semaphore at `+0x2c`,
//! walks the inclusive `+0x40` head through `+0x44` tail chain, and calls the
//! predicate only for nodes whose byte at `+0x10` is nonzero. It returns one
//! on the first nonzero predicate result, otherwise zero, after signaling.
//!
//! Deliberate deviation: none. The semaphores are the already-ported
//! [`crate::kernel::sync_sem`] wrappers; the predicate remains an opaque ABI
//! callback, exactly as the conditional `blx` does in retailOS.

use crate::kernel::sync_sem::{sem_signal, sem_wait, SemHandle};

/// Target-width layout of the callback list fields reached by this routine.
#[repr(C)]
pub struct LockedCallbackList {
    _unknown_00: [u32; 11],
    semaphore: u32,
    _unknown_30: [u32; 4],
    head: u32,
    tail: u32,
}

const _: () = assert!(core::mem::size_of::<LockedCallbackList>() == 0x48);
const _: [u8; 0x2c] = [0; core::mem::offset_of!(LockedCallbackList, semaphore)];
const _: [u8; 0x40] = [0; core::mem::offset_of!(LockedCallbackList, head)];
const _: [u8; 0x44] = [0; core::mem::offset_of!(LockedCallbackList, tail)];

/// Target-width node fields observed by this walk. Other node fields are
/// owned by the callback-list implementation.
#[repr(C)]
pub struct LockedCallbackNode {
    next: u32,
    _unknown_04: [u32; 3],
    active: u8,
}

const _: () = assert!(core::mem::size_of::<LockedCallbackNode>() == 0x14);
const _: [u8; 0x10] = [0; core::mem::offset_of!(LockedCallbackNode, active)];

/// Callback ABI at the predicated `blxne r6`: `(node, context) -> nonzero`.
pub type LockedCallbackPredicate = unsafe extern "C" fn(*mut LockedCallbackNode, u32) -> u32;

/// Calls `predicate` for active nodes until it reports a match.
///
/// # Safety
/// `list` must point to the retail target-width layout. Its semaphore slot and
/// every node from `head` through the inclusive `tail` must remain valid; each
/// nonzero `next` word is a valid target pointer. `predicate` must accept the
/// node layout and context word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn locked_callback_list_any(
    list: *mut LockedCallbackList,
    predicate: LockedCallbackPredicate,
    context: u32,
) -> u32 {
    sem_wait((*list).semaphore as usize as SemHandle);

    let mut node = (*list).head as usize as *mut LockedCallbackNode;
    let mut matched = 0;
    if !node.is_null() {
        loop {
            if core::ptr::read_volatile(core::ptr::addr_of!((*node).active)) != 0 {
                matched = predicate(node, context);
            }
            if matched != 0 || node as usize as u32 == (*list).tail {
                break;
            }
            node = core::ptr::read_volatile(core::ptr::addr_of!((*node).next)) as usize
                as *mut LockedCallbackNode;
        }
    }

    sem_signal((*list).semaphore as usize as SemHandle);
    if matched != 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const SEMAPHORE_OFFSET: usize = 0x80;
    const FIRST_NODE_OFFSET: usize = 0x100;
    const SECOND_NODE_OFFSET: usize = 0x140;
    const THIRD_NODE_OFFSET: usize = 0x180;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LOCKED_CALLBACK_LIST_ANY, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static LAST_NODE: AtomicUsize = AtomicUsize::new(0);
    static LAST_CONTEXT: AtomicU32 = AtomicU32::new(0);
    static RESULT: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn record_predicate(node: *mut LockedCallbackNode, context: u32) -> u32 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_NODE.store(node as usize, Ordering::SeqCst);
        LAST_CONTEXT.store(context, Ordering::SeqCst);
        RESULT.load(Ordering::SeqCst)
    }

    fn fixture() -> Option<(*mut u8, MutexGuard<'static, ()>)> {
        let guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let base = *FIXTURE.as_ref()? as *mut u8;
        unsafe { base.write_bytes(0, FIXTURE_LEN) };
        CALLS.store(0, Ordering::SeqCst);
        LAST_NODE.store(0, Ordering::SeqCst);
        LAST_CONTEXT.store(0, Ordering::SeqCst);
        Some((base, guard))
    }

    unsafe fn list_at(base: *mut u8) -> *mut LockedCallbackList {
        let list = base.cast::<LockedCallbackList>();
        (*list).semaphore = base.add(SEMAPHORE_OFFSET) as usize as u32;
        list
    }

    #[test]
    fn empty_list_returns_zero_without_invoking_the_predicate() {
        let Some((base, _guard)) = fixture() else { return };
        unsafe {
            assert_eq!(locked_callback_list_any(list_at(base), record_predicate, 0x1234_5678), 0);
        }
        assert_eq!(CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn skips_inactive_nodes_and_stops_at_the_first_matching_active_node() {
        let Some((base, _guard)) = fixture() else { return };
        unsafe {
            let list = list_at(base);
            let first = base.add(FIRST_NODE_OFFSET).cast::<LockedCallbackNode>();
            let second = base.add(SECOND_NODE_OFFSET).cast::<LockedCallbackNode>();
            let third = base.add(THIRD_NODE_OFFSET).cast::<LockedCallbackNode>();
            (*first).next = second as usize as u32;
            (*second).next = third as usize as u32;
            (*first).active = 0;
            (*second).active = 1;
            (*third).active = 1;
            (*list).head = first as usize as u32;
            (*list).tail = third as usize as u32;
            RESULT.store(1, Ordering::SeqCst);
            assert_eq!(locked_callback_list_any(list, record_predicate, 0xa5a5_5a5a), 1);
            assert_eq!(CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(LAST_NODE.load(Ordering::SeqCst), second as usize);
            assert_eq!(LAST_CONTEXT.load(Ordering::SeqCst), 0xa5a5_5a5a);
        }
    }

    #[test]
    fn walks_through_the_inclusive_tail_when_predicates_do_not_match() {
        let Some((base, _guard)) = fixture() else { return };
        unsafe {
            let list = list_at(base);
            let first = base.add(FIRST_NODE_OFFSET).cast::<LockedCallbackNode>();
            let second = base.add(SECOND_NODE_OFFSET).cast::<LockedCallbackNode>();
            (*first).next = second as usize as u32;
            (*first).active = 1;
            (*second).active = 1;
            (*list).head = first as usize as u32;
            (*list).tail = second as usize as u32;
            RESULT.store(0, Ordering::SeqCst);
            assert_eq!(locked_callback_list_any(list, record_predicate, 7), 0);
            assert_eq!(CALLS.load(Ordering::SeqCst), 2);
            assert_eq!(LAST_NODE.load(Ordering::SeqCst), second as usize);
        }
    }
}
