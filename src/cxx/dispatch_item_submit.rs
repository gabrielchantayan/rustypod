//! `dispatch_item_submit` — `FUN_08261998` @ **0x08261998**.
//! True extent: 76 bytes (`0x08261998..0x082619e4`), one plain outgoing
//! BL and zero predicated BL; two plain inbound BL and four tail B callers.
//! Ghidra's 192 bytes include the separately entered 116-byte helper at
//! 0x082619e4, also reached by the conditional branch at 0x08261b4c.
//!
//! Wait for an item from the manager's free queue at +0x38, with no selector.
//! NULL returns status 0x14. Otherwise transfer to the shared helper with
//! (manager, item, payload, 0). That helper locks the manager, initializes the
//! item, enqueues it on manager+0x9c, conditionally waits for completion, and
//! unlocks. Only this wrapper is ported; no helper identity is inferred beyond
//! its decoded behavior. Deliberate deviations: a normal call represents the
//! tail transfer; the unported helper is a fixed-address target call and host
//! operation seam. The existing dequeue port is used directly on target.

use core::ptr;
#[cfg(target_os = "none")]
use crate::cxx::tagged_context_dequeue::tagged_context_dequeue;

type Dequeue = unsafe extern "C" fn(*mut u8, *mut u8, u32, *const u32) -> *mut u8;
type FinishSubmit = unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dequeue(_: *mut u8, _: *mut u8, _: u32, _: *const u32) -> *mut u8 {
    panic!("dispatch_item_submit dequeue operation was not installed")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_finish(_: *mut u8, _: *mut u8, _: *mut u8, _: u32) -> u32 {
    panic!("dispatch_item_submit shared helper was not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut DISPATCH_ITEM_SUBMIT_DEQUEUE: Dequeue = missing_dequeue;
#[cfg(not(target_os = "none"))]
pub static mut DISPATCH_ITEM_SUBMIT_FINISH: FinishSubmit = missing_finish;

/// # Safety
/// `manager` must be a live retailOS dispatch manager with its free queue at
/// +0x38. `payload` must meet the shared submission helper's lifetime contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dispatch_item_submit(manager: *mut u8, payload: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    let dequeue: Dequeue = tagged_context_dequeue;
    #[cfg(not(target_os = "none"))]
    let dequeue = unsafe { ptr::read_volatile(ptr::addr_of!(DISPATCH_ITEM_SUBMIT_DEQUEUE)) };
    let item = unsafe { dequeue(manager, manager.add(0x38), 1, ptr::null()) };
    if item.is_null() { return 0x14; }
    #[cfg(target_os = "none")]
    let finish: FinishSubmit = unsafe { core::mem::transmute(0x082619e4usize) };
    #[cfg(not(target_os = "none"))]
    let finish = unsafe { ptr::read_volatile(ptr::addr_of!(DISPATCH_ITEM_SUBMIT_FINISH)) };
    unsafe { finish(manager, item, payload, 0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ITEM: *mut u8 = ptr::null_mut();
    static mut STATUS: u32 = 0;
    static mut FINISHED: bool = false;
    unsafe extern "C" fn dequeue(manager: *mut u8, owner: *mut u8, wait: u32, selector: *const u32) -> *mut u8 {
        assert_eq!(owner, unsafe { manager.add(0x38) });
        assert_eq!(wait, 1);
        assert!(selector.is_null());
        unsafe { ITEM }
    }
    unsafe extern "C" fn finish(_: *mut u8, item: *mut u8, _: *mut u8, mode: u32) -> u32 {
        assert_eq!(item, unsafe { ITEM });
        assert_eq!(mode, 0);
        unsafe { FINISHED = true; STATUS }
    }
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                DISPATCH_ITEM_SUBMIT_DEQUEUE = missing_dequeue;
                DISPATCH_ITEM_SUBMIT_FINISH = missing_finish;
            }
        }
    }
    #[test]
    fn exhausted_free_queue_returns_twenty_without_submitting() {
        let _lock = LOCK.lock(); let _restore = Restore;
        let mut manager = [0u32; 64];
        unsafe {
            ITEM = ptr::null_mut(); FINISHED = false;
            DISPATCH_ITEM_SUBMIT_DEQUEUE = dequeue;
            DISPATCH_ITEM_SUBMIT_FINISH = finish;
            assert_eq!(dispatch_item_submit(manager.as_mut_ptr().cast(), ptr::null_mut()), 0x14);
            assert!(!FINISHED);
        }
    }
    #[test]
    fn acquired_item_propagates_success_and_failure_status() {
        let _lock = LOCK.lock(); let _restore = Restore;
        let mut manager = [0u32; 64];
        let mut item = [0u32; 4];
        let mut payload = 7u32;
        unsafe {
            ITEM = item.as_mut_ptr().cast();
            DISPATCH_ITEM_SUBMIT_DEQUEUE = dequeue;
            DISPATCH_ITEM_SUBMIT_FINISH = finish;
            for status in [0, 0x14, 0x1a, u32::MAX] {
                STATUS = status; FINISHED = false;
                assert_eq!(dispatch_item_submit(manager.as_mut_ptr().cast(), (&mut payload as *mut u32).cast()), status);
                assert!(FINISHED);
            }
        }
    }
}
