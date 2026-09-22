//! `tagged_context_dequeue` — original: `FUN_08261890` @ **0x08261890**
//! (164 bytes, raw extent `0x08261890..0x08261934`).
//!
//! Raw A32 establishes the next independent `push` prologue at `0x08261934`.
//! The body contains nine plain `bl` instructions and no predicated `bl`:
//! lock; two tagged-context dispatch variants; two deque-empty checks; deque
//! front and pop; and unlock.
//!
//! Algorithm: lock the owner mutex at +0x00. With `wait` nonzero, repeatedly
//! dispatch the tagged context at +0x1c until either it returns a nonzero
//! status or the four-byte deque at +0x38 becomes nonempty. With `wait` zero,
//! only inspect the deque once. If an element is available, return its front
//! word and pop it; otherwise return NULL. Unlock in every path.
//!
//! Deliberate deviations: the retail deque front member is an unported
//! iterator-dereference helper; its verified effect is the begin cursor word,
//! read directly here. Host builds use an operation seam for the lock,
//! dispatch, deque, and unlock boundaries; target builds call the established
//! ports directly.

use core::ptr;

use crate::cxx::tagged_context_dispatch::{
    dispatch_tagged_context_with_selector, validate_and_dispatch_tagged_context,
};
use crate::cxx::templates::{container_is_empty, deque_pop_front_elem4};
use crate::heap::block_deque::BlockDeque;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

const TAGGED_CONTEXT_OFFSET: usize = 0x1c;
const DEQUE_OFFSET: usize = 0x38;

type ContextDispatch = unsafe extern "C" fn(*mut u32, *mut u32, *const u32) -> u32;
type VoidCall = unsafe extern "C" fn(*mut u8);
type IsEmpty = unsafe extern "C" fn(*mut u8) -> u32;
type PopFront = unsafe extern "C" fn(*mut u8);

#[derive(Clone, Copy)]
pub struct TaggedContextDequeueOps {
    pub lock: VoidCall,
    pub is_empty: IsEmpty,
    pub dispatch: ContextDispatch,
    pub pop_front: PopFront,
    pub unlock: VoidCall,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_void(_pointer: *mut u8) {
    panic!("tagged_context_dequeue operation was not installed")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_empty(_deque: *mut u8) -> u32 {
    panic!("tagged_context_dequeue deque predicate was not installed")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_context: *mut u32, _input: *mut u32, _selector: *const u32) -> u32 {
    panic!("tagged_context_dequeue dispatcher was not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut TAGGED_CONTEXT_DEQUEUE_OPS: TaggedContextDequeueOps = TaggedContextDequeueOps {
    lock: missing_void,
    is_empty: missing_empty,
    dispatch: missing_dispatch,
    pop_front: missing_void,
    unlock: missing_void,
};

#[inline(always)]
unsafe fn lock(mutex: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { posix_mutex_lock(mutex.cast::<PosixMutex>()); }
    #[cfg(not(target_os = "none"))]
    unsafe { ptr::read_volatile(ptr::addr_of!(TAGGED_CONTEXT_DEQUEUE_OPS.lock))(mutex); }
}
#[inline(always)]
unsafe fn is_empty(deque: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    unsafe { container_is_empty(deque) }
    #[cfg(not(target_os = "none"))]
    unsafe { ptr::read_volatile(ptr::addr_of!(TAGGED_CONTEXT_DEQUEUE_OPS.is_empty))(deque) }
}
#[inline(always)]
unsafe fn dispatch(context: *mut u32, input: *mut u32, selector: *const u32) -> u32 {
    #[cfg(target_os = "none")]
    unsafe {
        if selector.is_null() { validate_and_dispatch_tagged_context(context, input) }
        else { dispatch_tagged_context_with_selector(context, input, selector) }
    }
    #[cfg(not(target_os = "none"))]
    unsafe { ptr::read_volatile(ptr::addr_of!(TAGGED_CONTEXT_DEQUEUE_OPS.dispatch))(context, input, selector) }
}
#[inline(always)]
unsafe fn pop_front(deque: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { deque_pop_front_elem4(deque.cast::<BlockDeque>()); }
    #[cfg(not(target_os = "none"))]
    unsafe { ptr::read_volatile(ptr::addr_of!(TAGGED_CONTEXT_DEQUEUE_OPS.pop_front))(deque); }
}
#[inline(always)]
unsafe fn unlock(mutex: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { posix_mutex_unlock(mutex.cast::<PosixMutex>()); }
    #[cfg(not(target_os = "none"))]
    unsafe { ptr::read_volatile(ptr::addr_of!(TAGGED_CONTEXT_DEQUEUE_OPS.unlock))(mutex); }
}

/// # Safety
/// `owner` must address a valid retailOS object with a mutex at +0x00, a
/// tagged context at +0x1c, and a four-byte deque at +0x38. `selector`, when
/// non-NULL, must meet the tagged-context dispatcher contract. `_unused` is
/// the preserved but unread r0 ABI argument.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_context_dequeue(
    _unused: *mut u8,
    owner: *mut u8,
    wait: u32,
    selector: *const u32,
) -> *mut u8 {
    let deque = unsafe { owner.add(DEQUE_OFFSET) };
    let context = unsafe { owner.add(TAGGED_CONTEXT_OFFSET).cast::<u32>() };
    unsafe { lock(owner) };

    if wait != 0 {
        while unsafe { is_empty(deque) } != 0 {
            if unsafe { dispatch(context, owner.cast::<u32>(), selector) } != 0 {
                break;
            }
        }
    }

    let result = if unsafe { is_empty(deque) } == 0 {
        let front = unsafe { (deque as *mut *mut u8).read() };
        unsafe { pop_front(deque) };
        front
    } else {
        ptr::null_mut()
    };
    unsafe { unlock(owner) };
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EMPTY_RESPONSES: [u32; 3] = [0; 3];
    static mut EMPTY_INDEX: usize = 0;
    static mut CALLS: [u8; 8] = [0; 8];
    static mut CALL_COUNT: usize = 0;

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { TAGGED_CONTEXT_DEQUEUE_OPS = TaggedContextDequeueOps { lock: missing_void, is_empty: missing_empty, dispatch: missing_dispatch, pop_front: missing_void, unlock: missing_void }; }
        }
    }
    unsafe fn record(code: u8) { CALLS[CALL_COUNT] = code; CALL_COUNT += 1; }
    unsafe extern "C" fn record_lock(_pointer: *mut u8) { unsafe { record(1) } }
    unsafe extern "C" fn record_empty(_deque: *mut u8) -> u32 { unsafe { record(2); let answer = EMPTY_RESPONSES[EMPTY_INDEX]; EMPTY_INDEX += 1; answer } }
    unsafe extern "C" fn record_dispatch(_context: *mut u32, _input: *mut u32, selector: *const u32) -> u32 { unsafe { record(if selector.is_null() { 3 } else { 4 }); 0 } }
    unsafe extern "C" fn record_pop(_deque: *mut u8) { unsafe { record(5) } }
    unsafe extern "C" fn record_unlock(_pointer: *mut u8) { unsafe { record(6) } }

    unsafe fn install(responses: [u32; 3]) {
        EMPTY_RESPONSES = responses; EMPTY_INDEX = 0; CALL_COUNT = 0;
        TAGGED_CONTEXT_DEQUEUE_OPS = TaggedContextDequeueOps { lock: record_lock, is_empty: record_empty, dispatch: record_dispatch, pop_front: record_pop, unlock: record_unlock };
    }

    #[test]
    fn no_wait_empty_queue_unlocks_without_dispatch() {
        let _guard = OPS_LOCK.lock(); let _restore = Restore;
        let mut owner = [0u32; 32];
        unsafe { install([1, 0, 0]); assert!(tagged_context_dequeue(ptr::null_mut(), owner.as_mut_ptr().cast(), 0, ptr::null()).is_null()); assert_eq!(&CALLS[..CALL_COUNT], &[1, 2, 6]); }
    }

    #[test]
    fn wait_dispatches_then_returns_and_pops_front() {
        let _guard = OPS_LOCK.lock(); let _restore = Restore;
        let Some(owner) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TAGGED_CONTEXT_DEQUEUE, 0x1000,
        ) else {
            crate::testing::note_missing_u32_fixture("cxx::tagged_context_dequeue");
            return;
        };
        let item = unsafe { owner.add(0x100) };
        unsafe { (owner.add(DEQUE_OFFSET) as *mut u32).write(item as usize as u32); }
        let selector = [9u32];
        unsafe { install([1, 0, 0]); assert_eq!(tagged_context_dequeue(ptr::null_mut(), owner, 1, selector.as_ptr()), item); assert_eq!(&CALLS[..CALL_COUNT], &[1, 2, 4, 2, 2, 5, 6]); }
    }
}
