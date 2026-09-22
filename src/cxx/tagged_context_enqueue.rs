//! `tagged_context_enqueue` — original: `FUN_08261850` @ **0x08261850**
//! (64 bytes, raw extent `0x08261850..0x08261890`).
//!
//! Raw A32 establishes the next independent `push` prologue at `0x08261890`.
//! The body has four plain `bl` instructions and no predicated `bl`: lock,
//! deque push-back, opaque-context activation, and unlock. Ghidra's reported
//! three calls omits the final unlock.
//!
//! Algorithm: lock the owner mutex at +0x00, append `value` to the elem4 deque
//! at +0x38, activate the tagged context at +0x1c, unlock, and return the
//! activation status. The incoming r0 is never read.
//!
//! Deliberate deviation: the still-unported activation target at 0x082e7f78
//! is an indirect fixed-address call on target and a volatile host seam; the
//! three already-ported boundaries are called directly.

use core::ptr;

use crate::heap::block_deque::BlockDeque;
use crate::heap::deque_push_back_elem4;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

const TAGGED_CONTEXT_OFFSET: usize = 0x1c;
const DEQUE_OFFSET: usize = 0x38;
const RETAIL_OPAQUE_CONTEXT_ACTIVATE: usize = 0x082e_7f78;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_context_activate(_context: *mut u32) -> u32 { 0 }

/// Host boundary for the unported tagged-context activation routine.
#[cfg(not(target_os = "none"))]
pub static mut TAGGED_CONTEXT_ENQUEUE_ACTIVATE: unsafe extern "C" fn(*mut u32) -> u32 =
    missing_opaque_context_activate;

#[inline(always)]
unsafe fn activate(context: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let target: unsafe extern "C" fn(*mut u32) -> u32 =
            core::mem::transmute(RETAIL_OPAQUE_CONTEXT_ACTIVATE);
        target(context)
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(TAGGED_CONTEXT_ENQUEUE_ACTIVATE))(context)
    }
}

/// Enqueues `value` under `owner`'s mutex, then activates its tagged context.
///
/// # Safety
/// `owner` must address a valid retailOS object with a [`PosixMutex`] at +0,
/// a tagged context at +0x1c, and a [`BlockDeque`] at +0x38. `value` must be
/// readable. `_unused` preserves the unread r0 ABI argument.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_context_enqueue(
    _unused: *mut u8,
    owner: *mut u8,
    value: *const u32,
) -> u32 {
    posix_mutex_lock(owner.cast::<PosixMutex>());
    deque_push_back_elem4::deque_push_back_elem4(owner.add(DEQUE_OFFSET).cast::<BlockDeque>(), value);
    let status = activate(owner.add(TAGGED_CONTEXT_OFFSET).cast::<u32>());
    posix_mutex_unlock(owner.cast::<PosixMutex>());
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::block_deque::DequeIter;

    static OPS_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut ACTIVATION_CONTEXT: *mut u32 = ptr::null_mut();
    static mut ACTIVATION_STATUS: u32 = 0;

    struct ActivationReset;
    impl Drop for ActivationReset {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(TAGGED_CONTEXT_ENQUEUE_ACTIVATE)
                    .write_volatile(missing_opaque_context_activate);
            }
        }
    }

    unsafe extern "C" fn record_activation(context: *mut u32) -> u32 {
        ACTIVATION_CONTEXT = context;
        ACTIVATION_STATUS
    }

    #[test]
    fn appends_then_activates_and_returns_its_status() {
        let _lock = OPS_LOCK.lock();
        let _reset = ActivationReset;
        let mut owner = [0u64; 32];
        let owner = owner.as_mut_ptr().cast::<u8>();
        let mut storage = [0u32; 2];
        let deque = unsafe { owner.add(DEQUE_OFFSET).cast::<BlockDeque>() };
        unsafe {
            deque.write(BlockDeque {
                begin: DequeIter::NULL,
                end: DequeIter {
                    cur: storage.as_mut_ptr().cast(),
                    seg_base: storage.as_mut_ptr().cast(),
                    seg_end: storage.as_mut_ptr().add(2).cast(),
                    seg_slot: ptr::null_mut(),
                },
                count: 1,
                map: ptr::null_mut(),
                map_cap: 0,
            });
            ACTIVATION_CONTEXT = ptr::null_mut();
            ACTIVATION_STATUS = 0x27;
            ptr::addr_of_mut!(TAGGED_CONTEXT_ENQUEUE_ACTIVATE).write_volatile(record_activation);
            assert_eq!(tagged_context_enqueue(ptr::null_mut(), owner, &0xaabb_ccdd), 0x27);
            assert_eq!(storage, [0xaabb_ccdd, 0]);
            assert_eq!((*deque).count, 2);
            assert_eq!(ACTIVATION_CONTEXT as usize, owner.add(TAGGED_CONTEXT_OFFSET) as usize);
        }
    }
}
