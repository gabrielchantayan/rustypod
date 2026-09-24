//! `global_callback_dispatch_cleanup` — original: `FUN_08124f7c` @
//! `0x08124f7c` (96 bytes of code, `0x08124f7c..0x08124fdc`; Ghidra reports
//! 100 bytes because it includes the first literal-pool word).
//!
//! Raw ARM first tests the global callback pointer at `0x089cc830`. When it
//! exists, it locks the counted mutex at `0x08a79c68`, dispatches the supplied
//! opaque event word through vtable slot `+0x28`, and then destroys and clears
//! the global callback when its word at `+0x04` is zero. It unlocks after that
//! cleanup. The input is passed through a stack-local word, so a callback may
//! rewrite that local value but cannot affect this void function's caller.
//!
//! **Three direct inbound `bl` callers, all unconditional and no predicated
//! `bl` callers**, verified by decoding every ARM B/BL immediate in
//! `work/firmware/osos.dec`: `0x08124f18`, `0x08125278`, and `0x08629bec`.
//! Deliberate deviation: the vtable calls remain typed indirect Rust calls;
//! their slot roles and dispatch/cleanup order are preserved.

use core::ptr::{addr_of_mut, read_volatile, write_volatile};
#[cfg(test)]
use core::ptr::addr_of;
#[cfg(not(target_os = "none"))]
use crate::kernel::sync_mutex::Mutex;
use crate::kernel::sync_mutex::{mutex_lock_counted, mutex_unlock_counted, CountedMutex};

const GLOBAL_CALLBACK_ADDRESS: usize = 0x089c_c830;
const GLOBAL_CALLBACK_MUTEX_ADDRESS: usize = 0x08a7_9c68;

/// Opaque global callback object. Its second target word is observed as the
/// cleanup gate; all other object state belongs to the vtable implementation.
#[repr(C)]
pub struct GlobalCallback {
    pub vtable: *const GlobalCallbackVtable,
    pub reference_count: u32,
}

/// Recovered callback vtable slots. On the 32-bit target `destroy` and
/// `dispatch` are precisely `+0x04` and `+0x28`; native host pointer widths
/// retain the same slot roles for fixtures.
#[repr(C)]
pub struct GlobalCallbackVtable {
    pub unknown_00: usize,
    pub destroy: unsafe extern "C" fn(*mut GlobalCallback),
    pub unknown_08: usize,
    pub unknown_0c: usize,
    pub unknown_10: usize,
    pub unknown_14: usize,
    pub unknown_18: usize,
    pub unknown_1c: usize,
    pub unknown_20: usize,
    pub unknown_24: usize,
    pub dispatch: unsafe extern "C" fn(*mut GlobalCallback, *mut u32),
}

#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_CALLBACK: *mut GlobalCallback = core::ptr::null_mut();
#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_CALLBACK_MUTEX: CountedMutex = CountedMutex {
    mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
    hold_count: 0,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn callback_globals() -> (*mut *mut GlobalCallback, *mut CountedMutex) {
    (GLOBAL_CALLBACK_ADDRESS as *mut *mut GlobalCallback, GLOBAL_CALLBACK_MUTEX_ADDRESS as *mut CountedMutex)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn callback_globals() -> (*mut *mut GlobalCallback, *mut CountedMutex) {
    (addr_of_mut!(HOST_GLOBAL_CALLBACK), addr_of_mut!(HOST_GLOBAL_CALLBACK_MUTEX))
}

/// Dispatches `event` to the optional global callback, then destroys and
/// clears that callback when its reference count is zero.
///
/// Original: `FUN_08124f7c` at `0x08124f7c` (96 bytes; **3 unconditional
/// direct `bl` callers and no predicated forms**). The global pointer is
/// checked before taking the lock; after dispatch the object and its vtable
/// are assumed live, exactly as in the firmware.
///
/// # Safety
///
/// The installed global callback must have a valid vtable. Its dispatch
/// routine receives a pointer to a temporary event word and must not retain it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_callback_dispatch_cleanup(event: u32) {
    let (global_callback, callback_mutex) = callback_globals();
    if read_volatile(global_callback).is_null() {
        return;
    }

    mutex_lock_counted(callback_mutex);
    let callback = read_volatile(global_callback);
    let mut local_event = event;
    ((*(*callback).vtable).dispatch)(callback, addr_of_mut!(local_event));

    if (*callback).reference_count == 0 {
        ((*(*callback).vtable).destroy)(callback);
        write_volatile(global_callback, core::ptr::null_mut());
    }
    mutex_unlock_counted(callback_mutex);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex as StdMutex;

    static TEST_LOCK: StdMutex<()> = StdMutex::new(());
    static CALLS: StdMutex<[u32; 3]> = StdMutex::new([0; 3]);

    unsafe extern "C" fn dispatch(_callback: *mut GlobalCallback, event: *mut u32) {
        let mut calls = CALLS.lock();
        calls[0] += 1;
        calls[1] = *event;
        *event = 0xfeed_beef;
    }

    unsafe extern "C" fn destroy(_callback: *mut GlobalCallback) {
        CALLS.lock()[2] += 1;
    }

    static VTABLE: GlobalCallbackVtable = GlobalCallbackVtable {
        unknown_00: 0,
        destroy,
        unknown_08: 0,
        unknown_0c: 0,
        unknown_10: 0,
        unknown_14: 0,
        unknown_18: 0,
        unknown_1c: 0,
        unknown_20: 0,
        unknown_24: 0,
        dispatch,
    };

    fn reset(callback: *mut GlobalCallback) {
        *CALLS.lock() = [0; 3];
        unsafe {
            write_volatile(addr_of_mut!(HOST_GLOBAL_CALLBACK), callback);
            (*addr_of_mut!(HOST_GLOBAL_CALLBACK_MUTEX)).hold_count = 0;
        }
    }

    #[test]
    fn absent_callback_does_not_lock_or_dispatch() {
        let _test_lock = TEST_LOCK.lock();
        reset(core::ptr::null_mut());
        unsafe { global_callback_dispatch_cleanup(0x1234_5678) };
        assert_eq!(*CALLS.lock(), [0; 3]);
        assert_eq!(unsafe { HOST_GLOBAL_CALLBACK_MUTEX.hold_count }, 0);
    }

    #[test]
    fn live_callback_receives_event_and_remains_installed() {
        let _test_lock = TEST_LOCK.lock();
        let mut callback = GlobalCallback { vtable: addr_of!(VTABLE), reference_count: 1 };
        reset(addr_of_mut!(callback));
        unsafe { global_callback_dispatch_cleanup(0x1234_5678) };
        assert_eq!(*CALLS.lock(), [1, 0x1234_5678, 0]);
        assert_eq!(unsafe { read_volatile(addr_of!(HOST_GLOBAL_CALLBACK)) }, addr_of_mut!(callback));
        assert_eq!(unsafe { HOST_GLOBAL_CALLBACK_MUTEX.hold_count }, 0);
    }

    #[test]
    fn zero_reference_callback_is_destroyed_then_cleared() {
        let _test_lock = TEST_LOCK.lock();
        let mut callback = GlobalCallback { vtable: addr_of!(VTABLE), reference_count: 0 };
        reset(addr_of_mut!(callback));
        unsafe { global_callback_dispatch_cleanup(9) };
        assert_eq!(*CALLS.lock(), [1, 9, 1]);
        assert!(unsafe { read_volatile(addr_of!(HOST_GLOBAL_CALLBACK)) }.is_null());
        assert_eq!(unsafe { HOST_GLOBAL_CALLBACK_MUTEX.hold_count }, 0);
    }
}
