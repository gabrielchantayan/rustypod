//! `request_callback_state_reset` — original: `FUN_081e2ae8` @ `0x081e2ae8`.
//!
//! Raw ARM establishes **184 instruction bytes** (`0x081e2ae8..0x081e2ba0`),
//! followed by the 8-byte literal pool at `0x081e2ba0..0x081e2ba8`; the next
//! separately linked function begins at `0x081e2ba8`. Ghidra follows the tail
//! branch through the mutex unlock and incorrectly absorbs that mutex body.
//! A full-image ARM B/BL decode finds exactly **8 direct `bl` callers**, all
//! unconditional: `0x081e2720`, `0x081e2874`, `0x081e29c4`, `0x081e29e8`,
//! `0x081e2c40`, `0x081e2e0c`, `0x081e2ea4`, and `0x081e30d8`. There are no
//! predicated direct calls; the body itself has no state-pointer NULL guard.
//!
//! # Algorithm
//!
//! Under the global mutex at `0x08ac88a0`, if the callback registry at
//! `0x089cca14` has a nonzero count, reload its count and table word before
//! every iteration and call each non-NULL callback's vtable slot `+0x04`.
//! It tag-3 deletes the final reloaded table allocation, clears its table
//! word, and clears the registry's four leading bytes. Independently, a
//! `reset_pending_request` changes `state+0x2d0` to `0x7fffffff` and zeros
//! `state+0x2d4`; a nonzero `reset_reply_progress` clears the four individual
//! bytes at `state+0x2e0..+0x2e3`. It then unlocks, ignoring both mutex status
//! values exactly as stock does.
//!
//! # Deliberate deviations
//!
//! The target reads the fixed globals and invokes the existing
//! `operator_delete_tag3` port directly. Host tests model the fixed registry
//! with native-width pointers, because firmware's two pointer words are only
//! 32 bits wide there. The target's tail branch to mutex unlock is a normal
//! Rust call after the stores complete.

use core::ptr::{addr_of, addr_of_mut};

use crate::heap::veneers::operator_delete_tag3;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

const CALLBACK_REGISTRY_ADDRESS: usize = 0x089c_ca14;
const CALLBACK_REGISTRY_MUTEX_ADDRESS: usize = 0x08ac_88a0;
const PENDING_REQUEST_SENTINEL: u32 = 0x7fff_ffff;

/// The target callback registry's exact 32-bit layout.
#[cfg(target_os = "none")]
#[repr(C)]
struct TargetCallbackRegistry {
    callback_count: u8,
    _leading_flags: [u8; 3],
    owner: u32,
    callbacks: u32,
}

#[cfg(target_os = "none")]
const _: () = assert!(core::mem::size_of::<TargetCallbackRegistry>() == 0x0c);
#[cfg(target_os = "none")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(TargetCallbackRegistry, callbacks)];

/// Host equivalent of the fixed callback registry. Its pointers deliberately
/// retain host width; only the target representation has fixed 32-bit words.
#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostCallbackRegistry {
    callback_count: u8,
    _leading_flags: [u8; 3],
    owner: *mut u8,
    callbacks: *mut *mut HostCallbackEntry,
}

/// Host representation of the callback's leading vtable pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostCallbackEntry {
    vtable: *const HostCallbackVtable,
    id: usize,
}

/// Only callback vtable slot `+0x04` is used on target. On the host, the
/// native-width preceding slot preserves the same vtable ordering.
#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostCallbackVtable {
    _slot_00: usize,
    release: unsafe extern "C" fn(*mut HostCallbackEntry),
}

/// The only fields reached on the caller-provided operation state.
#[repr(C)]
pub struct RequestCallbackState {
    _before_pending_request: [u8; 0x2d0],
    pub pending_request: u32,
    pub pending_request_payload: u32,
    _before_reply_progress: [u8; 8],
    pub reply_progress: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<RequestCallbackState>() == 0x2e4);
const _: [u8; 0x2d0] = [0; core::mem::offset_of!(RequestCallbackState, pending_request)];
const _: [u8; 0x2d4] = [0; core::mem::offset_of!(RequestCallbackState, pending_request_payload)];
const _: [u8; 0x2e0] = [0; core::mem::offset_of!(RequestCallbackState, reply_progress)];

#[cfg(not(target_os = "none"))]
static mut HOST_CALLBACK_REGISTRY: HostCallbackRegistry = HostCallbackRegistry {
    callback_count: 0,
    _leading_flags: [0; 3],
    owner: core::ptr::null_mut(),
    callbacks: core::ptr::null_mut(),
};

#[cfg(not(target_os = "none"))]
static mut HOST_CALLBACK_REGISTRY_MUTEX: PosixMutex = PosixMutex {
    magic: 0,
    owner: 0,
    reserved_08: 0,
    attr_flags: 0,
    reserved_10: 0,
    recursion: 0,
    sem_handle: 0,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn callback_registry_mutex() -> *mut PosixMutex {
    CALLBACK_REGISTRY_MUTEX_ADDRESS as *mut PosixMutex
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn callback_registry_mutex() -> *mut PosixMutex {
    addr_of_mut!(HOST_CALLBACK_REGISTRY_MUTEX)
}

#[cfg(target_os = "none")]
unsafe fn clear_callback_registry() {
    let registry = CALLBACK_REGISTRY_ADDRESS as *mut TargetCallbackRegistry;
    if addr_of!((*registry).callback_count).read_volatile() == 0 {
        return;
    }

    if addr_of!((*registry).callbacks).read_volatile() != 0 {
        let mut index = 0u8;
        while index < addr_of!((*registry).callback_count).read_volatile() {
            let callbacks = addr_of!((*registry).callbacks).read_volatile() as *mut u32;
            let callback = callbacks.add(index as usize).read_volatile() as *mut u8;
            if !callback.is_null() {
                let vtable = callback.cast::<u32>().read_volatile() as *const u32;
                let release_address = vtable.add(1).read_volatile();
                let release: unsafe extern "C" fn(*mut u8) = core::mem::transmute(release_address as usize);
                release(callback);
            }
            index = index.wrapping_add(1);
        }
        let callbacks = addr_of!((*registry).callbacks).read_volatile() as *mut u8;
        operator_delete_tag3(callbacks);
        addr_of_mut!((*registry).callbacks).write_volatile(0);
    }

    addr_of_mut!((*registry).callback_count).write_volatile(0);
    (registry.cast::<u8>().add(1)).write_volatile(0);
    (registry.cast::<u8>().add(2)).write_volatile(0);
    (registry.cast::<u8>().add(3)).write_volatile(0);
}

#[cfg(not(target_os = "none"))]
unsafe fn clear_callback_registry() {
    let registry = addr_of_mut!(HOST_CALLBACK_REGISTRY);
    if addr_of!((*registry).callback_count).read_volatile() == 0 {
        return;
    }

    if !addr_of!((*registry).callbacks).read_volatile().is_null() {
        let mut index = 0u8;
        while index < addr_of!((*registry).callback_count).read_volatile() {
            let callbacks = addr_of!((*registry).callbacks).read_volatile();
            let callback = callbacks.add(index as usize).read_volatile();
            if !callback.is_null() {
                let vtable = addr_of!((*callback).vtable).read_volatile();
                ((*vtable).release)(callback);
            }
            index = index.wrapping_add(1);
        }
        let callbacks = addr_of!((*registry).callbacks).read_volatile();
        operator_delete_tag3(callbacks.cast());
        addr_of_mut!((*registry).callbacks).write_volatile(core::ptr::null_mut());
    }

    addr_of_mut!((*registry).callback_count).write_volatile(0);
    (registry.cast::<u8>().add(1)).write_volatile(0);
    (registry.cast::<u8>().add(2)).write_volatile(0);
    (registry.cast::<u8>().add(3)).write_volatile(0);
}

/// Clears the global callback registry and selected operation-state fields.
///
/// Original: `FUN_081e2ae8` at `0x081e2ae8` (184 instruction bytes plus an
/// 8-byte literal pool; **8 unconditional direct `bl` callers**).
///
/// # Safety
///
/// `state` must name a writable [`RequestCallbackState`]. On target, the
/// fixed callback registry and its mutex must retain their retail layouts; a
/// non-NULL callback-table word must be a tag-3 allocation whose non-NULL
/// entries have a readable vtable and a callable slot `+0x04`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn request_callback_state_reset(
    state: *mut RequestCallbackState,
    reset_pending_request: u32,
    reset_reply_progress: u32,
) {
    posix_mutex_lock(callback_registry_mutex());
    clear_callback_registry();

    if reset_pending_request != 0 {
        addr_of_mut!((*state).pending_request).write_volatile(PENDING_REQUEST_SENTINEL);
        addr_of_mut!((*state).pending_request_payload).write_volatile(0);
    }
    if reset_reply_progress != 0 {
        addr_of_mut!((*state).reply_progress).cast::<u8>().write_volatile(0);
        addr_of_mut!((*state).reply_progress).cast::<u8>().add(1).write_volatile(0);
        addr_of_mut!((*state).reply_progress).cast::<u8>().add(2).write_volatile(0);
        addr_of_mut!((*state).reply_progress).cast::<u8>().add(3).write_volatile(0);
    }

    posix_mutex_unlock(callback_registry_mutex());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLBACK_LOG: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn record_release(callback: *mut HostCallbackEntry) {
        CALLBACK_LOG.lock().push((*callback).id);
    }

    unsafe extern "C" fn record_release_and_truncate(callback: *mut HostCallbackEntry) {
        CALLBACK_LOG.lock().push((*callback).id);
        addr_of_mut!(HOST_CALLBACK_REGISTRY.callback_count).write_volatile(1);
    }

    static CALLBACK_VTABLE: HostCallbackVtable = HostCallbackVtable {
        _slot_00: 0,
        release: record_release,
    };

    static TRUNCATING_CALLBACK_VTABLE: HostCallbackVtable = HostCallbackVtable {
        _slot_00: 0,
        release: record_release_and_truncate,
    };

    struct RegistryReset;

    impl Drop for RegistryReset {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(HOST_CALLBACK_REGISTRY).write(HostCallbackRegistry {
                    callback_count: 0,
                    _leading_flags: [0; 3],
                    owner: core::ptr::null_mut(),
                    callbacks: core::ptr::null_mut(),
                });
            }
        }
    }

    fn state_with_values() -> RequestCallbackState {
        RequestCallbackState {
            _before_pending_request: [0; 0x2d0],
            pending_request: 0x1122_3344,
            pending_request_payload: 0x5566_7788,
            _before_reply_progress: [0; 8],
            reply_progress: [1, 2, 3, 4],
        }
    }

    #[test]
    fn releases_non_null_callbacks_then_clears_both_requested_state_groups() {
        let _test_guard = TEST_LOCK.lock();
        let _heap_guard = crate::heap::veneers::tests::mock_heap();
        let _reset = RegistryReset;
        CALLBACK_LOG.lock().clear();

        let mut first = HostCallbackEntry { vtable: &CALLBACK_VTABLE, id: 7 };
        let mut second = HostCallbackEntry { vtable: &CALLBACK_VTABLE, id: 9 };
        let mut callbacks = [
            core::ptr::addr_of_mut!(first),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(second),
        ];
        unsafe {
            addr_of_mut!(HOST_CALLBACK_REGISTRY).write(HostCallbackRegistry {
                callback_count: callbacks.len() as u8,
                _leading_flags: [0x5a, 0x6b, 0x7c],
                owner: 0x1234usize as *mut u8,
                callbacks: callbacks.as_mut_ptr(),
            });
        }
        let mut state = state_with_values();

        unsafe { request_callback_state_reset(&mut state, 1, 1) };

        assert_eq!(*CALLBACK_LOG.lock(), [7, 9]);
        assert_eq!(crate::heap::veneers::tests::free_log(), (1, callbacks.as_mut_ptr().cast(), 3));
        unsafe {
            assert_eq!(HOST_CALLBACK_REGISTRY.callback_count, 0);
            assert_eq!(HOST_CALLBACK_REGISTRY._leading_flags, [0; 3]);
            assert_eq!(HOST_CALLBACK_REGISTRY.owner, 0x1234usize as *mut u8);
            assert!(HOST_CALLBACK_REGISTRY.callbacks.is_null());
        }
        assert_eq!(state.pending_request, PENDING_REQUEST_SENTINEL);
        assert_eq!(state.pending_request_payload, 0);
        assert_eq!(state.reply_progress, [0; 4]);
    }

    #[test]
    fn an_empty_registry_is_untouched_and_false_flags_preserve_operation_state() {
        let _test_guard = TEST_LOCK.lock();
        let _heap_guard = crate::heap::veneers::tests::mock_heap();
        let _reset = RegistryReset;
        let mut callbacks = [core::ptr::null_mut::<HostCallbackEntry>()];
        unsafe {
            addr_of_mut!(HOST_CALLBACK_REGISTRY).write(HostCallbackRegistry {
                callback_count: 0,
                _leading_flags: [4, 5, 6],
                owner: 0x5678usize as *mut u8,
                callbacks: callbacks.as_mut_ptr(),
            });
        }
        let mut state = state_with_values();

        unsafe { request_callback_state_reset(&mut state, 0, 0) };

        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
        unsafe {
            assert_eq!(HOST_CALLBACK_REGISTRY.callback_count, 0);
            assert_eq!(HOST_CALLBACK_REGISTRY._leading_flags, [4, 5, 6]);
            assert_eq!(HOST_CALLBACK_REGISTRY.owner, 0x5678usize as *mut u8);
            assert_eq!(HOST_CALLBACK_REGISTRY.callbacks, callbacks.as_mut_ptr());
        }
        assert_eq!(state.pending_request, 0x1122_3344);
        assert_eq!(state.pending_request_payload, 0x5566_7788);
        assert_eq!(state.reply_progress, [1, 2, 3, 4]);
    }

    #[test]
    fn reloads_callback_count_after_each_release() {
        let _test_guard = TEST_LOCK.lock();
        let _heap_guard = crate::heap::veneers::tests::mock_heap();
        let _reset = RegistryReset;
        CALLBACK_LOG.lock().clear();

        let mut first = HostCallbackEntry { vtable: &TRUNCATING_CALLBACK_VTABLE, id: 1 };
        let mut second = HostCallbackEntry { vtable: &CALLBACK_VTABLE, id: 2 };
        let mut callbacks = [
            core::ptr::addr_of_mut!(first),
            core::ptr::addr_of_mut!(second),
        ];
        unsafe {
            addr_of_mut!(HOST_CALLBACK_REGISTRY).write(HostCallbackRegistry {
                callback_count: callbacks.len() as u8,
                _leading_flags: [0; 3],
                owner: core::ptr::null_mut(),
                callbacks: callbacks.as_mut_ptr(),
            });
        }
        let mut state = state_with_values();

        unsafe { request_callback_state_reset(&mut state, 0, 0) };

        assert_eq!(*CALLBACK_LOG.lock(), [1]);
        assert_eq!(crate::heap::veneers::tests::free_log(), (1, callbacks.as_mut_ptr().cast(), 3));
    }
}
