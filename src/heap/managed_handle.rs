//! Port of a mode-dispatched managed-handle lifecycle boundary.
//!
//! The original's two callees construct and dispose a 0x54-byte object, but
//! their surrounding subsystem has not been ported. This module therefore
//! preserves the small dispatch contract and exposes that boundary through an
//! ops table, following the heap client's normal host-test seam convention.

/// Indirect dispatch for the unported managed-handle constructor and
/// destructor. On target these slots must be wired to the retailOS helpers;
/// host tests replace them with recorders.
#[derive(Clone, Copy)]
pub struct ManagedHandleOps {
    /// Constructor @ 0x08062470. Returns a managed handle, or NULL when its
    /// allocation or initialization fails.
    pub create: unsafe extern "C" fn() -> *mut u8,
    /// Destructor @ 0x08062374. The retailOS implementation is NULL-tolerant.
    pub release: unsafe extern "C" fn(handle: *mut u8),
}

/// The surrounding resource subsystem is not ported yet, so an unwired
/// constructor reports the same observable allocation failure as a NULL
/// return from the original helper.
unsafe extern "C" fn missing_create() -> *mut u8 {
    core::ptr::null_mut()
}

/// The unwired release boundary cannot safely reclaim an unknown resource.
unsafe extern "C" fn missing_release(_handle: *mut u8) {}

/// Defaults until the resource subsystem supplies the retailOS helpers.
pub const DEFAULT_MANAGED_HANDLE_OPS: ManagedHandleOps = ManagedHandleOps {
    create: missing_create,
    release: missing_release,
};

/// Active managed-handle helpers. Written once during target integration;
/// host tests temporarily install recorders.
pub static mut MANAGED_HANDLE_OPS: ManagedHandleOps = DEFAULT_MANAGED_HANDLE_OPS;

/// Volatile table read prevents a target build with only the defaults from
/// folding the seam and erasing its later integration point.
#[inline(always)]
fn managed_handle_ops() -> ManagedHandleOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MANAGED_HANDLE_OPS)) }
}

/// managed_handle_mode — original: `FUN_080e9600` @ 0x080e9600 (72 bytes).
///
/// Mode 0 constructs a managed handle, stores it through `handle_slot`, and
/// returns 2 on success or 0 on allocation/initialization failure. Mode 2
/// releases the handle currently in the slot, clears the slot, and returns 2.
/// Every other mode returns 1 without reading or writing the slot.
///
/// # Deviations
///
/// The constructor @ 0x08062470 and release helper @ 0x08062374 belong to an
/// unported resource subsystem. They are represented by [`MANAGED_HANDLE_OPS`]
/// rather than guessed implementations; its default reports construction
/// failure and makes release inert until target integration wires both calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn managed_handle_mode(mode: i32, handle_slot: *mut *mut u8) -> i32 {
    if mode == 0 {
        let handle = (managed_handle_ops().create)();
        handle_slot.write(handle);
        return if handle.is_null() { 0 } else { 2 };
    }

    if mode != 2 {
        return 1;
    }

    (managed_handle_ops().release)(handle_slot.read());
    handle_slot.write(core::ptr::null_mut());
    2
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CREATE_CALLS: u32 = 0;
    static mut RELEASE_CALLS: u32 = 0;
    static mut RELEASED_HANDLE: *mut u8 = core::ptr::null_mut();
    static mut CREATE_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn mock_create() -> *mut u8 {
        *addr_of_mut!(CREATE_CALLS) += 1;
        addr_of!(CREATE_RESULT).read()
    }

    unsafe extern "C" fn mock_release(handle: *mut u8) {
        *addr_of_mut!(RELEASE_CALLS) += 1;
        addr_of_mut!(RELEASED_HANDLE).write(handle);
    }

    fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CREATE_CALLS).write(0);
            addr_of_mut!(RELEASE_CALLS).write(0);
            addr_of_mut!(RELEASED_HANDLE).write(core::ptr::null_mut());
            addr_of_mut!(CREATE_RESULT).write(core::ptr::null_mut());
            addr_of_mut!(MANAGED_HANDLE_OPS).write(ManagedHandleOps {
                create: mock_create,
                release: mock_release,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(MANAGED_HANDLE_OPS).write(DEFAULT_MANAGED_HANDLE_OPS) };
        drop(guard);
    }

    #[test]
    fn mode_zero_stores_created_handle_and_returns_success_status() {
        let guard = install();
        unsafe {
            let created = 0x1234usize as *mut u8;
            addr_of_mut!(CREATE_RESULT).write(created);
            let mut slot = core::ptr::null_mut();

            assert_eq!(managed_handle_mode(0, &mut slot), 2);
            assert_eq!(slot, created);
            assert_eq!(addr_of!(CREATE_CALLS).read(), 1);
            assert_eq!(addr_of!(RELEASE_CALLS).read(), 0);
        }
        restore(guard);
    }

    #[test]
    fn mode_zero_stores_null_and_returns_allocation_failure_status() {
        let guard = install();
        unsafe {
            let mut slot = 0x1234usize as *mut u8;

            assert_eq!(managed_handle_mode(0, &mut slot), 0);
            assert!(slot.is_null(), "a failed create must overwrite the old slot value");
            assert_eq!(addr_of!(CREATE_CALLS).read(), 1);
            assert_eq!(addr_of!(RELEASE_CALLS).read(), 0);
        }
        restore(guard);
    }

    #[test]
    fn mode_two_releases_slot_handle_clears_slot_and_returns_success_status() {
        let guard = install();
        unsafe {
            let released = 0x5678usize as *mut u8;
            let mut slot = released;

            assert_eq!(managed_handle_mode(2, &mut slot), 2);
            assert!(slot.is_null());
            assert_eq!(addr_of!(CREATE_CALLS).read(), 0);
            assert_eq!(addr_of!(RELEASE_CALLS).read(), 1);
            assert_eq!(addr_of!(RELEASED_HANDLE).read(), released);
        }
        restore(guard);
    }

    #[test]
    fn unsupported_mode_preserves_slot_and_returns_unsupported_status() {
        let guard = install();
        unsafe {
            let retained = 0x9abcusize as *mut u8;
            let mut slot = retained;

            assert_eq!(managed_handle_mode(1, &mut slot), 1);
            assert_eq!(slot, retained);
            assert_eq!(addr_of!(CREATE_CALLS).read(), 0);
            assert_eq!(addr_of!(RELEASE_CALLS).read(), 0);
        }
        restore(guard);
    }
}
