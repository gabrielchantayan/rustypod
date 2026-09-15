//! Base interface-guard scoped dispatch.

use core::mem::MaybeUninit;

use crate::app::path_probe::{
    interface_guard_base_construct, interface_guard_base_destroy, InterfaceGuard,
};

/// Firmware load address of the unresolved operation invoked with the guard's
/// resolved interface word.
pub const INTERFACE_GUARD_OPERATION_ADDRESS: usize = 0x0829_71bc;

/// The unresolved `FUN_082971bc` operation ABI.
pub type InterfaceGuardOperation = unsafe extern "C" fn(interface: u32, guard: *mut InterfaceGuard) -> u32;

unsafe extern "C" fn firmware_interface_guard_operation(
    interface: u32,
    guard: *mut InterfaceGuard,
) -> u32 {
    #[cfg(target_os = "none")]
    {
        let operation: InterfaceGuardOperation = core::mem::transmute(INTERFACE_GUARD_OPERATION_ADDRESS);
        operation(interface, guard)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = interface;
        let _ = guard;
        0
    }
}

/// Active boundary for the unported operation at [`INTERFACE_GUARD_OPERATION_ADDRESS`].
pub static mut INTERFACE_GUARD_OPERATION: InterfaceGuardOperation = firmware_interface_guard_operation;

#[inline(always)]
unsafe fn interface_guard_operation_fn() -> InterfaceGuardOperation {
    core::ptr::read_volatile(core::ptr::addr_of!(INTERFACE_GUARD_OPERATION))
}

/// interface_guard_base_dispatch — original: `FUN_080ef4b4` @ 0x080ef4b4
/// (52 bytes; **five inbound direct `bl` call sites: four plain and one
/// `bleq`; no direct tail branches**).
///
/// Constructs the 12-byte common interface guard over its spill frame with
/// `base_hint` and flag zero, passes its resolved interface word and storage to
/// `FUN_082971bc`, destroys the guard, and returns that operation's status.
/// The three internal calls are the shared constructor @ 0x0818a0c4, the
/// operation @ 0x082971bc, and the base destructor @ 0x0818a0fc.
///
/// Deliberate deviation: `FUN_082971bc` has no established semantic identity,
/// so it remains a fixed-address volatile dispatch boundary. Host builds use a
/// zero-status default; tests install a recorder. Rust's ABI frame replaces
/// the ARM r1-r5 spill frame while preserving the constructed guard, call
/// order, arguments, teardown, and returned status.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.interface_guard_base_dispatch")]
pub unsafe extern "C" fn interface_guard_base_dispatch(base_hint: u32) -> u32 {
    let mut storage = MaybeUninit::<InterfaceGuard>::uninit();
    let guard = interface_guard_base_construct(storage.as_mut_ptr(), base_hint, 0);
    let interface = core::ptr::addr_of!((*guard).words[1]).read_volatile();
    let status = interface_guard_operation_fn()(interface, guard);
    interface_guard_base_destroy(guard);
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED_INTERFACE: u32 = 0;
    static mut OBSERVED_GUARD: *mut InterfaceGuard = core::ptr::null_mut();
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn recording_operation(interface: u32, guard: *mut InterfaceGuard) -> u32 {
        OBSERVED_INTERFACE = interface;
        OBSERVED_GUARD = guard;
        RESULT
    }

    struct OperationGuard(InterfaceGuardOperation);

    impl OperationGuard {
        unsafe fn install() -> Self {
            let saved = core::ptr::addr_of!(INTERFACE_GUARD_OPERATION).read_volatile();
            core::ptr::addr_of_mut!(INTERFACE_GUARD_OPERATION).write_volatile(recording_operation);
            OperationGuard(saved)
        }
    }

    impl Drop for OperationGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(INTERFACE_GUARD_OPERATION).write_volatile(self.0);
            }
        }
    }

    #[test]
    fn constructs_dispatches_and_tears_down_a_base_guard() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let _operation = OperationGuard::install();
            OBSERVED_INTERFACE = u32::MAX;
            OBSERVED_GUARD = core::ptr::null_mut();
            RESULT = 0x52;

            assert_eq!(interface_guard_base_dispatch(0), 0x52);
            assert_eq!(OBSERVED_INTERFACE, 0);
            assert!(!OBSERVED_GUARD.is_null());
            assert_eq!((*OBSERVED_GUARD).words[0], 0x0898_994c);
            assert_eq!((*OBSERVED_GUARD).words[1], 0);
            assert_eq!((OBSERVED_GUARD as *const u8).add(8).read(), 0);
            assert_eq!((OBSERVED_GUARD as *const u8).add(9).read(), 0);
        }
    }
}
