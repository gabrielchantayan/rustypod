//! `app_controller_dispatch_screen` — original: `FUN_08183950` @ `0x08183950`
//! (**72 bytes**, `0x08183950..0x08183998`; `0x08183998` starts the next
//! separately linked function). Raw ARM decoding finds **four** inbound plain
//! `bl` calls and no predicated `bl` calls; its sole direct `bl` is the ported
//! [`command_record_resolve_or_allocate`], followed by a plain-`b` tail call
//! to unported `FUN_0817ee90`.
//!
//! Resolve or allocate the command record keyed by the controller words at
//! `+0x20` and `+0x24`, reset its first two words, store `screen` in word two,
//! set word three to `u32::MAX`, then tail-dispatch that key pair.
//!
//! # Deliberate deviations
//!
//! `FUN_0817ee90` is not ported and its identity is not inferred. Device builds
//! call its verified retailOS address; host builds use the volatile
//! `CONTROLLER_SCREEN_DISPATCH_OPS` boundary. Rust returns normally after that
//! call instead of preserving the ARM tail-branch frame shape.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

use crate::app::controller_pending_command::{
    command_record_resolve_or_allocate, AppControllerPendingCommand,
};

/// Address of the unported pending-command dispatcher `FUN_0817ee90`.
pub const PENDING_COMMAND_DISPATCH_ADDRESS: usize = 0x0817_ee90;

/// ABI of the unported pending-command dispatch tail call.
pub type PendingCommandDispatch = unsafe extern "C" fn(*mut AppControllerPendingCommand, u32, u32);

/// Host-model boundary for the unported pending-command dispatcher.
#[derive(Clone, Copy)]
pub struct ControllerScreenDispatchOps {
    pub dispatch: PendingCommandDispatch,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(
    _controller: *mut AppControllerPendingCommand,
    _first_key: u32,
    _second_key: u32,
) {
    panic!("app_controller_dispatch_screen requires pending-command dispatcher 0x0817ee90")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_CONTROLLER_SCREEN_DISPATCH_OPS: ControllerScreenDispatchOps = ControllerScreenDispatchOps {
    dispatch: missing_dispatch,
};

/// Active host implementation of the unported pending-command dispatcher.
#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_SCREEN_DISPATCH_OPS: ControllerScreenDispatchOps =
    DEFAULT_CONTROLLER_SCREEN_DISPATCH_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_pending_command(
    controller: *mut AppControllerPendingCommand,
    first_key: u32,
    second_key: u32,
) {
    let dispatch = unsafe { core::ptr::read_volatile(addr_of!(CONTROLLER_SCREEN_DISPATCH_OPS.dispatch)) };
    unsafe { dispatch(controller, first_key, second_key) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_pending_command(
    controller: *mut AppControllerPendingCommand,
    first_key: u32,
    second_key: u32,
) {
    let dispatch: PendingCommandDispatch = unsafe { core::mem::transmute(PENDING_COMMAND_DISPATCH_ADDRESS) };
    unsafe { dispatch(controller, first_key, second_key) }
}

/// Prepares and dispatches a screen-targeted pending command.
///
/// # Safety
///
/// `controller` must be valid through its command-map state and the words at
/// `+0x20` and `+0x24`. Those words must identify a record whose resolver slot
/// is writable; the resolved record is written without NULL checks, exactly as
/// retailOS does. The active dispatcher must accept the same controller/key ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.app_controller_dispatch_screen")]
pub unsafe extern "C" fn app_controller_dispatch_screen(
    controller: *mut AppControllerPendingCommand,
    screen: u32,
) {
    let first_key = unsafe { (*controller).opaque_00_3b[8] };
    let second_key = unsafe { (*controller).opaque_00_3b[9] };
    let record = unsafe { command_record_resolve_or_allocate(controller, first_key, second_key, 1) };

    unsafe {
        (*record).arg2 = 0;
        (*record).arg3 = 0;
        (*record).state = screen;
        (*record).aux = u32::MAX;
        dispatch_pending_command(controller, first_key, second_key);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::controller_pending_command::{
        CommandRecordResolverOps, PendingCommandRecord, COMMAND_RECORD_RESOLVER_OPS,
    };
    use core::ptr;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RECORD_SLOT: *mut PendingCommandRecord = ptr::null_mut();
    static mut DISPATCH_SEEN: (*mut AppControllerPendingCommand, u32, u32) = (ptr::null_mut(), 0, 0);

    unsafe extern "C" fn lookup_slot(
        _map: *mut u32,
        _first_key: u32,
        _second_key: u32,
    ) -> *mut *mut PendingCommandRecord {
        ptr::addr_of_mut!(RECORD_SLOT)
    }

    unsafe extern "C" fn dispatch(
        controller: *mut AppControllerPendingCommand,
        first_key: u32,
        second_key: u32,
    ) {
        DISPATCH_SEEN = (controller, first_key, second_key);
    }

    #[test]
    fn resets_and_dispatches_the_existing_keyed_record() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut controller: AppControllerPendingCommand = unsafe { core::mem::zeroed() };
        let mut record = PendingCommandRecord { arg2: 1, arg3: 2, state: 3, aux: 4 };
        controller.opaque_00_3b[8] = 0x1234_5678;
        controller.opaque_00_3b[9] = 0x9abc_def0;

        unsafe {
            let saved_resolver = COMMAND_RECORD_RESOLVER_OPS;
            let saved_dispatch = CONTROLLER_SCREEN_DISPATCH_OPS;
            COMMAND_RECORD_RESOLVER_OPS = CommandRecordResolverOps { lookup_slot };
            CONTROLLER_SCREEN_DISPATCH_OPS = ControllerScreenDispatchOps { dispatch };
            RECORD_SLOT = ptr::addr_of_mut!(record);
            DISPATCH_SEEN = (ptr::null_mut(), 0, 0);

            app_controller_dispatch_screen(ptr::addr_of_mut!(controller), 0xfeed_cafe);

            assert_eq!((record.arg2, record.arg3, record.state, record.aux), (0, 0, 0xfeed_cafe, u32::MAX));
            assert_eq!(DISPATCH_SEEN, (ptr::addr_of_mut!(controller), 0x1234_5678, 0x9abc_def0));
            COMMAND_RECORD_RESOLVER_OPS = saved_resolver;
            CONTROLLER_SCREEN_DISPATCH_OPS = saved_dispatch;
        }
    }
}
