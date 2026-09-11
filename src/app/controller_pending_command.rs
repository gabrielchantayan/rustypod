//! `app_controller_begin_command` — original: `FUN_08181110` @ `0x08181110`.
//!
//! **48 bytes**, `0x08181110..0x08181140`: the next function begins with
//! `push {r0-r12, lr}` at `0x08181140`. **9 `bl` call sites**, verified by
//! decoding every ARM B/BL word in `work/firmware/osos.dec`: all nine are
//! unconditional `bl` instructions at `0x08134764`, `0x08225498`,
//! `0x082290f4`, `0x08230824`, `0x082319d0`, `0x08231aa4`, `0x08231b78`,
//! `0x08231c38`, and `0x082323bc`; there are no predicated calls or plain-B
//! tail-call sites.
//!
//! # Algorithm
//!
//! Resolves (and, on a miss, allocates) the controller's 16-byte command
//! record for `(command, 0)` through `FUN_08182c78(controller, command, 0,
//! 1)`. It writes `arg2`, `arg3`, `state`, and `aux` to that record in order,
//! then writes the same four words to the controller's embedded
//! pending-command slot at `+0x88`. There are no NULL guards: both returned
//! record and controller are dereferenced unconditionally.
//!
//! # Deliberate deviations
//!
//! `FUN_08182c78` is not yet ported, so the record resolver is an explicit
//! `read_volatile` dispatch seam. Device builds call its stock body at
//! `0x08182c78`; host tests install a resolver fixture. The observed record
//! and controller layouts use named `#[repr(C)]` fields rather than byte
//! offsets, preserving the ARM target offsets without overlapping host
//! pointers.

/// The four argument words in a controller command record.
#[repr(C)]
pub struct PendingCommandRecord {
    pub arg2: u32,
    pub arg3: u32,
    pub state: u32,
    pub aux: u32,
}

/// The controller prefix observed by [`app_controller_begin_command`].
#[repr(C)]
pub struct AppControllerPendingCommand {
    /// +0x00..+0x87: controller state not observed here.
    pub opaque_00_87: [u32; 34],
    /// +0x88: four-word command data mirrored from the resolved record.
    pub pending_command: PendingCommandRecord,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x88] = [0; core::mem::offset_of!(AppControllerPendingCommand, pending_command)];

/// The unported command-record resolver, `FUN_08182c78` @ `0x08182c78`.
#[derive(Clone, Copy)]
pub struct AppControllerBeginCommandOps {
    /// Resolves the `(command, zero)` record and creates it when `allocate`
    /// is nonzero, matching the raw call's four arguments.
    pub resolve_record: unsafe extern "C" fn(
        *mut AppControllerPendingCommand,
        u32,
        u32,
        u32,
    ) -> *mut PendingCommandRecord,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_resolve_record(
    controller: *mut AppControllerPendingCommand,
    command: u32,
    zero: u32,
    allocate: u32,
) -> *mut PendingCommandRecord {
    let resolve: unsafe extern "C" fn(*mut AppControllerPendingCommand, u32, u32, u32) -> *mut PendingCommandRecord =
        unsafe { core::mem::transmute(0x0818_2c78usize) };
    unsafe { resolve(controller, command, zero, allocate) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resolve_record(
    _controller: *mut AppControllerPendingCommand,
    _command: u32,
    _zero: u32,
    _allocate: u32,
) -> *mut PendingCommandRecord {
    panic!("app_controller_begin_command requires command record resolver 0x08182c78")
}

/// Default resolver wiring for [`APP_CONTROLLER_BEGIN_COMMAND_OPS`].
#[cfg(target_os = "none")]
pub const DEFAULT_APP_CONTROLLER_BEGIN_COMMAND_OPS: AppControllerBeginCommandOps =
    AppControllerBeginCommandOps {
        resolve_record: firmware_resolve_record,
    };

/// Default resolver wiring for [`APP_CONTROLLER_BEGIN_COMMAND_OPS`].
#[cfg(not(target_os = "none"))]
pub const DEFAULT_APP_CONTROLLER_BEGIN_COMMAND_OPS: AppControllerBeginCommandOps =
    AppControllerBeginCommandOps {
        resolve_record: missing_resolve_record,
    };

/// Active implementation of the unported command-record resolver.
pub static mut APP_CONTROLLER_BEGIN_COMMAND_OPS: AppControllerBeginCommandOps =
    DEFAULT_APP_CONTROLLER_BEGIN_COMMAND_OPS;

#[inline(always)]
unsafe fn begin_command_ops() -> AppControllerBeginCommandOps {
    core::ptr::read_volatile(core::ptr::addr_of!(APP_CONTROLLER_BEGIN_COMMAND_OPS))
}

/// Posts a four-word command record and mirrors it at the controller's
/// `+0x88` pending-command slot.
///
/// Original: `FUN_08181110` @ `0x08181110` (48 bytes, **9 unconditional
/// `bl` call sites**, binary-scanned). The resolver return and `controller`
/// are dereferenced without NULL guards, as in retailOS.
///
/// # Safety
///
/// `controller` must be valid through its pending-command field; the active
/// resolver must return a writable [`PendingCommandRecord`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_controller_begin_command(
    controller: *mut AppControllerPendingCommand,
    command: u32,
    arg2: u32,
    arg3: u32,
    state: u32,
    aux: u32,
) {
    let ops = begin_command_ops();
    let record = (ops.resolve_record)(controller, command, 0, 1);
    (*record).arg2 = arg2;
    (*record).arg3 = arg3;
    (*record).state = state;
    (*record).aux = aux;
    (*controller).pending_command.arg2 = arg2;
    (*controller).pending_command.arg3 = arg3;
    (*controller).pending_command.state = state;
    (*controller).pending_command.aux = aux;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOLVED_RECORD: *mut PendingCommandRecord = ptr::null_mut();
    static mut RESOLVE_SEEN: (*mut AppControllerPendingCommand, u32, u32, u32) =
        (ptr::null_mut(), 0, 0, 0);

    unsafe extern "C" fn mock_resolve_record(
        controller: *mut AppControllerPendingCommand,
        command: u32,
        zero: u32,
        allocate: u32,
    ) -> *mut PendingCommandRecord {
        RESOLVE_SEEN = (controller, command, zero, allocate);
        RESOLVED_RECORD
    }

    struct Installed {
        _guard: MutexGuard<'static, ()>,
    }

    unsafe fn install(record: *mut PendingCommandRecord) -> Installed {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        RESOLVED_RECORD = record;
        RESOLVE_SEEN = (ptr::null_mut(), 0, 0, 0);
        APP_CONTROLLER_BEGIN_COMMAND_OPS = AppControllerBeginCommandOps {
            resolve_record: mock_resolve_record,
        };
        Installed { _guard: guard }
    }

    unsafe fn restore() {
        APP_CONTROLLER_BEGIN_COMMAND_OPS = DEFAULT_APP_CONTROLLER_BEGIN_COMMAND_OPS;
        RESOLVED_RECORD = ptr::null_mut();
    }

    fn controller() -> AppControllerPendingCommand {
        AppControllerPendingCommand {
            opaque_00_87: [0xa5a5_a5a5; 34],
            pending_command: PendingCommandRecord {
                arg2: 0x1111_1111,
                arg3: 0x2222_2222,
                state: 0x3333_3333,
                aux: 0x4444_4444,
            },
        }
    }

    #[test]
    fn resolves_allocating_record_and_mirrors_every_argument_word() {
        let mut controller = controller();
        let mut record = PendingCommandRecord {
            arg2: 0,
            arg3: 0,
            state: 0,
            aux: 0,
        };

        unsafe {
            let _installed = install(ptr::addr_of_mut!(record));
            app_controller_begin_command(
                ptr::addr_of_mut!(controller),
                0x0dad_0195,
                0xffff_ffff,
                0x8000_0000,
                0,
                0x7fff_ffff,
            );

            assert_eq!(
                RESOLVE_SEEN,
                (ptr::addr_of_mut!(controller), 0x0dad_0195, 0, 1),
                "the raw resolver call uses zero key extension and allocates"
            );
            assert_eq!(record.arg2, 0xffff_ffff);
            assert_eq!(record.arg3, 0x8000_0000);
            assert_eq!(record.state, 0);
            assert_eq!(record.aux, 0x7fff_ffff);
            assert_eq!(controller.pending_command.arg2, record.arg2);
            assert_eq!(controller.pending_command.arg3, record.arg3);
            assert_eq!(controller.pending_command.state, record.state);
            assert_eq!(controller.pending_command.aux, record.aux);
            assert!(
                controller.opaque_00_87.iter().all(|word| *word == 0xa5a5_a5a5),
                "only controller +0x88..+0x97 is written"
            );
            restore();
        }
    }

    #[test]
    fn overwrites_a_prior_record_without_replacing_the_resolver_result() {
        let mut controller = controller();
        let mut record = PendingCommandRecord {
            arg2: 0xaaaa_aaaa,
            arg3: 0xbbbb_bbbb,
            state: 0xcccc_cccc,
            aux: 0xdddd_dddd,
        };

        unsafe {
            let _installed = install(ptr::addr_of_mut!(record));
            app_controller_begin_command(
                ptr::addr_of_mut!(controller),
                1, 2, 3, 4, 5,
            );

            assert_eq!([record.arg2, record.arg3, record.state, record.aux], [2, 3, 4, 5]);
            assert_eq!(
                [
                    controller.pending_command.arg2,
                    controller.pending_command.arg3,
                    controller.pending_command.state,
                    controller.pending_command.aux,
                ],
                [2, 3, 4, 5]
            );
            restore();
        }
    }
}
