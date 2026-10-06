//! `app_controller_dispatch_screen` — `FUN_08183950` @ `0x08183950`.
//! Raw extent 72 bytes; four incoming plain BLs, zero predicated BLs.
//! Resolve or allocate the keyed record, reset its first two words, store
//! the screen and sentinel, then call the ported pending-command applicator.
//! Deviation: Rust uses a returning call rather than the original tail B.

use crate::app::controller_pending_command::{
    command_record_resolve_or_allocate, app_controller_apply_pending_command,
    AppControllerPendingCommand,
};

/// Prepares and applies a screen-targeted pending command.
///
/// # Safety
/// The controller and its keyed record must be writable and its selection
/// object must satisfy `app_controller_apply_pending_command`'s contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.app_controller_dispatch_screen")]
pub unsafe extern "C" fn app_controller_dispatch_screen(
    controller: *mut AppControllerPendingCommand,
    screen: u32,
) {
    let first_key = (*controller).opaque_00_3b[8];
    let second_key = (*controller).opaque_00_3b[9];
    let record = command_record_resolve_or_allocate(controller, first_key, second_key, 1);
    (*record).arg2 = 0;
    (*record).arg3 = 0;
    (*record).state = screen;
    (*record).aux = u32::MAX;
    app_controller_apply_pending_command(controller, first_key, second_key);
}
