//! `controller_scoped_notification_refresh` — original: `FUN_08114408` @
//! `0x08114408`.
//!
//! The raw extent is **200 bytes** (`0x08114408..0x081144cf`): 172 bytes of
//! instructions followed by the seven-word literal pool, and the next real
//! function begins at `0x081144d0` with `push {r4, lr}`. Decoding the raw ARM
//! words finds **four plain, unconditional `bl` callers** (two in
//! `FUN_08113a68`, one each in `FUN_08113028` and `FUN_08116e44`) and no
//! predicated `bl` callers. The body has three direct `bl` instructions and
//! three indirect `blx` notifications; its final notification is a tail `bx`.
//!
//! # Algorithm
//!
//! The controller checks its embedded scoped context at `+0x38`. When enabled,
//! it updates the opaque object at `+0x720` and posts `(Strtr, 0x5a05)`. A
//! nonzero byte at `+0x52c` expires when the controller timestamp reaches the
//! wrapping deadline at `+0x524 + 1000`. It then posts `(Strtr, 0x63c1)`,
//! `(Strtr, 0x63c2)`, and `(Cntl, 0x63c3)` through vtable slot `+0x58`.
//!
//! # Deliberate deviations
//!
//! The opaque update helper (`0x081f426c`), timestamp helper (`0x08111488`),
//! and notification slot are retained as target calls. Host builds expose them
//! as replaceable operations, making their order and arguments testable without
//! inventing their unported identities. Target-width words are addressed by
//! byte offset, avoiding host pointer-width layout assumptions.

use core::ptr::{addr_of, read_volatile};

use super::scoped_context::scoped_context_owner_byte_8f_bit_0;

const SCOPED_CONTEXT_OFFSET: usize = 0x38;
const UPDATE_TARGET_OFFSET: usize = 0x720;
const DEADLINE_OFFSET: usize = 0x524;
const EXPIRING_FLAG_OFFSET: usize = 0x52c;
const NOTIFICATION_SLOT: usize = 0x58 / 4;
const START_NOTIFICATION: u32 = 0x5374_7220;
const CONTROL_NOTIFICATION: u32 = 0x436e_746c;
const START_VALUE: u32 = 0x0000_5a05;
const FOLLOW_UP_VALUES: [u32; 2] = [0x0000_63c1, 0x0000_63c2];
const CONTROL_VALUE: u32 = 0x0000_63c3;
const EXPIRY_MILLISECONDS: u32 = 1000;
const RETAIL_UPDATE: usize = 0x081f_426c;
const RETAIL_TIMESTAMP: usize = 0x0811_1488;

pub type ScopedCapability = unsafe extern "C" fn(*const u8) -> u32;
pub type OpaqueUpdate = unsafe extern "C" fn(*mut u8);
pub type ControllerTimestamp = unsafe extern "C" fn(*mut u8) -> u32;
pub type ControllerNotification = unsafe extern "C" fn(*mut u8, u32, u32);

#[derive(Clone, Copy)]
pub struct ControllerScopedNotificationRefreshOps {
    pub capability: ScopedCapability,
    pub update: OpaqueUpdate,
    pub timestamp: ControllerTimestamp,
    pub notify: ControllerNotification,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_capability(controller: *const u8) -> u32 {
    scoped_context_owner_byte_8f_bit_0(controller.add(SCOPED_CONTEXT_OFFSET).cast())
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_update(target: *mut u8) {
    let update: OpaqueUpdate = core::mem::transmute(RETAIL_UPDATE);
    update(target)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_timestamp(controller: *mut u8) -> u32 {
    let timestamp: ControllerTimestamp = core::mem::transmute(RETAIL_TIMESTAMP);
    timestamp(controller)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_notify(controller: *mut u8, notification: u32, value: u32) {
    let vtable = read_volatile(controller.cast::<u32>());
    let notify: ControllerNotification = core::mem::transmute(read_volatile(
        (vtable as *const u32).add(NOTIFICATION_SLOT),
    ));
    notify(controller, notification, value)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_capability(_controller: *const u8) -> u32 {
    panic!("install controller scoped notification refresh host operations")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_update(_target: *mut u8) {
    panic!("install controller scoped notification refresh host operations")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_timestamp(_controller: *mut u8) -> u32 {
    panic!("install controller scoped notification refresh host operations")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_notify(_controller: *mut u8, _notification: u32, _value: u32) {
    panic!("install controller scoped notification refresh host operations")
}

#[cfg(target_os = "none")]
pub const DEFAULT_CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS: ControllerScopedNotificationRefreshOps =
    ControllerScopedNotificationRefreshOps {
        capability: retail_capability,
        update: retail_update,
        timestamp: retail_timestamp,
        notify: retail_notify,
    };
#[cfg(not(target_os = "none"))]
pub const DEFAULT_CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS: ControllerScopedNotificationRefreshOps =
    ControllerScopedNotificationRefreshOps {
        capability: missing_capability,
        update: missing_update,
        timestamp: missing_timestamp,
        notify: missing_notify,
    };

pub static mut CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS: ControllerScopedNotificationRefreshOps =
    DEFAULT_CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS;

#[inline(always)]
fn ops() -> ControllerScopedNotificationRefreshOps {
    unsafe { read_volatile(addr_of!(CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS)) }
}

/// Refreshes the controller's scoped notifications and expires its timed flag.
///
/// # Safety
/// `controller` must designate a retailOS controller covering byte `+0x52c`.
/// On target, it must have a valid scoped context at `+0x38`, target pointer at
/// `+0x720`, and vtable notification slot `+0x58`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_scoped_notification_refresh(controller: *mut u8) {
    let operations = ops();
    if (operations.capability)(controller) != 0 {
        (operations.update)(read_volatile(controller.add(UPDATE_TARGET_OFFSET).cast::<u32>()) as *mut u8);
        (operations.notify)(controller, START_NOTIFICATION, START_VALUE);
    }
    if read_volatile(controller.add(EXPIRING_FLAG_OFFSET)) != 0
        && (operations.timestamp)(controller)
            >= read_volatile(controller.add(DEADLINE_OFFSET).cast::<u32>()).wrapping_add(EXPIRY_MILLISECONDS)
    {
        controller.add(EXPIRING_FLAG_OFFSET).write_volatile(0);
    }
    (operations.notify)(controller, START_NOTIFICATION, FOLLOW_UP_VALUES[0]);
    (operations.notify)(controller, START_NOTIFICATION, FOLLOW_UP_VALUES[1]);
    (operations.notify)(controller, CONTROL_NOTIFICATION, CONTROL_VALUE);
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CAPABILITY: u32 = 0;
    static mut TIMESTAMP: u32 = 0;
    static mut UPDATES: [usize; 2] = [0; 2];
    static mut UPDATE_COUNT: usize = 0;
    static mut NOTIFICATIONS: [(u32, u32); 8] = [(0, 0); 8];
    static mut NOTIFICATION_COUNT: usize = 0;

    unsafe extern "C" fn capability(_controller: *const u8) -> u32 { CAPABILITY }
    unsafe extern "C" fn update(target: *mut u8) {
        UPDATES[UPDATE_COUNT] = target as usize;
        UPDATE_COUNT += 1;
    }
    unsafe extern "C" fn timestamp(_controller: *mut u8) -> u32 { TIMESTAMP }
    unsafe extern "C" fn notify(_controller: *mut u8, notification: u32, value: u32) {
        NOTIFICATIONS[NOTIFICATION_COUNT] = (notification, value);
        NOTIFICATION_COUNT += 1;
    }

    #[test]
    fn enabled_refresh_updates_before_all_four_notifications_and_expires_at_deadline() {
        let _guard = TEST_LOCK.lock();
        let saved = unsafe { CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS };
        unsafe {
            CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS = ControllerScopedNotificationRefreshOps {
                capability,
                update,
                timestamp,
                notify,
            };
            CAPABILITY = 1;
            TIMESTAMP = 998;
            UPDATE_COUNT = 0;
            NOTIFICATION_COUNT = 0;
            let mut controller = [0u8; UPDATE_TARGET_OFFSET + core::mem::size_of::<u32>()];
            controller[EXPIRING_FLAG_OFFSET] = 1;
            controller.as_mut_ptr().add(UPDATE_TARGET_OFFSET).cast::<u32>().write(0x1234_5000);
            controller.as_mut_ptr().add(DEADLINE_OFFSET).cast::<u32>().write(u32::MAX);
            controller_scoped_notification_refresh(controller.as_mut_ptr());
            assert_eq!(UPDATES[..UPDATE_COUNT], [0x1234_5000]);
            assert_eq!(controller[EXPIRING_FLAG_OFFSET], 1, "wrapping deadline is not due at 998");
            TIMESTAMP = 1000;
            controller.as_mut_ptr().add(DEADLINE_OFFSET).cast::<u32>().write(0);
            controller_scoped_notification_refresh(controller.as_mut_ptr());
            assert_eq!(controller[EXPIRING_FLAG_OFFSET], 0);
            assert_eq!(NOTIFICATIONS[..NOTIFICATION_COUNT], [
                (START_NOTIFICATION, START_VALUE),
                (START_NOTIFICATION, FOLLOW_UP_VALUES[0]),
                (START_NOTIFICATION, FOLLOW_UP_VALUES[1]),
                (CONTROL_NOTIFICATION, CONTROL_VALUE),
                (START_NOTIFICATION, START_VALUE),
                (START_NOTIFICATION, FOLLOW_UP_VALUES[0]),
                (START_NOTIFICATION, FOLLOW_UP_VALUES[1]),
                (CONTROL_NOTIFICATION, CONTROL_VALUE),
            ]);
            CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS = saved;
        }
    }

    #[test]
    fn disabled_refresh_skips_update_and_timestamp_when_flag_is_clear() {
        let _guard = TEST_LOCK.lock();
        let saved = unsafe { CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS };
        unsafe {
            CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS = ControllerScopedNotificationRefreshOps {
                capability,
                update,
                timestamp,
                notify,
            };
            CAPABILITY = 0;
            UPDATE_COUNT = 0;
            NOTIFICATION_COUNT = 0;
            let mut controller = [0u8; UPDATE_TARGET_OFFSET + core::mem::size_of::<u32>()];
            controller_scoped_notification_refresh(controller.as_mut_ptr());
            assert_eq!(UPDATE_COUNT, 0);
            assert_eq!(NOTIFICATIONS[..NOTIFICATION_COUNT], [
                (START_NOTIFICATION, FOLLOW_UP_VALUES[0]),
                (START_NOTIFICATION, FOLLOW_UP_VALUES[1]),
                (CONTROL_NOTIFICATION, CONTROL_VALUE),
            ]);
            CONTROLLER_SCOPED_NOTIFICATION_REFRESH_OPS = saved;
        }
    }
}
