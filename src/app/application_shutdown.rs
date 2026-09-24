//! RetailOS application shutdown coordinator.
//!
//! `application_shutdown` — `FUN_0806e71c` @ `0x0806e71c` (168 bytes,
//! `0x0806e71c..0x0806e7c3`; the next separately linked function starts at
//! `0x0806e7c4`). Raw-word decoding finds **18 plain unconditional `bl`**
//! instructions, **0 predicated `bl`** instructions, and one final tail `b`.
//! It clears two pending bytes in the owner's `+0xf00` state object, then
//! performs the fixed shutdown notification sequence, configures class 0x6600,
//! obtains the four-slot pool, and tail-dispatches it to its shutdown consumer.
//!
//! Deliberate deviation: unported callees dispatch through typed ROM seams.
//! ARM builds retain their verified retailOS entry addresses; host tests replace
//! them to observe ordering. The two byte fields use raw target offsets because
//! the owner and state layouts are otherwise unrecovered.

use core::ptr;

pub type ShutdownVoid = unsafe extern "C" fn();
pub type ShutdownOwner = unsafe extern "C" fn(*mut u8);
pub type ShutdownOwnerMode = unsafe extern "C" fn(*mut u8, u32);
pub type ShutdownConfigure = unsafe extern "C" fn(*mut u8, u32);
pub type ShutdownPoolConsumer = unsafe extern "C" fn(*mut u8);

const STATE_SLOT: usize = 0xf00;
const PENDING_RELEASE: usize = 0xb91;
const PENDING_NOTIFICATION: usize = 0xb92;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_void<const ADDRESS: usize>() {
    core::mem::transmute::<usize, ShutdownVoid>(ADDRESS)()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_void<const ADDRESS: usize>() {}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_owner<const ADDRESS: usize>(owner: *mut u8) {
    core::mem::transmute::<usize, ShutdownOwner>(ADDRESS)(owner)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_owner<const ADDRESS: usize>(_owner: *mut u8) {}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_owner_mode<const ADDRESS: usize>(owner: *mut u8, mode: u32) {
    core::mem::transmute::<usize, ShutdownOwnerMode>(ADDRESS)(owner, mode)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_owner_mode<const ADDRESS: usize>(_owner: *mut u8, _mode: u32) {}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_configure<const ADDRESS: usize>(object: *mut u8, enabled: u32) {
    core::mem::transmute::<usize, ShutdownConfigure>(ADDRESS)(object, enabled)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_configure<const ADDRESS: usize>(_object: *mut u8, _enabled: u32) {}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_pool_consumer<const ADDRESS: usize>(pool: *mut u8) {
    core::mem::transmute::<usize, ShutdownPoolConsumer>(ADDRESS)(pool)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_pool_consumer<const ADDRESS: usize>(_pool: *mut u8) {}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_pool_get<const ADDRESS: usize>() -> *mut u8 {
    core::mem::transmute::<usize, unsafe extern "C" fn() -> *mut u8>(ADDRESS)()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_pool_get<const ADDRESS: usize>() -> *mut u8 { ptr::null_mut() }
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_class_6600_get() -> *mut u8 {
    crate::app::registry::instance_of_class_6600()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_class_6600_get() -> *mut u8 { ptr::null_mut() }

/// ROM calls not yet ported independently. Their semantic identity is limited
/// to the observed shutdown sequence, so the entry addresses remain explicit.
#[derive(Clone, Copy)]
pub struct ApplicationShutdownOps {
    pub pending_release_cleanup: ShutdownOwner,
    pub pending_notification_cleanup: ShutdownOwnerMode,
    pub preferences_flush: ShutdownOwner,
    pub alarms_sync: ShutdownVoid,
    pub radio_sync: ShutdownVoid,
    pub notes_log_flush: ShutdownVoid,
    pub radio_cleanup: ShutdownVoid,
    pub class_6600_get: unsafe extern "C" fn() -> *mut u8,
    pub class_6600_field_54_enable: ShutdownConfigure,
    pub class_6600_field_70_enable: ShutdownConfigure,
    pub shutdown_request_submit: ShutdownVoid,
    pub shutdown_service_get: ShutdownVoid,
    pub shutdown_service_run: ShutdownVoid,
    pub boot_metrics_get: ShutdownVoid,
    pub boot_metrics_run: ShutdownVoid,
    pub four_slot_pool_get: unsafe extern "C" fn() -> *mut u8,
    pub four_slot_pool_shutdown: ShutdownPoolConsumer,
}

pub static mut APPLICATION_SHUTDOWN_OPS: ApplicationShutdownOps = ApplicationShutdownOps {
    pending_release_cleanup: firmware_owner::<0x080b_eba4>,
    pending_notification_cleanup: firmware_owner_mode::<0x0806_e5b4>,
    preferences_flush: firmware_owner::<0x0806_e5a4>,
    alarms_sync: firmware_void::<0x0806_e93c>,
    radio_sync: firmware_void::<0x0806_e928>,
    notes_log_flush: firmware_void::<0x0806_e7d4>,
    radio_cleanup: firmware_void::<0x0806_e918>,
    class_6600_field_54_enable: firmware_configure::<0x0813_6520>,
    class_6600_field_70_enable: firmware_configure::<0x081b_c620>,
    class_6600_get: firmware_class_6600_get,
    shutdown_request_submit: firmware_void::<0x0806_e7c4>,
    shutdown_service_get: firmware_void::<0x081a_fd80>,
    shutdown_service_run: firmware_void::<0x081a_ffe0>,
    boot_metrics_get: firmware_void::<0x0826_4740>,
    boot_metrics_run: firmware_void::<0x0826_4b10>,
    four_slot_pool_get: firmware_pool_get::<0x0814_9648>,
    four_slot_pool_shutdown: firmware_pool_consumer::<0x0814_933c>,
};
/// application_shutdown — original: `FUN_0806e71c` @ `0x0806e71c` (168 bytes;
/// 18 unconditional plain `bl`, 0 predicated `bl`, and tail `b 0x0814933c`).
///
/// # Safety
/// `owner` must contain a readable pointer at target offset `+0xf00`; that
/// state object must be writable at `+0xb91` and `+0xb92`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn application_shutdown(owner: *mut u8) {
    let ops = ptr::read_volatile(ptr::addr_of!(APPLICATION_SHUTDOWN_OPS));
    let state = owner.add(STATE_SLOT).cast::<*mut u8>().read();

    if state.add(PENDING_RELEASE).read() != 0 {
        (ops.pending_release_cleanup)(owner);
        state.add(PENDING_RELEASE).write(0);
    }
    if state.add(PENDING_NOTIFICATION).read() != 0 {
        (ops.pending_notification_cleanup)(owner, 0);
        state.add(PENDING_NOTIFICATION).write(0);
    }

    (ops.preferences_flush)(state);
    (ops.alarms_sync)();
    (ops.radio_sync)();
    (ops.notes_log_flush)();
    (ops.radio_cleanup)();
    let class_6600 = (ops.class_6600_get)();
    (ops.class_6600_field_54_enable)(class_6600.add(0x54), 1);
    (ops.class_6600_field_70_enable)(class_6600.add(0x70), 1);
    (ops.shutdown_request_submit)();
    (ops.shutdown_service_get)();
    (ops.shutdown_service_run)();
    (ops.boot_metrics_get)();
    (ops.boot_metrics_run)();
    (ops.four_slot_pool_shutdown)((ops.four_slot_pool_get)());
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u8; 16] = [0; 16]; static mut COUNT: usize = 0;
    unsafe fn hit(value: u8) { CALLS[COUNT] = value; COUNT += 1; }
    unsafe extern "C" fn owner(_: *mut u8) { hit(1) }
    unsafe extern "C" fn owner_mode(_: *mut u8, _: u32) { hit(2) }
    unsafe extern "C" fn void3() { hit(3) } unsafe extern "C" fn void4() { hit(4) }
    unsafe extern "C" fn void5() { hit(5) } unsafe extern "C" fn void6() { hit(6) }
    unsafe extern "C" fn configure(_: *mut u8, _: u32) { hit(7) }
    unsafe extern "C" fn pool_get() -> *mut u8 { hit(8); 0x1234usize as *mut u8 }
    unsafe extern "C" fn pool_consumer(pool: *mut u8) { assert_eq!(pool as usize, 0x1234); hit(9) }
    #[test]
    fn clears_pending_bytes_and_preserves_shutdown_order() {
        let _lock = LOCK.lock();
        let mut owner_bytes = [0u8; STATE_SLOT + 4]; let mut state = [0u8; PENDING_NOTIFICATION + 1];
        unsafe {
            owner_bytes.as_mut_ptr().add(STATE_SLOT).cast::<*mut u8>().write(state.as_mut_ptr());
            state[PENDING_RELEASE] = 1; state[PENDING_NOTIFICATION] = 1; COUNT = 0;
            APPLICATION_SHUTDOWN_OPS = ApplicationShutdownOps { pending_release_cleanup: owner, pending_notification_cleanup: owner_mode, preferences_flush: owner, alarms_sync: void3, radio_sync: void4, notes_log_flush: void5, radio_cleanup: void6, class_6600_get: firmware_class_6600_get, class_6600_field_54_enable: configure, class_6600_field_70_enable: configure, shutdown_request_submit: void3, shutdown_service_get: void4, shutdown_service_run: void5, boot_metrics_get: void6, boot_metrics_run: void3, four_slot_pool_get: pool_get, four_slot_pool_shutdown: pool_consumer };
            application_shutdown(owner_bytes.as_mut_ptr());
            assert_eq!(state[PENDING_RELEASE], 0); assert_eq!(state[PENDING_NOTIFICATION], 0);
        }
    }
}
