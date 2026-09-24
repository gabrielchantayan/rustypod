//! Refreshes a UI owner's notification state.

use core::ptr;

use super::notification_dispatch::ui_dispatch_notification;

const SAVED_EVENT_OFFSET: usize = 0x734;
const CURRENT_EVENT_OFFSET: usize = 0x73c;
const NOTIFICATION_TARGET_OFFSET: usize = 0x88c;
const PENDING_FLAG_OFFSET: usize = 0x884;

type TargetStateChanged = unsafe extern "C" fn(*mut u8) -> u32;
type OwnerEventOperation = unsafe extern "C" fn(*mut u8, u32);
type TargetEventReplacement = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_target_state_changed(target: *mut u8) -> u32 {
    let callee: TargetStateChanged = unsafe { core::mem::transmute(0x0811_6dacusize) };
    unsafe { callee(target) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_owner_event_cleanup(owner: *mut u8, event: u32) {
    let callee: OwnerEventOperation = unsafe { core::mem::transmute(0x0811_190cusize) };
    unsafe { callee(owner, event) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_owner_event_changed(owner: *mut u8, event: u32) {
    let callee: OwnerEventOperation = unsafe { core::mem::transmute(0x0811_6574usize) };
    unsafe { callee(owner, event) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_target_state_changed(_: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owner_event_operation(_: *mut u8, _: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_target_event_replacement(_: *mut u8) -> u32 { 0 }

#[cfg(target_os = "none")]
static mut TARGET_STATE_CHANGED: TargetStateChanged = firmware_target_state_changed;
#[cfg(target_os = "none")]
static mut OWNER_EVENT_CLEANUP: OwnerEventOperation = firmware_owner_event_cleanup;
#[cfg(target_os = "none")]
static mut OWNER_EVENT_CHANGED: OwnerEventOperation = firmware_owner_event_changed;
#[cfg(not(target_os = "none"))]
pub static mut TARGET_STATE_CHANGED: TargetStateChanged = missing_target_state_changed;
#[cfg(not(target_os = "none"))]
pub static mut OWNER_EVENT_CLEANUP: OwnerEventOperation = missing_owner_event_operation;
#[cfg(not(target_os = "none"))]
pub static mut OWNER_EVENT_CHANGED: OwnerEventOperation = missing_owner_event_operation;
#[cfg(not(target_os = "none"))]
pub static mut TARGET_EVENT_REPLACEMENT: TargetEventReplacement = missing_target_event_replacement;

/// Updates the owner's saved notification event and clears its pending flag.
///
/// Original: `FUN_081169a0` @ `0x081169a0` (92 bytes,
/// `0x081169a0..0x081169fb`). Raw A32 decoding establishes four outgoing
/// plain `bl` instructions (`0x08116dac`, `0x0811190c`, `0x08116574`, and
/// `0x0811707c`), one indirect `blx` through target vtable slot `+0x5c`, and
/// three inbound plain BL callers (`0x08202eb8`, `0x08202fdc`, `0x0820e8d8`);
/// no predicated BL forms occur. The next real function begins at `0x081169fc`.
///
/// Algorithm: ask the target whether its state changed. If it did, perform the
/// two observed owner/event operations for the current event. Dispatch the
/// saved event as a notification, replace it through target vtable slot `+0x5c`,
/// clear owner byte `+0x884`, and return the change predicate's result.
///
/// Deliberate deviations: unrecovered direct callees remain address-named only
/// by their observed ABI and are host-test seams. Host builds similarly replace
/// the four-byte target vtable function pointer with [`TARGET_EVENT_REPLACEMENT`].
///
/// # Safety
///
/// `owner` must reference the ARM-layout fields described above; its target and
/// vtable must be valid for the observed calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_refresh_notification_state")]
#[inline(never)]
pub unsafe extern "C" fn ui_refresh_notification_state(owner: *mut u8) -> u32 {
    let target = unsafe { ptr::read_volatile(owner.add(NOTIFICATION_TARGET_OFFSET).cast::<u32>()) as usize as *mut u8 };
    let changed = unsafe { TARGET_STATE_CHANGED(target) };
    if changed != 0 {
        let event = unsafe { ptr::read_volatile(owner.add(CURRENT_EVENT_OFFSET).cast::<u32>()) };
        unsafe { OWNER_EVENT_CLEANUP(owner, event) };
        unsafe { OWNER_EVENT_CHANGED(owner, event) };
    }
    let saved_event = unsafe { ptr::read_volatile(owner.add(SAVED_EVENT_OFFSET).cast::<u32>()) };
    unsafe { ui_dispatch_notification(owner, saved_event) };
    #[cfg(target_os = "none")]
    let replacement = unsafe {
        let vtable = ptr::read_volatile(target.cast::<u32>()) as usize as *const u8;
        let method: TargetEventReplacement = core::mem::transmute(ptr::read_volatile(vtable.add(0x5c).cast::<u32>()) as usize);
        method(target)
    };
    #[cfg(not(target_os = "none"))]
    let replacement = unsafe { TARGET_EVENT_REPLACEMENT(target) };
    unsafe {
        ptr::write_volatile(owner.add(SAVED_EVENT_OFFSET).cast::<u32>(), replacement);
        ptr::write_volatile(owner.add(PENDING_FLAG_OFFSET), 0);
    }
    changed
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    const FIXTURE_LEN: usize = 0x1000;
    const TARGET_OFFSET: usize = 0x900;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CHANGED: u32 = 0;
    static mut CLEANUP_CALLS: u32 = 0;
    static mut CHANGED_CALLS: u32 = 0;
    static mut NOTIFIED_EVENT: u32 = 0;
    static mut REPLACEMENT_TARGET: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn state_changed(_: *mut u8) -> u32 { unsafe { CHANGED } }
    unsafe extern "C" fn cleanup(_: *mut u8, event: u32) { unsafe { CLEANUP_CALLS += 1; assert_eq!(event, 0xaabb_ccdd) } }
    unsafe extern "C" fn event_changed(_: *mut u8, event: u32) { unsafe { CHANGED_CALLS += 1; assert_eq!(event, 0xaabb_ccdd) } }
    unsafe extern "C" fn notification(_: *mut u8, event: u32, one: u32) { unsafe { assert_eq!(one, 1); NOTIFIED_EVENT = event } }
    unsafe extern "C" fn replacement(target: *mut u8) -> u32 { unsafe { REPLACEMENT_TARGET = target; 0x1122_3344 } }

    #[test]
    fn refreshes_changed_state_and_replaces_saved_event() {
        let _guard = LOCK.lock();
        let Some(owner) = try_map_u32_slab(hints::UI_REFRESH_NOTIFICATION_STATE, FIXTURE_LEN) else { assert!(note_missing_u32_fixture("ui/refresh_notification_state")); return; };
        unsafe {
            owner.write_bytes(0, FIXTURE_LEN);
            let target = owner.add(TARGET_OFFSET);
            owner.add(NOTIFICATION_TARGET_OFFSET).cast::<u32>().write(target as usize as u32);
            owner.add(CURRENT_EVENT_OFFSET).cast::<u32>().write(0xaabb_ccdd);
            owner.add(SAVED_EVENT_OFFSET).cast::<u32>().write(0xfeed_beef);
            owner.add(PENDING_FLAG_OFFSET).write(1);
            CHANGED = 1; CLEANUP_CALLS = 0; CHANGED_CALLS = 0; NOTIFIED_EVENT = 0; REPLACEMENT_TARGET = ptr::null_mut();
            TARGET_STATE_CHANGED = state_changed; OWNER_EVENT_CLEANUP = cleanup; OWNER_EVENT_CHANGED = event_changed;
            super::super::notification_dispatch::UI_NOTIFICATION_METHOD = notification;
            TARGET_EVENT_REPLACEMENT = replacement;
            assert_eq!(ui_refresh_notification_state(owner), 1);
            assert_eq!(CLEANUP_CALLS, 1); assert_eq!(CHANGED_CALLS, 1); assert_eq!(NOTIFIED_EVENT, 0xfeed_beef);
            assert_eq!(REPLACEMENT_TARGET, target); assert_eq!(owner.add(SAVED_EVENT_OFFSET).cast::<u32>().read(), 0x1122_3344); assert_eq!(owner.add(PENDING_FLAG_OFFSET).read(), 0);
            TARGET_STATE_CHANGED = missing_target_state_changed; OWNER_EVENT_CLEANUP = missing_owner_event_operation; OWNER_EVENT_CHANGED = missing_owner_event_operation;
            super::super::notification_dispatch::UI_NOTIFICATION_METHOD = super::super::notification_dispatch::host_notification_method;
            TARGET_EVENT_REPLACEMENT = missing_target_event_replacement;
        }
    }

    #[test]
    fn skips_owner_event_operations_when_state_is_unchanged() {
        let _guard = LOCK.lock();
        let Some(owner) = try_map_u32_slab(hints::UI_REFRESH_NOTIFICATION_STATE, FIXTURE_LEN) else { assert!(note_missing_u32_fixture("ui/refresh_notification_state")); return; };
        unsafe {
            owner.write_bytes(0, FIXTURE_LEN); owner.add(NOTIFICATION_TARGET_OFFSET).cast::<u32>().write(owner.add(TARGET_OFFSET) as usize as u32);
            CHANGED = 0; CLEANUP_CALLS = 0; CHANGED_CALLS = 0; TARGET_STATE_CHANGED = state_changed; OWNER_EVENT_CLEANUP = cleanup; OWNER_EVENT_CHANGED = event_changed; TARGET_EVENT_REPLACEMENT = replacement;
            assert_eq!(ui_refresh_notification_state(owner), 0); assert_eq!(CLEANUP_CALLS, 0); assert_eq!(CHANGED_CALLS, 0);
            TARGET_STATE_CHANGED = missing_target_state_changed; OWNER_EVENT_CLEANUP = missing_owner_event_operation; OWNER_EVENT_CHANGED = missing_owner_event_operation; TARGET_EVENT_REPLACEMENT = missing_target_event_replacement;
        }
    }
}
