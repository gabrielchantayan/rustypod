//! UI notification virtual-dispatch thunk.

use core::ptr;

/// ARM byte offset of the notification target pointer in the UI owner.
const NOTIFICATION_TARGET_OFFSET: usize = 0x88c;
/// ARM byte offset of the notification method in that target's vtable.
const NOTIFICATION_METHOD_OFFSET: usize = 0x54;

/// ABI observed at the target's vtable slot `+0x54`.
type NotificationMethod = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_os = "none"))]
pub(crate) unsafe extern "C" fn host_notification_method(_target: *mut u8, _event: u32, _one: u32) {}

/// Host-test dispatch seam. The retail vtable method has no recovered semantic
/// identity, so only the observed ABI is named here.
#[cfg(not(target_os = "none"))]
pub static mut UI_NOTIFICATION_METHOD: NotificationMethod = host_notification_method;

/// Dispatches a UI notification through the owner's target vtable.
///
/// Original: `FUN_0811707c` @ `0x0811707c` (20 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec`:
///
/// ```text
/// 0811707c  ldr r0,[r0,#0x88c]
/// 08117080  ldr r2,[r0]
/// 08117084  ldr r3,[r2,#0x54]
/// 08117088  mov r2,#1
/// 0811708c  bx  r3
/// ```
///
/// The next real function begins at `0x08117090`, establishing the 20-byte
/// extent. Decoding every ARM direct-call instruction finds five inbound calls:
/// four unconditional `bl` at `0x08112fa4`, `0x081135b4`, `0x081169d4`, and
/// `0x08116c88`, plus one predicated `blne` at `0x08116c34`.
///
/// Algorithm: load the owner's target pointer at `+0x88c`, then its vtable
/// method at `+0x54`, and tail-dispatch it with the supplied event and constant
/// argument one. The vtable method's semantic identity remains unrecovered.
///
/// Deliberate deviations: host builds route the final call through
/// [`UI_NOTIFICATION_METHOD`] because 64-bit host function pointers cannot fit
/// in the target's four-byte vtable slot; target builds use that slot directly.
///
/// # Safety
///
/// `owner` must reference an ARM-layout object with a readable target pointer
/// at `+0x88c`; that target and its vtable must be readable, and slot `+0x54`
/// must be a valid `NotificationMethod`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_dispatch_notification")]
#[inline(never)]
pub unsafe extern "C" fn ui_dispatch_notification(owner: *mut u8, event: u32) {
    let target = unsafe {
        ptr::read_volatile(owner.add(NOTIFICATION_TARGET_OFFSET).cast::<u32>()) as usize as *mut u8
    };
    let vtable = unsafe { ptr::read_volatile(target.cast::<u32>()) as usize as *const u8 };

    #[cfg(target_os = "none")]
    let method: NotificationMethod = unsafe {
        core::mem::transmute(ptr::read_volatile(vtable.add(NOTIFICATION_METHOD_OFFSET).cast::<u32>()) as usize)
    };
    #[cfg(not(target_os = "none"))]
    let method = unsafe { ptr::read_volatile(ptr::addr_of!(UI_NOTIFICATION_METHOD)) };

    unsafe { method(target, event, 1) };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    const FIXTURE_LEN: usize = 0x1000;
    const TARGET_OFFSET: usize = 0x900;
    const VTABLE_OFFSET: usize = 0x980;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RECEIVED_TARGET: *mut u8 = ptr::null_mut();
    static mut RECEIVED_EVENT: u32 = 0;
    static mut RECEIVED_ONE: u32 = 0;

    unsafe extern "C" fn recording_method(target: *mut u8, event: u32, one: u32) {
        unsafe {
            CALLS += 1;
            RECEIVED_TARGET = target;
            RECEIVED_EVENT = event;
            RECEIVED_ONE = one;
        }
    }

    #[test]
    fn dispatches_target_vtable_notification_with_constant_one() {
        let _guard = LOCK.lock();
        let Some(owner) = try_map_u32_slab(hints::UI_NOTIFICATION_DISPATCH, FIXTURE_LEN) else {
            assert!(note_missing_u32_fixture("ui/notification_dispatch"));
            return;
        };
        let target = unsafe { owner.add(TARGET_OFFSET) };
        let vtable = unsafe { owner.add(VTABLE_OFFSET) };
        unsafe {
            owner.write_bytes(0, FIXTURE_LEN);
            owner.add(NOTIFICATION_TARGET_OFFSET).cast::<u32>().write(target as usize as u32);
            target.cast::<u32>().write(vtable as usize as u32);
            CALLS = 0;
            RECEIVED_TARGET = ptr::null_mut();
            RECEIVED_EVENT = 0;
            RECEIVED_ONE = 0;
            UI_NOTIFICATION_METHOD = recording_method;
            ui_dispatch_notification(owner, 0xfeed_beef);
            assert_eq!(CALLS, 1);
            assert_eq!(RECEIVED_TARGET, target);
            assert_eq!(RECEIVED_EVENT, 0xfeed_beef);
            assert_eq!(RECEIVED_ONE, 1);
            UI_NOTIFICATION_METHOD = host_notification_method;
        }
    }
}
