//! `context_secondary_target_set` — original: `FUN_08168350` @ `0x08168350`
//! (28 bytes; true extent `0x08168350..0x0816836b`, followed by the separate
//! `FUN_0816836c` prologue).
//!
//! Raw ARM contains no direct plain or predicated `bl` instructions. Its only
//! call is the predicated indirect `bxne` through target vtable slot `+0x10`.
//! A full-image aligned A32 decode finds two inbound plain `bl` sites
//! (`0x081683b0`, `0x081684f0`) and one predicated `bleq` site (`0x08168394`).
//!
//! Algorithm: store the target-width `target` pointer at `context+0x24`; when
//! it is nonzero, dispatch the target through vtable slot `+0x10` with target
//! in r0.
//!
//! Deliberate deviation: Rust uses a direct call rather than the ARM `bxne`
//! tail dispatch. The vtable callback has no recovered semantic identity;
//! target builds retain its target-width address while host tests install a
//! recording seam.

#[cfg(target_arch = "arm")]
use core::mem;

const CONTEXT_SECONDARY_TARGET_WORD: usize = 0x24 / 4;
const TARGET_VTABLE_NOTIFY_WORD: usize = 0x10 / 4;

type TargetNotify = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_target_notify(_target: *mut u8) {}

#[cfg(not(target_arch = "arm"))]
pub static mut CONTEXT_SECONDARY_TARGET_NOTIFY: TargetNotify = missing_target_notify;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn notify_target(target: u32) {
    let target = target as usize as *mut u32;
    let vtable = core::ptr::read_volatile(target) as usize as *const u32;
    let notify: TargetNotify = mem::transmute(core::ptr::read_volatile(vtable.add(TARGET_VTABLE_NOTIFY_WORD)) as usize);
    notify(target as *mut u8);
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn notify_target(target: u32) {
    let target = target as usize as *mut u8;
    let vtable = core::ptr::read_volatile(target as *const u32) as usize as *const u32;
    let _notify_word = core::ptr::read_volatile(vtable.add(TARGET_VTABLE_NOTIFY_WORD));
    core::ptr::read_volatile(core::ptr::addr_of!(CONTEXT_SECONDARY_TARGET_NOTIFY))(target);
}

/// Stores the secondary target and notifies its vtable slot `+0x10` if non-null.
///
/// # Safety
/// `context` must provide a writable word at `+0x24`. A nonzero `target` must
/// be a target-width pointer to an object with a readable vtable and callable
/// slot `+0x10`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_secondary_target_set(context: *mut u32, target: u32) {
    core::ptr::write_volatile(context.add(CONTEXT_SECONDARY_TARGET_WORD), target);
    if target != 0 {
        notify_target(target);
    }
}

#[cfg(test)]
mod tests {
    use super::{context_secondary_target_set, TargetNotify, CONTEXT_SECONDARY_TARGET_NOTIFY};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut NOTIFIED_TARGET: u32 = 0;

    unsafe extern "C" fn record_target_notify(target: *mut u8) {
        NOTIFIED_TARGET = target as usize as u32;
    }

    struct NotifyRestore(TargetNotify);

    impl Drop for NotifyRestore {
        fn drop(&mut self) {
            unsafe { CONTEXT_SECONDARY_TARGET_NOTIFY = self.0; }
        }
    }

    #[test]
    fn stores_null_target_without_dispatching() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CONTEXT_SECONDARY_TARGET_SET, 0x100) else {
            assert!(note_missing_u32_fixture("context_secondary_target_set"));
            return;
        };
        let context = slab as *mut u32;
        unsafe {
            let previous = CONTEXT_SECONDARY_TARGET_NOTIFY;
            CONTEXT_SECONDARY_TARGET_NOTIFY = record_target_notify;
            let _restore = NotifyRestore(previous);
            NOTIFIED_TARGET = 0xfeed_beef;
            context_secondary_target_set(context, 0);
            assert_eq!(*context.add(9), 0);
            assert_eq!(NOTIFIED_TARGET, 0xfeed_beef);
        }
    }

    #[test]
    fn stores_and_notifies_nonnull_target() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CONTEXT_SECONDARY_TARGET_SET_NON_NULL, 0x200) else {
            assert!(note_missing_u32_fixture("context_secondary_target_set"));
            return;
        };
        let context = slab as *mut u32;
        let target = unsafe { slab.add(0x80) as *mut u32 };
        let vtable = unsafe { slab.add(0xc0) as *mut u32 };
        unsafe {
            *target = vtable as usize as u32;
            *vtable.add(4) = 0x1234_5678;
            let previous = CONTEXT_SECONDARY_TARGET_NOTIFY;
            CONTEXT_SECONDARY_TARGET_NOTIFY = record_target_notify;
            let _restore = NotifyRestore(previous);
            NOTIFIED_TARGET = 0;
            context_secondary_target_set(context, target as usize as u32);
            assert_eq!(*context.add(9), target as usize as u32);
            assert_eq!(NOTIFIED_TARGET, target as usize as u32);
        }
    }
}
