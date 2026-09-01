//! `app_screen_set_layout` — original: `FUN_0817434c` @ `0x0817434c`
//! (28 bytes; **25 direct `bl` call sites**, all unconditional, binary-scanned
//! from `work/firmware/osos.dec`).
//!
//! # Algorithm
//!
//! Assign the supplied [`StringObject`] to the screen object's embedded layout
//! name at target offset `+0x1c`, then tail-enter `FUN_081779c8` with the
//! screen object. The latter is an unported framework notification routine: it
//! dispatches virtual slot `+0x58` twice around `FUN_08177424`, forwarding the
//! final virtual call's result. The direct `bl` to the already-ported
//! `string_object_assign` and the final `b 0x081779c8` are decoded from raw
//! bytes; Ghidra incorrectly folds unrelated code into this function.
//!
//! # Deliberate deviation
//!
//! On ARM the notification remains a call to its retailOS entry. Host builds
//! use [`SCREEN_LAYOUT_ASSIGN_OPS`] because that ROM framework callback cannot
//! run natively. The normal Rust call represents the stock tail branch while
//! preserving its returned value.

#[cfg(not(target_arch = "arm"))]
use core::ptr::addr_of;

use crate::cxx::string_object::{string_object_assign, StringObject};

/// ABI of the unported layout-change framework notification @ `0x081779c8`.
pub type ScreenLayoutChanged = unsafe extern "C" fn(screen: *mut u8) -> *mut u8;

/// Host-model boundary for the notification tail call.
#[derive(Clone, Copy)]
pub struct ScreenLayoutAssignOps {
    pub layout_changed: ScreenLayoutChanged,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_layout_changed(_screen: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Default host behavior until `FUN_081779c8` is ported.
#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_SCREEN_LAYOUT_ASSIGN_OPS: ScreenLayoutAssignOps = ScreenLayoutAssignOps {
    layout_changed: missing_layout_changed,
};

/// Replaceable host boundary for the unported notification routine.
#[cfg(not(target_arch = "arm"))]
pub static mut SCREEN_LAYOUT_ASSIGN_OPS: ScreenLayoutAssignOps = DEFAULT_SCREEN_LAYOUT_ASSIGN_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn layout_changed(screen: *mut u8) -> *mut u8 {
    unsafe { core::ptr::read_volatile(addr_of!(SCREEN_LAYOUT_ASSIGN_OPS.layout_changed))(screen) }
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn layout_changed(screen: *mut u8) -> *mut u8 {
    let retail_notification: ScreenLayoutChanged = unsafe { core::mem::transmute(0x081779c8usize) };
    unsafe { retail_notification(screen) }
}

/// app_screen_set_layout — original: `FUN_0817434c` @ `0x0817434c`
/// (28 bytes; **25 direct `bl` call sites**, all unconditional — zero
/// predicated forms — binary-verified).
///
/// Copies `layout` into the screen's embedded `StringObject`, its seventh
/// 32-bit word (`+0x1c`), then runs the layout-change notification and returns
/// that notification's result. The source is not NULL-guarded: as in stock,
/// `string_object_assign` dereferences a distinct source object.
///
/// # Safety
///
/// `screen` must be writable through its target word index 7, where a valid
/// `StringObject` begins; `layout` must be a valid `StringObject` pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_screen_set_layout(
    screen: *mut u8,
    layout: *const StringObject,
) -> *mut u8 {
    let layout_slot = unsafe { screen.cast::<u32>().add(7).cast::<StringObject>() };
    unsafe { string_object_assign(layout_slot, layout) };
    unsafe { layout_changed(screen) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;
    use crate::testing::SCREEN_LAYOUT_ASSIGN_TEST_LOCK;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALLBACK_SCREEN: AtomicUsize = AtomicUsize::new(0);
    const CALLBACK_RESULT: usize = 0xdecafbad;

    unsafe extern "C" fn recording_layout_changed(screen: *mut u8) -> *mut u8 {
        CALLBACK_SCREEN.store(screen as usize, Ordering::SeqCst);
        CALLBACK_RESULT as *mut u8
    }

    struct OpsRestore(ScreenLayoutAssignOps);

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(SCREEN_LAYOUT_ASSIGN_OPS).write_volatile(self.0);
            }
        }
    }

    #[repr(align(8))]
    struct ScreenBacking([u8; 64]);

    #[test]
    fn assigns_the_embedded_layout_before_notifying() {
        let _guard = SCREEN_LAYOUT_ASSIGN_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        CALLBACK_SCREEN.store(0, Ordering::SeqCst);

        let old_ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCREEN_LAYOUT_ASSIGN_OPS)) };
        unsafe {
            core::ptr::addr_of_mut!(SCREEN_LAYOUT_ASSIGN_OPS).write_volatile(ScreenLayoutAssignOps {
                layout_changed: recording_layout_changed,
            });
        }
        let _restore = OpsRestore(old_ops);

        let mut backing = ScreenBacking([0; 64]);
        // A 32-bit-target screen pointer may be only 4-byte aligned. Starting
        // it at +4 keeps its +0x1c StringObject naturally aligned on this host.
        let screen = unsafe { backing.0.as_mut_ptr().add(4) };
        let embedded = unsafe { screen.add(0x1c).cast::<StringObject>() };
        assert_eq!((embedded as usize) % core::mem::align_of::<StringObject>(), 0);
        unsafe {
            embedded.write(StringObject {
                vtable: &STRING_OBJECT_VTABLE,
                payload: 0x55usize as *mut u8,
            });
        }

        let result = unsafe { app_screen_set_layout(screen, embedded) };

        assert_eq!(result as usize, CALLBACK_RESULT);
        assert_eq!(CALLBACK_SCREEN.load(Ordering::SeqCst), screen as usize);
        // Passing the exact embedded object is self-assignment, so stock's
        // address guard leaves its payload untouched while still notifying.
        assert_eq!(unsafe { (*embedded).payload as usize }, 0x55);
    }
}
