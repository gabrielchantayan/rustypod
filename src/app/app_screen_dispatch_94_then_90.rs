//! Screen singleton virtual-dispatch sequence.
//!
//! Original: `FUN_08229c94` @ `0x08229c94`, 52 bytes, ending before
//! the next function's push at `0x08229cc8`. Raw ARM decoding finds zero
//! plain and two predicated inbound BLs: BLNE at 0x08229ae4 and BLEQ at
//! 0x08229c74. The body has one plain BL to app_screen_get, one BLEQ to
//! heap_panic, one BLX through +0x94, and a tail BX through +0x90.
//!
//! Obtain the screen, reject NULL through the existing nonreturning panic,
//! dispatch +0x94, reload the object's vtable, and dispatch +0x90 on the
//! same object. No identity is inferred for either virtual method.
//! Deliberate deviations: typed repr(C) vtables widen pointers on hosts;
//! the final r0 word is exposed as u32 although Ghidra declares void.
//! The existing singleton port retains its documented constructor caveat.

use core::ptr::addr_of;
use super::singletons::app_screen_get;
use crate::heap::veneers::heap_panic;

pub type ScreenDispatch = unsafe extern "C" fn(*mut ScreenDispatchObject) -> u32;

#[repr(C)]
pub struct ScreenDispatchVtable {
    pub preceding_slots: [usize; 0x90 / 4],
    pub slot_90: ScreenDispatch,
    pub slot_94: ScreenDispatch,
}

#[repr(C)]
pub struct ScreenDispatchObject {
    pub vtable: *const ScreenDispatchVtable,
}

pub static mut APP_SCREEN_DISPATCH_GET: unsafe extern "C" fn() -> *mut u8 = app_screen_get;

/// Dispatches screen slots +0x94 then +0x90, returning the final r0 word.
///
/// # Safety
/// The getter must return NULL or a live screen with callable vtable slots.
/// Slot +0x94 must leave the object and its (possibly replaced) vtable live.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_screen_dispatch_94_then_90() -> u32 {
    let get = unsafe { addr_of!(APP_SCREEN_DISPATCH_GET).read_volatile() };
    let screen = unsafe { get() }.cast::<ScreenDispatchObject>();
    if screen.is_null() {
        unsafe { heap_panic() }
    }
    let first = unsafe { (*(*screen).vtable).slot_94 };
    unsafe { first(screen) };
    let last = unsafe { (*(*screen).vtable).slot_90 };
    unsafe { last(screen) }
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(ScreenDispatchVtable, slot_90) == 0x90);
    assert!(core::mem::offset_of!(ScreenDispatchVtable, slot_94) == 0x94);
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of_mut, null_mut};

    static mut CURRENT: *mut Fixture = null_mut();

    #[repr(C)]
    struct Fixture {
        object: ScreenDispatchObject,
        replacement: *const ScreenDispatchVtable,
        state: u32,
    }

    unsafe extern "C" fn get() -> *mut u8 { unsafe { CURRENT.cast() } }
    unsafe extern "C" fn prepare(object: *mut ScreenDispatchObject) -> u32 {
        let fixture = object.cast::<Fixture>();
        unsafe {
            (*fixture).state = (*fixture).state.wrapping_add(1);
            (*object).vtable = (*fixture).replacement;
        }
        0xdeadbeef
    }
    unsafe extern "C" fn finish(object: *mut ScreenDispatchObject) -> u32 {
        unsafe { (*object.cast::<Fixture>()).state.rotate_left(7) }
    }
    unsafe extern "C" fn stale(_object: *mut ScreenDispatchObject) -> u32 { 0xbad }

    struct Restore(unsafe extern "C" fn() -> *mut u8);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(APP_SCREEN_DISPATCH_GET).write(self.0);
                CURRENT = null_mut();
            }
        }
    }

    #[test]
    fn reloads_replaced_vtable_and_returns_final_result() {
        let original = ScreenDispatchVtable { preceding_slots: [0; 36], slot_90: stale, slot_94: prepare };
        let replacement = ScreenDispatchVtable { preceding_slots: [0; 36], slot_90: finish, slot_94: prepare };
        unsafe {
            let _restore = Restore(addr_of!(APP_SCREEN_DISPATCH_GET).read());
            APP_SCREEN_DISPATCH_GET = get;
            for state in [0, 1, 0x80000000, u32::MAX] {
                for replace in [false, true] {
                    let table = if replace { &original } else { &replacement };
                    let mut fixture = Fixture { object: ScreenDispatchObject { vtable: table }, replacement: &replacement, state };
                    CURRENT = &mut fixture;
                    assert_eq!(app_screen_dispatch_94_then_90(), state.wrapping_add(1).rotate_left(7));
                    assert_eq!(fixture.state, state.wrapping_add(1));
                }
            }
        }
    }
}
