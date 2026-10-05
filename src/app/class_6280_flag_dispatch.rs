//! `class_6280_flag_dispatch` — FUN_081cf650 @ 0x081cf650, 80 bytes
//! (0x081cf650..0x081cf6a0; next function starts with push {r4, lr}).
//! Raw A32 words verify 7 outgoing plain BLs, 0 predicated BLs, two direct
//! tail branches and one BX virtual tail dispatch. Incoming: 1 BL, 1 BLNE.
//!
//! Query the class-0x6280 singleton's +0x2c byte: zero selects the handler
//! at 0x0811c010, one selects 0x0811bd70, all other values dispatch the
//! media-player interface slot +0xac. Reacquire the singleton before each
//! predicate and selected class handler, exactly as the original does.
//! Deviations: Rust discards unspecified tail-call return registers; the
//! unported class handlers use firmware-address seams. Existing singleton
//! ports retain their documented cache/constructor deviations (not hook-ready).

use core::ptr;
use super::singletons::singleton_class_6280;
use super::flag_2c_is_one::flag_2c_is_one;
use crate::ui::flag_2c::flag_2c_is_clear;

#[derive(Clone, Copy)]
pub struct Class6280FlagDispatchOps {
    /// Original 0x0811c010: stores one to +0x2c and posts class events.
    pub set_one: unsafe extern "C" fn(*mut u8),
    /// Original 0x0811bd70: clears +0x2c and updates playback/class events.
    pub clear: unsafe extern "C" fn(*mut u8),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_set_one(object: *mut u8) {
    let handler: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0811_c010usize);
    handler(object);
}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_clear(object: *mut u8) {
    let handler: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0811_bd70usize);
    handler(object);
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_set_one(_: *mut u8) { panic!("firmware class handler unavailable on host"); }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_clear(_: *mut u8) { panic!("firmware class handler unavailable on host"); }

pub static mut CLASS_6280_FLAG_DISPATCH_OPS: Class6280FlagDispatchOps =
    Class6280FlagDispatchOps { set_one: firmware_set_one, clear: firmware_clear };

unsafe fn dispatch(
    mut get: impl FnMut() -> *mut u8,
    mut set_one: impl FnMut(*mut u8),
    mut clear: impl FnMut(*mut u8),
    mut media: impl FnMut(),
) {
    if flag_2c_is_clear(get()) != 0 {
        set_one(get());
    } else if flag_2c_is_one(get()) != 0 {
        clear(get());
    } else {
        media();
    }
}

/// Dispatches by the singleton flag, without consuming the caller's arguments.
///
/// # Safety
/// Singleton results must have a readable +0x2c byte. Selected handlers and
/// the media-player getter/vtable must be live and satisfy their own contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn class_6280_flag_dispatch() {
    dispatch(
        || singleton_class_6280(),
        |object| ptr::read_volatile(ptr::addr_of!(CLASS_6280_FLAG_DISPATCH_OPS.set_one))(object),
        |object| ptr::read_volatile(ptr::addr_of!(CLASS_6280_FLAG_DISPATCH_OPS.clear))(object),
        || {
            use super::media_player_slot_ac_dispatch::MediaPlayerInterfaceSlotAc;
            let interface = super::singletons::media_player_interface_get().cast::<MediaPlayerInterfaceSlotAc>();
            let vtable = ptr::read_volatile(ptr::addr_of!((*interface).vtable));
            ((*vtable).dispatch)(interface);
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn all_flag_values_select_exactly_one_state_transition() {
        for flag in 0u8..=255 {
            let mut object = [0u8; 0xa0];
            object[0x2c] = flag;
            let base = object.as_mut_ptr();
            let media_calls = Cell::new(0);
            unsafe {
                dispatch(|| base,
                    |p| *p.add(0x2c) = 1,
                    |p| *p.add(0x2c) = 0,
                    || media_calls.set(media_calls.get() + 1));
            }
            assert_eq!(object[0x2c], match flag { 0 => 1, 1 => 0, _ => flag });
            assert_eq!(media_calls.get(), u32::from(flag > 1));
            assert!(object[..0x2c].iter().chain(object[0x2d..].iter()).all(|&b| b == 0));
        }
    }

    #[test]
    fn predicates_and_handler_use_fresh_singleton_results() {
        for first in [0u8, 2] {
            let mut objects = [[0u8; 0xa0]; 3];
            objects[0][0x2c] = first;
            objects[1][0x2c] = 1;
            objects[2][0x2c] = 77;
            let pointers = objects.each_mut().map(|o| o.as_mut_ptr());
            let calls = Cell::new(0usize);
            unsafe {
                dispatch(|| { let n = calls.get(); calls.set(n + 1); pointers[n] },
                    |p| *p.add(0x2c) = 9,
                    |p| *p.add(0x2c) = 8,
                    || panic!("second predicate must select the clear handler"));
            }
            if first == 0 {
                assert_eq!(calls.get(), 2);
                assert_eq!(objects[1][0x2c], 9);
                assert_eq!(objects[2][0x2c], 77);
            } else {
                assert_eq!(calls.get(), 3);
                assert_eq!(objects[1][0x2c], 1);
                assert_eq!(objects[2][0x2c], 8);
            }
            assert_eq!(objects[0][0x2c], first);
        }
    }
}
