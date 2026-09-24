//! Tuning-region status display.
//!
//! `show_tuning_region` — original: `FUN_0811aa6c` @ 0x0811aa6c (72 bytes,
//! exact extent 0x0811aa6c..0x0811aab4; the following bytes are the two
//! NUL-terminated display strings). Raw A32 decoding finds two unconditional
//! direct `bl` calls (`cxx_string_from_cstr` and `cxx_string_release`), no
//! predicated `bl` calls, and one virtual `blx` through controller-vtable slot
//! `+0x11c`; three inbound direct calls are all unconditional. It reads the
//! tuning region byte at `controller[0xbc] + 0x2d`, constructs either
//! `"ShowTuningJapan"` for region 3 or `"ShowTuningWorld"` otherwise, sends
//! that temporary COW string to the virtual display method, then releases it.
//!
//! Deliberate host deviation: target objects use four-byte vtable and state
//! pointers; host tests route the virtual call through a replaceable seam so
//! 64-bit pointers do not change the target layout.

use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

const TUNING_STATE_OFFSET: usize = 0xbc;
const TUNING_REGION_OFFSET: usize = 0x2d;
const DISPLAY_SLOT_OFFSET: usize = 0x11c;
const SHOW_TUNING_JAPAN: &[u8] = b"ShowTuningJapan\0";
const SHOW_TUNING_WORLD: &[u8] = b"ShowTuningWorld\0";

type ShowTuningRegionDisplay = unsafe extern "C" fn(*mut u8, *mut *mut u8);

#[cfg(not(target_os = "none"))]
pub struct ShowTuningRegionOps {
    pub display: ShowTuningRegionDisplay,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_display(_controller: *mut u8, _message: *mut *mut u8) {
    panic!("install tuning-region display host operations before calling show_tuning_region")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_SHOW_TUNING_REGION_OPS: ShowTuningRegionOps = ShowTuningRegionOps { display: missing_display };

#[cfg(not(target_os = "none"))]
pub static mut SHOW_TUNING_REGION_OPS: ShowTuningRegionOps = DEFAULT_SHOW_TUNING_REGION_OPS;

#[cfg(target_os = "none")]
unsafe fn display_tuning_region(controller: *mut u8, message: *mut *mut u8) {
    let vtable = unsafe { controller.cast::<u32>().read() as usize as *const u8 };
    let display: ShowTuningRegionDisplay = unsafe {
        core::mem::transmute(vtable.add(DISPLAY_SLOT_OFFSET).cast::<u32>().read() as usize)
    };
    unsafe { display(controller, message) };
}

/// Displays the tuning-region message selected from the controller state.
///
/// # Safety
/// `controller` must be a valid retailOS controller whose `+0xbc` state
/// pointer and vtable `+0x11c` display slot are readable and callable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn show_tuning_region(controller: *mut u8) {
    #[cfg(target_os = "none")]
    let state = unsafe { controller.add(TUNING_STATE_OFFSET).cast::<u32>().read() as usize as *const u8 };
    #[cfg(not(target_os = "none"))]
    let state = unsafe { controller.add(TUNING_STATE_OFFSET).cast::<usize>().read() as *const u8 };

    let source = if unsafe { state.add(TUNING_REGION_OFFSET).read() } == 3 {
        SHOW_TUNING_JAPAN.as_ptr()
    } else {
        SHOW_TUNING_WORLD.as_ptr()
    };
    let mut message = core::ptr::null_mut();
    unsafe {
        cxx_string_from_cstr(&mut message, source);
        #[cfg(target_os = "none")]
        display_tuning_region(controller, &mut message);
        #[cfg(not(target_os = "none"))]
        core::ptr::read_volatile(core::ptr::addr_of!(SHOW_TUNING_REGION_OPS.display))(controller, &mut message);
        cxx_string_release(&mut message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::SHOW_TUNING_REGION_TEST_LOCK;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret};
    use core::ptr::addr_of_mut;

    static mut SEEN_CONTROLLER: *mut u8 = core::ptr::null_mut();
    static mut SEEN_MESSAGE: [u8; 32] = [0; 32];

    unsafe extern "C" fn record_display(controller: *mut u8, message: *mut *mut u8) {
        unsafe {
            SEEN_CONTROLLER = controller;
            let mut index = 0;
            while (*message).add(index).read() != 0 {
                SEEN_MESSAGE[index] = (*message).add(index).read();
                index += 1;
            }
            SEEN_MESSAGE[index] = 0;
        }
    }

    #[test]
    fn displays_japan_only_for_region_three() {
        let _lock = SHOW_TUNING_REGION_TEST_LOCK.lock();
        let _heap = mock_heap();
        let mut controller = [0u8; TUNING_STATE_OFFSET + core::mem::size_of::<usize>()];
        #[repr(align(4))]
        struct Allocation([u8; 64]);
        let mut allocation = Allocation([0; 64]);
        let mut state = [0u8; TUNING_REGION_OFFSET + 1];
        unsafe {
            addr_of_mut!(SHOW_TUNING_REGION_OPS).write(ShowTuningRegionOps { display: record_display });
            SEEN_CONTROLLER = core::ptr::null_mut();
            set_alloc_ret(allocation.0.as_mut_ptr());
            controller.as_mut_ptr().add(TUNING_STATE_OFFSET).cast::<usize>().write(state.as_mut_ptr() as usize);
            state[TUNING_REGION_OFFSET] = 3;
            show_tuning_region(controller.as_mut_ptr());
            assert_eq!(SEEN_CONTROLLER, controller.as_mut_ptr());
            assert_eq!(&SEEN_MESSAGE[..16], b"ShowTuningJapan\0");

            SEEN_MESSAGE = [0; 32];
            state[TUNING_REGION_OFFSET] = 2;
            show_tuning_region(controller.as_mut_ptr());
            assert_eq!(&SEEN_MESSAGE[..16], b"ShowTuningWorld\0");
        }
    }
}
