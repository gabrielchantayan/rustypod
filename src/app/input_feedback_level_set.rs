//! Input-feedback level transition — `FUN_08293714` at `0x08293714`.
//! True extent: 96 bytes (92 bytes of code, literal at `0x08293770`;
//! next independently entered function at `0x08293774`). Two inbound plain
//! BLs, no predicated callers. Body: two plain BLs, one BLNE, one BEQ tail call.
//!
//! Clean up the current sequence, clear its index, update feedback with delta
//! 100, and publish the requested level at `0x089d04a8`. Zero delegates to the
//! retail zero-level transition at `0x08293774`; every other value selects mode
//! 4. UINT_MAX skips the audio call; other nonzero values call it with apply=0.
//! Deliberate deviations: volatile state/global access preserves ordering;
//! host builds replace cleanup/feedback/zero-transition calls because the
//! cleanup port uses a different native-pointer host layout and retail globals
//! are unmapped. Target builds reuse the existing named ports.

use core::ptr;

#[cfg(not(target_os = "none"))]
type ControllerAction = unsafe extern "C" fn(*mut u8);
#[cfg(not(target_os = "none"))]
type FeedbackAction = unsafe extern "C" fn(*mut u8, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_controller_action(_: *mut u8) {
    panic!("install input-feedback controller host operations");
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_feedback_action(_: *mut u8, _: u32) {
    panic!("install input-feedback controller host operations");
}

#[cfg(not(target_os = "none"))]
pub struct HostLevelOps {
    pub cleanup: ControllerAction,
    pub feedback: FeedbackAction,
    pub zero_transition: ControllerAction,
}
#[cfg(not(target_os = "none"))]
pub static mut HOST_LEVEL_OPS: HostLevelOps = HostLevelOps {
    cleanup: unavailable_controller_action,
    feedback: unavailable_feedback_action,
    zero_transition: unavailable_controller_action,
};
#[cfg(not(target_os = "none"))]
static mut HOST_REQUESTED_LEVEL: u32 = 0;

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn input_delta_feedback_update(state: *mut u8, delta: u32);
}

/// # Safety
/// `controller` must be an aligned retail controller valid through +0xc7,
/// including every object required by cleanup. Retail globals must be valid.
/// Host callers must install operations accepting the same byte-layout fixture.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_feedback_level_set(controller: *mut u8, level: u32) {
    #[cfg(target_os = "none")]
    super::app_state_cleanup::app_state_cleanup(controller);
    #[cfg(not(target_os = "none"))]
    (HOST_LEVEL_OPS.cleanup)(controller);

    controller.add(0xc4).cast::<u32>().write_volatile(0);
    #[cfg(target_os = "none")]
    input_delta_feedback_update(controller, 100);
    #[cfg(not(target_os = "none"))]
    (HOST_LEVEL_OPS.feedback)(controller, 100);

    #[cfg(target_os = "none")]
    let requested_level = 0x089d_04a8 as *mut u32;
    #[cfg(not(target_os = "none"))]
    let requested_level = ptr::addr_of_mut!(HOST_REQUESTED_LEVEL);
    requested_level.write_volatile(level);

    if level == 0 {
        #[cfg(target_os = "none")]
        {
            let zero_transition: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0829_3774usize);
            zero_transition(controller);
        }
        #[cfg(not(target_os = "none"))]
        (HOST_LEVEL_OPS.zero_transition)(controller);
        return;
    }
    if level != u32::MAX {
        let output = controller.add(0x34).cast::<u32>().read_volatile() as *mut u8;
        crate::drivers::audio_output_level::audio_output_set_level(output, level, 0);
    }
    controller.add(0xc1).write_volatile(4);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn cleanup(controller: *mut u8) {
        assert_eq!(controller.add(0xc4).cast::<u32>().read(), 7);
        controller.add(0x60).write(1);
    }
    unsafe extern "C" fn feedback(controller: *mut u8, delta: u32) {
        assert_eq!(delta, 100);
        assert_eq!(controller.add(0xc4).cast::<u32>().read(), 0);
        assert_eq!(controller.add(0x60).read(), 1);
        controller.add(0x61).write(0);
    }
    unsafe extern "C" fn zero_transition(controller: *mut u8) {
        assert_eq!(ptr::addr_of!(HOST_REQUESTED_LEVEL).read(), 0);
        assert_eq!(controller.add(0x61).read(), 0);
        controller.add(0xc1).write(3);
        // A delegate's state writes must not be overwritten on return.
        controller.add(0xc4).cast::<u32>().write(9);
    }

    #[test]
    fn zero_delegates_nonzero_and_sentinel_select_mode_four() {
        unsafe {
            let saved = ptr::addr_of!(HOST_LEVEL_OPS).read();
            HOST_LEVEL_OPS = HostLevelOps { cleanup, feedback, zero_transition };
            for level in [0, 1, 127, 128, u32::MAX - 1, u32::MAX] {
                let mut controller = [0xa5a5_a5a5u32; 0xc8 / 4];
                let bytes = controller.as_mut_ptr().cast::<u8>();
                bytes.add(0xc4).cast::<u32>().write(7);
                input_feedback_level_set(bytes, level);
                assert_eq!(ptr::addr_of!(HOST_REQUESTED_LEVEL).read(), level);
                assert_eq!(bytes.add(0xc1).read(), if level == 0 { 3 } else { 4 });
                assert_eq!(bytes.add(0xc4).cast::<u32>().read(), if level == 0 { 9 } else { 0 });
                assert_eq!(bytes.add(0x61).read(), 0);
                assert_eq!(bytes.add(0xc0).read(), 0xa5);
                assert_eq!(bytes.add(0xc2).read(), 0xa5);
            }
            HOST_LEVEL_OPS = saved;
        }
    }
}
