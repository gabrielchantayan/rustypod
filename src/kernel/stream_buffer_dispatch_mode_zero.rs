//! Dispatch a stream-buffer mode-zero event.
//!
//! Port: [`stream_buffer_dispatch_mode_zero`] — original: `FUN_08007260` @
//! `0x08007260` (36 bytes, `0x08007260..0x08007283`; the next independently
//! decoded function starts at `0x08007284`). Raw words are
//! `e92d4010 e1a04000 ebfff76a e3a01000 ebfff7ef e1a00004 e8bd4010
//! e3a01000 eaffffca`. The body has two unconditional outgoing `bl`
//! instructions, one unconditional tail `b`, and no predicated outgoing calls.
//! Decoding all direct incoming calls finds four `blne` sites (`0x08006bf4`,
//! `0x08006ca8`, `0x08006d60`, and `0x08006e34`): zero plain and four
//! predicated calls.
//!
//! ## Algorithm
//!
//! Initialize the shared UI manager, invoke the stream buffer's unported
//! mode-zero dispatch entry with the original stream-buffer pointer in `r0`
//! and zero in `r1`, then tail-dispatch to `stream_buffer_set_page_contexts`
//! with that same pointer and zero context.
//!
//! ## Deliberate deviations
//!
//! The mode-zero dispatch entry at `0x08005234` is not independently ported.
//! Target builds call both recovered targets directly; host builds expose
//! recording seams for their call boundaries.

use crate::kernel::stream_buffer_page_contexts::stream_buffer_set_page_contexts;
#[cfg(target_os = "none")]
use crate::ui::manager::ui_manager_instance;

/// ABI of the existing UI-manager initializer.
pub type UiManagerInitialize = unsafe extern "C" fn() -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_ui_manager_initialize() -> *mut u8 {
    ui_manager_instance()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ui_manager_initialize() -> *mut u8 {
    core::ptr::null_mut()
}

/// Host seam for the existing UI-manager initializer.
#[cfg(not(target_os = "none"))]
pub static mut UI_MANAGER_INITIALIZE: UiManagerInitialize = missing_ui_manager_initialize;

#[inline(always)]
unsafe fn ui_manager_initialize() -> UiManagerInitialize {
    #[cfg(target_os = "none")]
    {
        firmware_ui_manager_initialize
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(UI_MANAGER_INITIALIZE))
    }
}

/// ABI of the unported stream-buffer mode dispatch at `0x08005234`.
pub type StreamBufferModeDispatch = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_stream_buffer_mode_dispatch(stream_buffer: *mut u8, mode: u32) {
    let dispatch: StreamBufferModeDispatch = core::mem::transmute(0x0800_5234usize);
    dispatch(stream_buffer, mode);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_stream_buffer_mode_dispatch(_stream_buffer: *mut u8, _mode: u32) {}

/// Host seam for the unported mode-zero dispatch entry.
#[cfg(not(target_os = "none"))]
pub static mut STREAM_BUFFER_MODE_DISPATCH: StreamBufferModeDispatch = missing_stream_buffer_mode_dispatch;

#[inline(always)]
unsafe fn stream_buffer_mode_dispatch() -> StreamBufferModeDispatch {
    #[cfg(target_os = "none")]
    {
        firmware_stream_buffer_mode_dispatch
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(STREAM_BUFFER_MODE_DISPATCH))
    }
}

/// `stream_buffer_dispatch_mode_zero` — original: `FUN_08007260` @ `0x08007260`.
///
/// Initializes the shared UI manager, dispatches mode zero for `stream_buffer`,
/// then clears its fallback and all 32 page contexts through the existing
/// `stream_buffer_set_page_contexts` port.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_buffer_dispatch_mode_zero")]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_dispatch_mode_zero(stream_buffer: *mut u8) {
    ui_manager_initialize()();
    stream_buffer_mode_dispatch()(stream_buffer, 0);
    stream_buffer_set_page_contexts(stream_buffer, 0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVED_STREAM_BUFFER: *mut u8 = core::ptr::null_mut();
    static mut RECEIVED_MODE: u32 = u32::MAX;
    static mut DISPATCH_COUNT: u32 = 0;
    static mut UI_MANAGER_INITIALIZE_COUNT: u32 = 0;

    unsafe extern "C" fn record_ui_manager_initialize() -> *mut u8 {
        UI_MANAGER_INITIALIZE_COUNT += 1;
        core::ptr::null_mut()
    }

    unsafe extern "C" fn record_dispatch(stream_buffer: *mut u8, mode: u32) {
        assert_eq!(UI_MANAGER_INITIALIZE_COUNT, 1);
        RECEIVED_STREAM_BUFFER = stream_buffer;
        RECEIVED_MODE = mode;
        DISPATCH_COUNT += 1;
    }

    unsafe fn reset_dispatch() {
        UI_MANAGER_INITIALIZE = record_ui_manager_initialize;
        UI_MANAGER_INITIALIZE_COUNT = 0;
        STREAM_BUFFER_MODE_DISPATCH = record_dispatch;
        RECEIVED_STREAM_BUFFER = core::ptr::null_mut();
        RECEIVED_MODE = u32::MAX;
        DISPATCH_COUNT = 0;
    }

    #[repr(align(4))]
    struct StreamBuffer([u8; 0x140]);

    #[test]
    fn dispatches_then_clears_every_page_context() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut stream_buffer = StreamBuffer([0xa5; 0x140]);
        unsafe {
            reset_dispatch();
            stream_buffer_dispatch_mode_zero(stream_buffer.0.as_mut_ptr());
            assert_eq!(UI_MANAGER_INITIALIZE_COUNT, 1);
            assert_eq!(DISPATCH_COUNT, 1);
            assert_eq!(RECEIVED_STREAM_BUFFER, stream_buffer.0.as_mut_ptr());
            assert_eq!(RECEIVED_MODE, 0);
        }
        for offset in (0x34..=0xb0).step_by(4).chain(core::iter::once(0x13c)) {
            assert_eq!(&stream_buffer.0[offset..offset + 4], &[0; 4]);
        }
    }
}
