//! `video_engine_dispatch_opaque_four_words` — retailOS `FUN_082d0d64` @
//! `0x082d0d64` (52 bytes: thirteen ARM words; `push {r4,lr}` at
//! `0x082d0d98` begins the next independently linked wrapper).
//!
//! **Verified call count:** one plain outbound `bl` (`0x082d0d78 ->
//! video_engine_get`) and one predicated outbound `blne` (`0x082d0d8c ->
//! 0x0824fb68`); two inbound plain `bl` calls and no predicated direct calls.
//!
//! Loads the video-engine singleton, silently returns when no session is
//! installed, and otherwise dispatches the instance followed by four
//! unmodified caller words to the resident target at `0x0824fb68`.
//!
//! # Deliberate deviations
//!
//! Ghidra's C omits three register arguments and the stack argument passed to
//! the predicated call. The target has no independently verified semantic
//! identity and is absent from `names.yaml`, so it remains an opaque typed
//! resident seam. Rust expresses the conditional `blne` as a normal call;
//! host tests record all four unmodified words.

use super::video_engine::video_engine_get;

/// Firmware entry of the unported opaque four-word dispatcher.
#[cfg(target_os = "none")]
const VIDEO_ENGINE_OPAQUE_FOUR_WORD_DISPATCH_ADDR: usize = 0x0824_fb68;

type VideoEngineOpaqueFourWordDispatch = unsafe extern "C" fn(*mut u8, u32, u32, u32, u32);

#[cfg(not(target_os = "none"))]
static mut MOCK_DISPATCH: Option<VideoEngineOpaqueFourWordDispatch> = None;

#[cfg(not(target_os = "none"))]
pub unsafe fn set_mock_dispatch(dispatch: Option<VideoEngineOpaqueFourWordDispatch>) {
    core::ptr::addr_of_mut!(MOCK_DISPATCH).write(dispatch);
}

unsafe fn dispatch(engine: *mut u8, first: u32, second: u32, third: u32, fourth: u32) {
    #[cfg(target_os = "none")]
    {
        let dispatch: VideoEngineOpaqueFourWordDispatch =
            core::mem::transmute(VIDEO_ENGINE_OPAQUE_FOUR_WORD_DISPATCH_ADDR);
        dispatch(engine, first, second, third, fourth);
    }
    #[cfg(not(target_os = "none"))]
    {
        match core::ptr::addr_of!(MOCK_DISPATCH).read() {
            Some(dispatch) => dispatch(engine, first, second, third, fourth),
            None => panic!("video_engine_dispatch_opaque_four_words requires dispatcher 0x0824fb68"),
        }
    }
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_dispatch_opaque_four_words(
    first: u32,
    second: u32,
    third: u32,
    fourth: u32,
) {
    let engine = video_engine_get();
    if !engine.is_null() {
        dispatch(engine, first, second, third, fourth);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{self, addr_of_mut};
    use super::super::video_engine::LOCK;

    static mut RECORDED: Option<(*mut u8, u32, u32, u32, u32)> = None;

    unsafe extern "C" fn record(engine: *mut u8, first: u32, second: u32, third: u32, fourth: u32) {
        *addr_of_mut!(RECORDED) = Some((engine, first, second, third, fourth));
    }

    #[test]
    fn null_instance_is_a_silent_no_op() {
        let _guard = LOCK.lock();
        unsafe {
            super::super::video_engine::set_mock_instance(ptr::null_mut());
            set_mock_dispatch(Some(record));
            RECORDED = None;
            video_engine_dispatch_opaque_four_words(0, u32::MAX, 1, 0x8000_0000);
            assert_eq!(RECORDED, None);
            set_mock_dispatch(None);
        }
    }

    #[test]
    fn dispatch_prepends_instance_and_preserves_raw_words() {
        let _guard = LOCK.lock();
        let mut engine = [0u8; 16];
        unsafe {
            super::super::video_engine::set_mock_instance(engine.as_mut_ptr());
            set_mock_dispatch(Some(record));
            for (first, second, third, fourth) in [
                (0, 0, 0, 0),
                (u32::MAX, 0x8000_0000, 1, u32::MAX),
            ] {
                RECORDED = None;
                video_engine_dispatch_opaque_four_words(first, second, third, fourth);
                assert_eq!(
                    RECORDED,
                    Some((engine.as_mut_ptr(), first, second, third, fourth))
                );
            }
            set_mock_dispatch(None);
            super::super::video_engine::set_mock_instance(ptr::null_mut());
        }
    }
}
