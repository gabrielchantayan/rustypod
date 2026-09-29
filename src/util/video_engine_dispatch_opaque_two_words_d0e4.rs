//! `video_engine_dispatch_opaque_two_words_d0e4` — retailOS `FUN_082d1438` @
//! `0x082d1438` (40 bytes: ten ARM words; `push {r4,r5,r6,lr}` at
//! `0x082d1460` begins the next independently linked wrapper).
//!
//! **Verified call count:** one plain outbound `bl` (`0x082d1444 ->
//! video_engine_get`) and no predicated `bl`; two inbound plain `bl` calls
//! (`0x081bb718` and `0x083d39c8`) and no predicated direct calls.
//!
//! Loads the video-engine singleton, silently returns when no session is
//! installed, and otherwise tail-dispatches the instance followed by two
//! unmodified caller words to the resident target at `0x0824d0e4`.
//!
//! # Deliberate deviations
//!
//! Ghidra's 188-byte extent and free-index-table C are false: the conditional
//! `popne {r4,r5,r6,lr}; bne` ends this wrapper. The tail target has no
//! independently verified semantic identity and is absent from `names.yaml`,
//! so it remains an opaque typed resident seam. Rust expresses the tail branch
//! as a normal call; host tests record the unmodified words.

use super::video_engine::video_engine_get;

/// Firmware entry of the unported opaque two-word dispatcher.
#[cfg(target_os = "none")]
const VIDEO_ENGINE_OPAQUE_TWO_WORD_DISPATCH_D0E4_ADDR: usize = 0x0824_d0e4;

type VideoEngineOpaqueTwoWordDispatch = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_os = "none"))]
static mut MOCK_DISPATCH: Option<VideoEngineOpaqueTwoWordDispatch> = None;

#[cfg(not(target_os = "none"))]
pub unsafe fn set_mock_dispatch(dispatch: Option<VideoEngineOpaqueTwoWordDispatch>) {
    core::ptr::addr_of_mut!(MOCK_DISPATCH).write(dispatch);
}

unsafe fn dispatch(engine: *mut u8, first: u32, second: u32) {
    #[cfg(target_os = "none")]
    {
        let dispatch: VideoEngineOpaqueTwoWordDispatch =
            core::mem::transmute(VIDEO_ENGINE_OPAQUE_TWO_WORD_DISPATCH_D0E4_ADDR);
        dispatch(engine, first, second);
    }
    #[cfg(not(target_os = "none"))]
    {
        match core::ptr::addr_of!(MOCK_DISPATCH).read() {
            Some(dispatch) => dispatch(engine, first, second),
            None => panic!("video_engine_dispatch_opaque_two_words_d0e4 requires dispatcher 0x0824d0e4"),
        }
    }
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_dispatch_opaque_two_words_d0e4(first: u32, second: u32) {
    let engine = video_engine_get();
    if !engine.is_null() {
        dispatch(engine, first, second);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{self, addr_of_mut};
    use super::super::video_engine::LOCK;
    static mut RECORDED: Option<(*mut u8, u32, u32)> = None;

    unsafe extern "C" fn record(engine: *mut u8, first: u32, second: u32) {
        *addr_of_mut!(RECORDED) = Some((engine, first, second));
    }

    #[test]
    fn null_instance_is_a_silent_no_op() {
        let _guard = LOCK.lock();
        unsafe {
            super::super::video_engine::set_mock_instance(ptr::null_mut());
            set_mock_dispatch(Some(record));
            RECORDED = None;
            video_engine_dispatch_opaque_two_words_d0e4(0, u32::MAX);
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
            for (first, second) in [(1, 0), (0, u32::MAX), (u32::MAX, 0x8000_0000)] {
                RECORDED = None;
                video_engine_dispatch_opaque_two_words_d0e4(first, second);
                assert_eq!(RECORDED, Some((engine.as_mut_ptr(), first, second)));
            }
            set_mock_dispatch(None);
            super::super::video_engine::set_mock_instance(ptr::null_mut());
        }
    }
}
