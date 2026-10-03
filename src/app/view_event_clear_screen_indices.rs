//! Conditional screen-index cache clear before view-event completion.
//!
//! Original: `FUN_082398c8` @ `0x082398c8`, 48 bytes through
//! `0x082398f8` (the next entry is `add r0,r0,#0xd0; bx lr`). Raw
//! ARM-immediate decoding finds two inbound plain BLs (0x083b2f2c,
//! 0x083b34d4), zero predicated BLs. The body has two plain BLs and
//! a tail B to the ported completion veneer at 0x08260880.
//!
//! If view byte +0xe4 is nonzero, obtains the screen singleton and calls
//! 0x081778f0, which clears its four-byte-element vector at +0x840 and
//! marks the cache invalid at +0x84c. Then completes the view event,
//! stopping its optional timer and committing staged flags; returns handled.
//! Deliberate deviations: Rust calls the real completion body rather than
//! its branch veneer. The unused event word (preserved in r1 by retailOS)
//! remains in the public ABI but is not forwarded to the one-argument target.
//! The unported screen-clear helper uses the established firmware seam;
//! the singleton getter and event completion use existing Rust ports.

use core::ptr::addr_of;
use super::singletons::app_screen_get;
use super::view_event::view_event_complete;

pub struct ViewEventClearScreenIndicesOps {
    pub screen_get: unsafe extern "C" fn() -> *mut u8,
    pub clear_indices: unsafe extern "C" fn(*mut u8),
}

unsafe extern "C" fn screen_indices_clear(screen: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let clear: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x0817_78f0usize) };
        unsafe { clear(screen) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = screen;
        panic!("view_event_clear_screen_indices requires screen index clear 0x081778f0")
    }
}

pub static mut VIEW_EVENT_CLEAR_SCREEN_INDICES_OPS: ViewEventClearScreenIndicesOps = ViewEventClearScreenIndicesOps {
    screen_get: app_screen_get,
    clear_indices: screen_indices_clear,
};

/// Clears the screen index cache when requested by the view, then completes
/// the event. Any nonzero flag is true; the flag itself is not cleared.
///
/// # Safety
/// `view` must be valid through +0xe4 and for the completion helpers. The
/// active screen getter must return an object valid for its clear helper.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_event_clear_screen_indices(view: *mut u8, _event: u32) -> u32 {
    if unsafe { view.add(0xe4).read() } != 0 {
        let get = unsafe { addr_of!(VIEW_EVENT_CLEAR_SCREEN_INDICES_OPS.screen_get).read_volatile() };
        let screen = unsafe { get() };
        let clear = unsafe { addr_of!(VIEW_EVENT_CLEAR_SCREEN_INDICES_OPS.clear_indices).read_volatile() };
        unsafe { clear(screen) };
    }
    unsafe { view_event_complete(view) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::view_event::{ViewEventOps, VIEW_EVENT_OPS};
    use crate::testing::VIEW_EVENT_OPS_TEST_LOCK;
    use core::ptr::addr_of_mut;

    static mut SCREEN: [u32; 4] = [0; 4];
    static mut PHASE: u32 = 0;
    static mut EXPECT_CLEAR: bool = false;
    static mut EXPECT_TIMER: bool = false;

    unsafe extern "C" fn get_screen() -> *mut u8 {
        assert_eq!(PHASE, 0);
        PHASE = 1;
        addr_of_mut!(SCREEN).cast()
    }
    unsafe extern "C" fn clear(screen: *mut u8) {
        assert_eq!(PHASE, 1);
        assert_eq!(screen, addr_of_mut!(SCREEN).cast());
        // Model the observed cache invalidation, not an empty recording call.
        SCREEN[1] = SCREEN[0];
        SCREEN[3] = 0;
        PHASE = 2;
    }
    unsafe extern "C" fn stop(view: *mut u8) {
        assert_eq!(PHASE, if EXPECT_CLEAR { 2 } else { 0 });
        assert_ne!(view.add(0x50).cast::<u32>().read(), 0);
        view.add(0x50).cast::<u32>().write(0);
        PHASE = 3;
    }
    unsafe extern "C" fn commit(view: *mut u8) {
        assert_eq!(PHASE, if EXPECT_TIMER { 3 } else if EXPECT_CLEAR { 2 } else { 0 });
        assert_eq!(view.add(0x50).cast::<u32>().read(), 0);
        view.add(0x60).write(0xa5);
        PHASE = 4;
    }

    struct Restore(ViewEventClearScreenIndicesOps, ViewEventOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::swap(addr_of_mut!(VIEW_EVENT_CLEAR_SCREEN_INDICES_OPS), &mut self.0);
                core::ptr::swap(addr_of_mut!(VIEW_EVENT_OPS), &mut self.1);
            }
        }
    }

    #[test]
    fn conditional_cache_invalidation_precedes_timer_stop_and_commit() {
        let _lock = VIEW_EVENT_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = Restore(addr_of!(VIEW_EVENT_CLEAR_SCREEN_INDICES_OPS).read(), addr_of!(VIEW_EVENT_OPS).read());
            VIEW_EVENT_CLEAR_SCREEN_INDICES_OPS = ViewEventClearScreenIndicesOps { screen_get: get_screen, clear_indices: clear };
            VIEW_EVENT_OPS.stop_view_timer = stop;
            VIEW_EVENT_OPS.commit_staged_flags = commit;
            for flag in [0u8, 1, 0x80, 0xff] {
                for timer in [0u32, 0x12345678] {
                    let mut view = [0u32; 58];
                    let bytes = view.as_mut_ptr().cast::<u8>();
                    bytes.add(0xe4).write(flag);
                    view[0x50 / 4] = timer;
                    SCREEN = [0x1000, 0x1010, 0x1020, 1];
                    PHASE = 0;
                    EXPECT_CLEAR = flag != 0;
                    EXPECT_TIMER = timer != 0;
                    assert_eq!(view_event_clear_screen_indices(bytes, u32::MAX), 1);
                    assert_eq!(PHASE, 4);
                    assert_eq!(bytes.add(0x60).read(), 0xa5);
                    assert_eq!(bytes.add(0xe4).read(), flag);
                    assert_eq!(SCREEN, if flag == 0 { [0x1000, 0x1010, 0x1020, 1] } else { [0x1000, 0x1000, 0x1020, 0] });
                }
            }
        }
    }
}
