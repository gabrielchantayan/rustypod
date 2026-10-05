//! `video_session_clear` — `FUN_081bbc84` @ 0x081bbc84.
//! True extent: 136 bytes, [0x081bbc84,0x081bbd0c), including the literal
//! at 0x081bbd08; the next entry sets byte +0x10 and returns. Raw A32
//! decoding verifies two inbound plain BLs (0x081bb948,0x081bbb64), no
//! predicated inbound BLs, five outbound plain BLs, no predicated outbound
//! BLs, and one virtual BLX through slot +0x14.
//!
//! Only active == 1 closes the interface, destroys and deletes the frame
//! manager, releases the shared buffer, then destroys and deletes its pool.
//! Both flags are always cleared. Resources are reloaded after callbacks,
//! and destructor return values, not the original pointers, feed delete.
//!
//! Deliberate deviations: native repr(C) pointers widen on hosts; the known
//! argument-swapping pool-free wrapper at 0x082aad34 is replaced by the
//! existing pool_free port (its buffer is already known non-NULL). The
//! unported frame-manager destructor at 0x081d5dbc remains a literal target
//! veneer, not a guessed implementation. An ops table permits host fixtures;
//! default pool destruction and deletion call existing ports directly.

use crate::heap::pool::{PoolControl, pool_destroy, pool_free};
use crate::heap::veneers::operator_delete;
use core::ptr::{addr_of, read_volatile};

#[repr(C)]
pub struct VideoSessionVtable {
    pub unresolved: [usize; 5],
    pub close: unsafe extern "C" fn(*mut VideoSessionInterface),
}

#[repr(C)]
pub struct VideoSessionInterface {
    pub vtable: *const VideoSessionVtable,
}

/// Accessed prefix only; retail stores further session data after +0x10.
#[repr(C)]
pub struct VideoSession {
    pub interface: *mut VideoSessionInterface,
    pub frames: *mut u8,
    pub untouched: u32,
    pub active: u8,
    pub padding: [u8; 3],
    pub pending: u8,
}

/// Firmware global at 0x08a09d90, whose +8/+12 words own video storage.
#[repr(C)]
pub struct VideoSessionShared {
    pub untouched: [u32; 2],
    pub buffer: *mut u8,
    pub pool: *mut PoolControl,
}

#[derive(Clone, Copy)]
pub struct VideoSessionClearOps {
    pub shared: unsafe extern "C" fn() -> *mut VideoSessionShared,
    pub destroy_frames: unsafe extern "C" fn(*mut u8) -> *mut u8,
    pub release_buffer: unsafe extern "C" fn(*mut PoolControl, *mut u8),
    pub destroy_pool: unsafe extern "C" fn(*mut PoolControl) -> *mut PoolControl,
    pub delete: unsafe extern "C" fn(*mut u8),
}

#[cfg(target_os = "none")]
extern "C" {
    fn video_frame_manager_destroy_retail(frames: *mut u8) -> *mut u8;
}

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".syntax unified",
    ".text",
    ".p2align 2",
    ".type video_frame_manager_destroy_retail, %function",
    "video_frame_manager_destroy_retail:",
    "ldr pc, [pc, #-4]",
    ".word 0x081d5dbc",
    ".size video_frame_manager_destroy_retail, . - video_frame_manager_destroy_retail",
);

unsafe extern "C" fn shared_state() -> *mut VideoSessionShared {
    #[cfg(target_os = "none")]
    { 0x08a09d90 as *mut VideoSessionShared }
    #[cfg(not(target_os = "none"))]
    { panic!("video_session_clear requires a shared-state fixture") }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn video_frame_manager_destroy_retail(_: *mut u8) -> *mut u8 {
    panic!("video_session_clear requires a frame-manager destructor fixture")
}

pub const DEFAULT_VIDEO_SESSION_CLEAR_OPS: VideoSessionClearOps = VideoSessionClearOps {
    shared: shared_state,
    destroy_frames: video_frame_manager_destroy_retail,
    release_buffer: pool_free,
    destroy_pool: pool_destroy,
    delete: operator_delete,
};

pub static mut VIDEO_SESSION_CLEAR_OPS: VideoSessionClearOps = DEFAULT_VIDEO_SESSION_CLEAR_OPS;

/// Closes and releases an active video session; always clears its flags.
///
/// # Safety
/// The session prefix must be writable. For active == 1 its interface and
/// close slot must be valid; non-NULL resources and configured callbacks must
/// obey their lifecycle contracts. No concurrent ops-table mutation is allowed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_session_clear(session: *mut VideoSession) {
    clear_with_ops(session, read_volatile(addr_of!(VIDEO_SESSION_CLEAR_OPS)));
}

unsafe fn clear_with_ops(session: *mut VideoSession, ops: VideoSessionClearOps) {
    if (*session).active == 1 {
        let interface = (*session).interface;
        ((*(*interface).vtable).close)(interface);
        (*session).interface = core::ptr::null_mut();
        let frames = (*session).frames;
        if !frames.is_null() {
            (ops.delete)((ops.destroy_frames)(frames));
            (*session).frames = core::ptr::null_mut();
        }
        let shared = (ops.shared)();
        let buffer = (*shared).buffer;
        if !buffer.is_null() {
            (ops.release_buffer)((*shared).pool, buffer);
            (*shared).buffer = core::ptr::null_mut();
        }
        let pool = (*shared).pool;
        if !pool.is_null() {
            (ops.delete)((ops.destroy_pool)(pool).cast());
            (*shared).pool = core::ptr::null_mut();
        }
    }
    (*session).active = 0;
    (*session).pending = 0;
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;
    use std::vec::Vec;

    std::thread_local! {
        static EVENTS: RefCell<Vec<usize>> = RefCell::new(Vec::new());
        static SHARED: RefCell<VideoSessionShared> = RefCell::new(VideoSessionShared {
            untouched: [17, 29], buffer: core::ptr::null_mut(), pool: core::ptr::null_mut(),
        });
    }
    fn event(value: usize) { EVENTS.with(|e| e.borrow_mut().push(value)); }
    unsafe extern "C" fn close(_: *mut VideoSessionInterface) { event(1); }
    unsafe extern "C" fn shared() -> *mut VideoSessionShared {
        SHARED.with(|s| s.as_ptr())
    }
    unsafe extern "C" fn frames(p: *mut u8) -> *mut u8 { event(2); p.add(1) }
    unsafe extern "C" fn release(_: *mut PoolControl, _: *mut u8) {
        event(3);
        // A callback may replace the pool; the subsequent destructor must reload it.
        SHARED.with(|s| s.borrow_mut().pool = 0x4000 as *mut PoolControl);
    }
    unsafe extern "C" fn pool(p: *mut PoolControl) -> *mut PoolControl {
        event(p as usize); (p as *mut u8).wrapping_add(4).cast()
    }
    unsafe extern "C" fn delete(p: *mut u8) { event(p as usize); }
    const OPS: VideoSessionClearOps = VideoSessionClearOps {
        shared, destroy_frames: frames, release_buffer: release, destroy_pool: pool, delete,
    };
    static VTABLE: VideoSessionVtable = VideoSessionVtable { unresolved: [0; 5], close };

    #[test]
    fn only_exactly_one_is_active_and_flags_always_clear() {
        for active in [0, 2, 255] {
            let mut session = VideoSession {
                interface: 0x1000 as *mut VideoSessionInterface,
                frames: 0x2000 as *mut u8, untouched: 0x12345678,
                active, padding: [11, 22, 33], pending: 255,
            };
            unsafe { video_session_clear(&mut session) };
            assert_eq!(session.interface as usize, 0x1000);
            assert_eq!(session.frames as usize, 0x2000);
            assert_eq!((session.active, session.pending), (0, 0));
            assert_eq!(session.untouched, 0x12345678);
            assert_eq!(session.padding, [11, 22, 33]);
        }
    }

    #[test]
    fn cleanup_order_null_resources_return_adjustments_and_idempotence() {
        for has_frames in [false, true] {
            for has_buffer in [false, true] {
                for has_pool in [false, true] {
                    EVENTS.with(|e| e.borrow_mut().clear());
                    SHARED.with(|s| {
                        let mut s = s.borrow_mut();
                        s.buffer = if has_buffer { 0x3000 as *mut u8 } else { core::ptr::null_mut() };
                        s.pool = if has_pool { 0x5000 as *mut PoolControl } else { core::ptr::null_mut() };
                    });
                    let mut frame_storage = [0u8; 84];
                    let mut interface = VideoSessionInterface { vtable: &VTABLE };
                    let mut session = VideoSession {
                        interface: &mut interface,
                        frames: if has_frames { frame_storage.as_mut_ptr() } else { core::ptr::null_mut() },
                        untouched: 37, active: 1, padding: [8, 9, 10], pending: 7,
                    };
                    let mut expected = std::vec![1];
                    if has_frames { expected.extend([2, unsafe { frame_storage.as_mut_ptr().add(1) } as usize]); }
                    if has_buffer { expected.push(3); }
                    if has_pool || has_buffer {
                        let final_pool = if has_buffer { 0x4000 } else { 0x5000 };
                        expected.extend([final_pool, final_pool + 4]);
                    }
                    unsafe { clear_with_ops(&mut session, OPS) };
                    assert!(session.interface.is_null());
                    assert!(session.frames.is_null());
                    assert_eq!((session.active, session.pending), (0, 0));
                    assert_eq!((session.untouched, session.padding), (37, [8, 9, 10]));
                    SHARED.with(|s| {
                        let s = s.borrow();
                        assert!(s.buffer.is_null() && s.pool.is_null());
                        assert_eq!(s.untouched, [17, 29]);
                    });
                    unsafe { clear_with_ops(&mut session, OPS) };
                    EVENTS.with(|e| assert_eq!(*e.borrow(), expected));
                }
            }
        }
    }
}
