//! Release VDBE frames queued for destruction.
//!
//! `vdbe_frame_list_clear` is retailOS `FUN_0838af4c` at load address
//! `0x0838af4c`. Raw `osos.dec` establishes the 56-byte extent
//! `0x0838af4c..0x0838af83`: the closing `ldmia sp!,{r4,r5,r6,pc}` is followed
//! by the separately linked `vdbe_free_cursor` at `0x0838af84`. It has three
//! inbound plain `bl` call sites (`0x08044cd4`, `0x08044cfc`, `0x0838a554`) and
//! no predicated `bl` call sites. Its sole outbound call is a plain `bl` to
//! `tracked_free` @ `0x083906f4`.
//!
//! The descriptor's second target word heads a singly linked pending-frame
//! chain. Each frame's successor is its target word at +0x0c. The list is
//! released head-first, saving the successor before freeing the current frame;
//! then all three descriptor words are cleared. Deliberate deviation: host
//! builds use a recording seam for `tracked_free`, because target pointer words
//! are 32 bits while host pointers may be 64 bits. Target builds call the
//! verified port directly.

use crate::heap::tracked::tracked_free;

const PENDING_FRAME_HEAD: usize = 4;
const FRAME_NEXT: usize = 12;

#[cfg(not(target_os = "none"))]
type FrameFree = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_tracked_free(frame: *mut u8) {
    tracked_free(frame);
}

#[cfg(not(target_os = "none"))]
pub static mut VDBE_FRAME_LIST_CLEAR_FREE: FrameFree = host_tracked_free;

#[inline(always)]
unsafe fn target_word(base: *mut u8, offset: usize) -> *mut u8 {
    unsafe { base.add(offset).cast::<u32>().read() as usize as *mut u8 }
}

#[inline(always)]
unsafe fn free_frame(frame: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { tracked_free(frame) };
    #[cfg(not(target_os = "none"))]
    unsafe { VDBE_FRAME_LIST_CLEAR_FREE(frame) };
}

/// `sqlite3VdbeFrameDelete` — retailOS `FUN_0838af4c` @ `0x0838af4c` (56 bytes).
///
/// Releases every frame chained from descriptor word +4 through each frame's
/// +0x0c successor, then zeroes descriptor words +0, +4, and +8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_frame_list_clear(descriptor: *mut u8) {
    let mut frame = unsafe { target_word(descriptor, PENDING_FRAME_HEAD) };
    while !frame.is_null() {
        let next = unsafe { target_word(frame, FRAME_NEXT) };
        unsafe { free_frame(frame) };
        frame = next;
    }
    unsafe {
        descriptor.cast::<u32>().write(0);
        descriptor.add(4).cast::<u32>().write(0);
        descriptor.add(8).cast::<u32>().write(0);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec::Vec;
    use std::vec;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::VDBE_FRAME_LIST_CLEAR, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static FREED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn record_free(frame: *mut u8) {
        FREED.lock().push(frame as usize);
    }

    unsafe fn fixture() -> Option<*mut u8> {
        (*SLAB).map(|pointer| pointer as *mut u8)
    }

    unsafe fn set_word(base: *mut u8, offset: usize, value: *mut u8) {
        base.add(offset).cast::<u32>().write(value as usize as u32);
    }

    #[test]
    fn frees_pending_frames_head_first_and_clears_the_descriptor() {
        let _lock = LOCK.lock();
        let Some(slab) = (unsafe { fixture() }) else { return };
        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            let first = slab.add(0x100);
            let second = slab.add(0x200);
            set_word(slab, PENDING_FRAME_HEAD, first);
            set_word(first, FRAME_NEXT, second);
            VDBE_FRAME_LIST_CLEAR_FREE = record_free;
            FREED.lock().clear();
            vdbe_frame_list_clear(slab);
            assert_eq!(*FREED.lock(), vec![first as usize, second as usize]);
            assert_eq!(slab.cast::<u32>().read(), 0);
            assert_eq!(slab.add(4).cast::<u32>().read(), 0);
            assert_eq!(slab.add(8).cast::<u32>().read(), 0);
            VDBE_FRAME_LIST_CLEAR_FREE = host_tracked_free;
        }
    }

    #[test]
    fn empty_pending_list_still_clears_all_descriptor_words() {
        let _lock = LOCK.lock();
        let Some(slab) = (unsafe { fixture() }) else { return };
        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            set_word(slab, 0, slab.add(0x300));
            set_word(slab, 8, slab.add(0x400));
            VDBE_FRAME_LIST_CLEAR_FREE = record_free;
            FREED.lock().clear();
            vdbe_frame_list_clear(slab);
            assert!(FREED.lock().is_empty());
            assert_eq!(slab.cast::<u32>().read(), 0);
            assert_eq!(slab.add(4).cast::<u32>().read(), 0);
            assert_eq!(slab.add(8).cast::<u32>().read(), 0);
            VDBE_FRAME_LIST_CLEAR_FREE = host_tracked_free;
        }
    }
}
