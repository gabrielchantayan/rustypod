//! `draw_surface_bounds_background` — original: `FUN_0810e93c` @
//! **0x0810e93c** (52 bytes, `0x0810e93c..0x0810e970`; the next real
//! function starts with `push {r4-r8,lr}` at 0x0810e970). Raw decoding finds
//! exactly 3 direct unconditional `bl` calls and no predicated `bl` calls.
//!
//! Constructs a 0x44-byte scoped draw-state record for `surface`, fills the
//! surface rectangle at `surface + 0x98` with that record's background colour,
//! then destroys the trivially destructible temporary. Deliberate deviation:
//! the three already-ported callees retain their documented dispatch seams;

//! the retail code makes direct calls.
use core::mem::MaybeUninit;

use crate::cxx::draw_state::{draw_state_construct_with_surface, DRAW_STATE_SIZE};
use crate::cxx::draw_state_fill::draw_state_fill_rect_background;
use crate::cxx::trivial_destructor::trivial_destructor;
use crate::ui::rect::Rect;

/// draw_surface_bounds_background — original: `FUN_0810e93c` @ 0x0810e93c
/// (52 bytes; 3 unconditional `bl` calls, no predicated forms).
///
/// Build a stack-local draw state with `surface`, fill `surface`'s four-word
/// rectangle at +0x98, and run the shared trivial destructor. There are no
/// NULL or bounds checks; all three calls and the rectangle address are
/// unconditional in the ARM body.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_surface_bounds_background(surface: *mut u8) {
    let mut state_words = MaybeUninit::<[u32; DRAW_STATE_SIZE / core::mem::size_of::<u32>()]>::uninit();
    let state = state_words.as_mut_ptr().cast::<u8>();
    unsafe {
        draw_state_construct_with_surface(state, surface as usize);
        draw_state_fill_rect_background(state, surface.add(0x98).cast::<Rect>());
        trivial_destructor(state.cast());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::DRAW_STATE_FILL_OPS_TEST_LOCK;
    use crate::cxx::draw_state_fill::{
        DrawStateFillEngine, DrawStateFillOps, DRAW_STATE_FILL_OPS,
    };
    use core::sync::atomic::{AtomicBool, Ordering};
    use parking_lot::Mutex;
    
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static SEEN: AtomicBool = AtomicBool::new(false);
    static mut SEEN_VALUE: Option<(usize, Rect, u32)> = None;
    
    unsafe extern "C" fn recorder(
        surface_body: usize,
        rect: *const Rect,
        _color: *const u8,
        style: u32,
        _clip_rect: *const u8,
    ) {
        unsafe { SEEN_VALUE = Some((surface_body, *rect, style)) };
        SEEN.store(true, Ordering::Release);
    }
    
    #[test]
    fn fills_the_surface_bounds_with_a_stack_draw_state() {
        let _local_lock = OPS_LOCK.lock();
        let _shared_lock = DRAW_STATE_FILL_OPS_TEST_LOCK.lock();
        let old = unsafe { DRAW_STATE_FILL_OPS };
        unsafe {
            SEEN.store(false, Ordering::Relaxed);
            SEEN_VALUE = None;
            DRAW_STATE_FILL_OPS = DrawStateFillOps { fill_engine: recorder as DrawStateFillEngine };
        }
    
        let mut surface = [0u8; 0xa8];
        let bounds = Rect { top: -3, left: 7, bottom: 11, right: 19 };
        unsafe { (surface.as_mut_ptr().add(0x98) as *mut Rect).write(bounds) };
        unsafe { draw_surface_bounds_background(surface.as_mut_ptr()) };
    
        let seen = if SEEN.load(Ordering::Acquire) { unsafe { SEEN_VALUE } } else { None };
        unsafe { DRAW_STATE_FILL_OPS = old };
        assert_eq!(seen, Some(((surface.as_ptr() as usize as u32 as usize) + 4, bounds, 0)));
    }

}
