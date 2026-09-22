//! Adding a rectangle to a render context's dirty region.
//!
//! `render_context_invalidate_rect` — original: `FUN_0828d9b4` @
//! **0x0828d9b4** (124 bytes: 116 code bytes and one literal-pool word).
//! Raw `osos.dec` establishes the next real function at 0x0828da34. The body
//! contains five plain `bl` instructions at four sites (two call
//! `ui_current_window`), zero predicated `bl` instructions, and one indirect
//! `blx` through `context+0x78`'s vtable slot +0x5c.
//!
//! # Algorithm
//!
//! Records `context` as the active render context. Unless the current window,
//! or the context's optional owner, has a nonempty title byte at +0x101, takes
//! the mutex at +0xd4 and unions `rect` into the dirty rectangle at +0xdc.
//! It always clears the active-context global before returning.
//!
//! # Deliberate deviations
//!
//! The firmware global at 0x089cc8a0+0x10 is represented by a crate static.
//! The target's four-byte pointer fields are read as `u32`; host fixtures use
//! native pointers at the same offsets. Rust returns normally after unlock
//! rather than reproducing the exact register-save sequence.

use core::ptr;

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};
use crate::ui::current_window::ui_current_window;
use crate::ui::rect::{rect_union, Rect};

const OWNER_OFFSET: usize = 0x78;
const OWNER_TITLE_OFFSET: usize = 0x101;
const OWNER_IS_HIDDEN_OFFSET: usize = 0x5c;
const DIRTY_MUTEX_OFFSET: usize = 0xd4;
const DIRTY_RECT_OFFSET: usize = 0xdc;

/// RetailOS global at 0x089cc8b0, set only while invalidating a context.
pub static mut ACTIVE_RENDER_CONTEXT: *mut u8 = ptr::null_mut();

#[cfg(target_os = "none")]
type MutexOperation = unsafe extern "C" fn(*mut Mutex);
#[cfg(target_os = "none")]
type RectUnion = unsafe extern "C" fn(*mut Rect, *const Rect);

/// Volatile call boundaries retain the stock lock/union/unlock sequence.
#[cfg(target_os = "none")]
static DIRTY_MUTEX_LOCK: MutexOperation = mutex_lock;
#[cfg(target_os = "none")]
static DIRTY_RECT_UNION: RectUnion = rect_union;
#[cfg(target_os = "none")]
static DIRTY_MUTEX_UNLOCK: MutexOperation = mutex_unlock;

#[inline(always)]
unsafe fn owner_is_hidden(owner: *mut u8) -> bool {
    #[cfg(target_os = "none")]
    let vtable = owner.cast::<u32>().read() as usize as *const u8;
    #[cfg(not(target_os = "none"))]
    let vtable = owner.cast::<*const u8>().read_unaligned();

    #[cfg(target_os = "none")]
    let is_hidden: unsafe extern "C" fn() -> *mut u8 = core::mem::transmute(
        vtable.add(OWNER_IS_HIDDEN_OFFSET).cast::<u32>().read() as usize,
    );
    #[cfg(not(target_os = "none"))]
    let is_hidden: unsafe extern "C" fn() -> *mut u8 = vtable
        .add(OWNER_IS_HIDDEN_OFFSET)
        .cast::<unsafe extern "C" fn() -> *mut u8>()
        .read_unaligned();

    is_hidden().add(OWNER_TITLE_OFFSET).read() != 0
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lock_dirty_mutex(context: *mut u8) {
    ptr::read_volatile(ptr::addr_of!(DIRTY_MUTEX_LOCK))(context.add(DIRTY_MUTEX_OFFSET).cast());
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lock_dirty_mutex(_context: *mut u8) {
    // The target mutex starts at a 4-byte offset; its host pointer-expanded
    // representation cannot coexist with the target Rect at +0xdc.
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlock_dirty_mutex(context: *mut u8) {
    ptr::read_volatile(ptr::addr_of!(DIRTY_MUTEX_UNLOCK))(context.add(DIRTY_MUTEX_OFFSET).cast());
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn unlock_dirty_mutex(_context: *mut u8) {}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn union_dirty_rect(context: *mut u8, rect: *const Rect) {
    ptr::read_volatile(ptr::addr_of!(DIRTY_RECT_UNION))(context.add(DIRTY_RECT_OFFSET).cast(), rect);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn union_dirty_rect(context: *mut u8, rect: *const Rect) {
    rect_union(context.add(DIRTY_RECT_OFFSET).cast(), rect);
}

/// render_context_invalidate_rect — original: `FUN_0828d9b4` @ 0x0828d9b4.
///
/// # Safety
///
/// `context` must contain its mutex at +0xd4 and dirty [`Rect`] at +0xdc;
/// `rect` must be readable. A non-NULL current window or owner must provide a
/// readable byte at +0x101; a non-NULL owner also supplies its vtable slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn render_context_invalidate_rect(context: *mut u8, rect: *const Rect) {
    ptr::write_volatile(ptr::addr_of_mut!(ACTIVE_RENDER_CONTEXT), context);

    let current_window = ui_current_window();
    let current_window_hidden = !current_window.is_null()
        && current_window.add(OWNER_TITLE_OFFSET).read() != 0;
    #[cfg(target_os = "none")]
    let owner = context.add(OWNER_OFFSET).cast::<u32>().read() as usize as *mut u8;
    #[cfg(not(target_os = "none"))]
    let owner = context.add(OWNER_OFFSET).cast::<*mut u8>().read_unaligned();

    if !current_window_hidden && (owner.is_null() || !owner_is_hidden(owner)) {
        lock_dirty_mutex(context);
        union_dirty_rect(context, rect);
        unlock_dirty_mutex(context);
    }

    ptr::write_volatile(ptr::addr_of_mut!(ACTIVE_RENDER_CONTEXT), ptr::null_mut());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(C, align(8))]
    struct Context([u8; 0x100]);

    unsafe fn context() -> Context {
        Context([0; 0x100])
    }

    unsafe fn dirty(context: *mut Context) -> *mut Rect {
        (*context).0.as_mut_ptr().add(DIRTY_RECT_OFFSET).cast()
    }

    #[test]
    fn unions_nonempty_rectangle_and_clears_active_context() {
        unsafe {
            let mut context = context();
            dirty(&mut context).write(Rect { top: 3, left: 4, bottom: 8, right: 9 });
            let source = Rect { top: 1, left: 6, bottom: 12, right: 7 };
            render_context_invalidate_rect(context.0.as_mut_ptr(), &source);
            assert_eq!(*dirty(&mut context), Rect { top: 1, left: 4, bottom: 12, right: 9 });
            assert!(ACTIVE_RENDER_CONTEXT.is_null());
        }
    }

    #[test]
    fn empty_rectangle_leaves_existing_dirty_region_unchanged() {
        unsafe {
            let mut context = context();
            let original = Rect { top: 3, left: 4, bottom: 8, right: 9 };
            dirty(&mut context).write(original);
            let empty = Rect { top: 0, left: 0, bottom: 0, right: 0 };
            render_context_invalidate_rect(context.0.as_mut_ptr(), &empty);
            assert_eq!(*dirty(&mut context), original);
            assert!(ACTIVE_RENDER_CONTEXT.is_null());
        }
    }
}
