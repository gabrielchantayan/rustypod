//! Suspending and resuming a render context.
//!
//! `render_context_set_suspended` is retailOS `FUN_0828dda0` at
//! **0x0828dda0**. Raw `osos.dec` decoding fixes its extent at 148 bytes:
//! the next distinct function begins at 0x0828de34. Decoding every ARM
//! `B`/`BL` word finds nine direct call sites (eight `bl`, one `blne` at
//! 0x0816e0b8); the predicated caller checks its nullable context before this
//! body immediately dereferences it. No image word contains this address.
//!
//! # Algorithm
//!
//! The function stores the low byte of `suspended` at context +0x3d and acts
//! only on a changed value while rendering is enabled (+0x60). Suspending
//! returns early for an absent presentation (+0x54) or an in-use presentation
//! (+0x58); otherwise it releases the optional resource at +0x48 then releases
//! the presentation. Resuming creates a presentation only when one is absent
//! and the local bounds (+0x20) are non-empty, then tail-calls
//! `ui_element_invalidate` for the owner at +0x78 when present.
//!
//! # Deliberate deviations
//!
//! The three unported presentation operations retain their verified retail
//! addresses on device and use recording seams in host tests. Their concrete
//! object types are not inferred here. The raw ARM comparison uses all of r1,
//! while the store truncates it to a byte; the public argument therefore stays
//! `u32`, rather than being narrowed to `bool` or `u8`.

use core::mem::size_of;
use core::ptr;

use crate::ui::invalidate::ui_element_invalidate;
use crate::ui::rect::{rect_is_empty, Rect};

/// ABI of the setup operation at retailOS address 0x0828c700.
type RenderContextEnsurePresentation = unsafe extern "C" fn(*mut u8);
/// ABI of the resource release operation at retailOS address 0x0828d4e0.
type RenderContextReleaseSlot = unsafe extern "C" fn(*mut u8, *mut u32);

/// Unported calls preserved by [`render_context_set_suspended`].
#[derive(Clone, Copy)]
struct RenderContextSuspendOps {
    ensure_presentation: RenderContextEnsurePresentation,
    release_resource: RenderContextReleaseSlot,
    release_presentation: RenderContextReleaseSlot,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_ensure_presentation(context: *mut u8) {
    let ensure: RenderContextEnsurePresentation = core::mem::transmute(0x0828_c700usize);
    ensure(context);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_release_resource(context: *mut u8, slot: *mut u32) {
    let release: RenderContextReleaseSlot = core::mem::transmute(0x0828_d4e0usize);
    release(context, slot);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_release_presentation(context: *mut u8, slot: *mut u32) {
    let release: RenderContextReleaseSlot = core::mem::transmute(0x0828_cd54usize);
    release(context, slot);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ensure_presentation(_context: *mut u8) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_slot(_context: *mut u8, _slot: *mut u32) {}

#[cfg(target_os = "none")]
const DEFAULT_RENDER_CONTEXT_SUSPEND_OPS: RenderContextSuspendOps = RenderContextSuspendOps {
    ensure_presentation: firmware_ensure_presentation,
    release_resource: firmware_release_resource,
    release_presentation: firmware_release_presentation,
};

#[cfg(not(target_os = "none"))]
const DEFAULT_RENDER_CONTEXT_SUSPEND_OPS: RenderContextSuspendOps = RenderContextSuspendOps {
    ensure_presentation: missing_ensure_presentation,
    release_resource: missing_release_slot,
    release_presentation: missing_release_slot,
};

/// Active presentation operations. Volatile loading retains all three target
/// call boundaries instead of allowing LLVM to fold an unwired host default.
static mut RENDER_CONTEXT_SUSPEND_OPS: RenderContextSuspendOps = DEFAULT_RENDER_CONTEXT_SUSPEND_OPS;

#[inline(always)]
unsafe fn render_context_suspend_ops() -> RenderContextSuspendOps {
    ptr::read_volatile(ptr::addr_of!(RENDER_CONTEXT_SUSPEND_OPS))
}

/// The retailOS 32-bit object layout observed by this function.
#[repr(C)]
struct RenderContext {
    _before_bounds: [u8; 0x20],
    bounds: Rect,
    _before_suspend_state: [u8; 0x3d - 0x30],
    suspend_state: u8,
    _before_presentation_resource: [u8; 0x48 - 0x3e],
    presentation_resource: u32,
    _before_presentation: [u8; 0x54 - 0x4c],
    presentation: u32,
    presentation_in_use: u32,
    _before_rendering_enabled: [u8; 0x60 - 0x5c],
    rendering_enabled: u8,
    _before_owner: [u8; 0x78 - 0x61],
    owner: u32,
}

const _: () = assert!(size_of::<RenderContext>() == 0x7c);

/// render_context_set_suspended — original: `FUN_0828dda0` @ **0x0828dda0**
/// (148 bytes; next function begins at 0x0828de34).
///
/// Stores `suspended`'s low byte and releases or restores the context's
/// presentation resources on an enabled state transition. Returns the raw r0
/// value selected by the ARM exits: the prior state for a no-op, zero for a
/// disabled renderer or completed release, the in-use presentation word when
/// suspension is deferred, and the invalidated owner pointer on resume.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn render_context_set_suspended(context: *mut u8, suspended: u32) -> u32 {
    let context_fields = context.cast::<RenderContext>();
    let previous_state = ptr::addr_of!((*context_fields).suspend_state).read() as u32;
    if previous_state == suspended {
        return previous_state;
    }

    ptr::addr_of_mut!((*context_fields).suspend_state).write(suspended as u8);
    if ptr::addr_of!((*context_fields).rendering_enabled).read() == 0 {
        return 0;
    }

    let presentation = ptr::addr_of!((*context_fields).presentation).read();
    if suspended != 0 {
        if presentation == 0 {
            return 0;
        }
        let presentation_in_use = ptr::addr_of!((*context_fields).presentation_in_use).read();
        if presentation_in_use != 0 {
            return presentation_in_use;
        }

        let ops = render_context_suspend_ops();
        if ptr::addr_of!((*context_fields).presentation_resource).read() != 0 {
            (ops.release_resource)(context, ptr::addr_of_mut!((*context_fields).presentation_resource));
        }
        (ops.release_presentation)(context, ptr::addr_of_mut!((*context_fields).presentation));
        return 0;
    }

    if presentation == 0 && rect_is_empty(ptr::addr_of!((*context_fields).bounds)) == 0 {
        (render_context_suspend_ops().ensure_presentation)(context);
    }

    let owner = ptr::addr_of!((*context_fields).owner).read();
    if owner == 0 {
        0
    } else {
        ui_element_invalidate(owner as usize as *mut u8) as usize as u32
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static OPS_TEST_LOCK: Mutex<()> = Mutex::new(());
    static ENSURE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_LOG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_ensure(_context: *mut u8) {
        ENSURE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_resource_release(_context: *mut u8, slot: *mut u32) {
        RELEASE_LOG.fetch_add(1, Ordering::SeqCst);
        slot.write(0);
    }

    unsafe extern "C" fn record_presentation_release(_context: *mut u8, slot: *mut u32) {
        RELEASE_LOG.fetch_add(10, Ordering::SeqCst);
        slot.write(0);
    }

    const TEST_OPS: RenderContextSuspendOps = RenderContextSuspendOps {
        ensure_presentation: record_ensure,
        release_resource: record_resource_release,
        release_presentation: record_presentation_release,
    };

    unsafe fn reset_context(context: *mut RenderContext) {
        ptr::write_bytes(context.cast::<u8>(), 0, size_of::<RenderContext>());
        ptr::addr_of_mut!((*context).rendering_enabled).write(1);
    }

    #[test]
    fn suspend_resume_transitions_match_arm_exit_paths() {
        let _guard = OPS_TEST_LOCK.lock();
        let Some(storage) = try_map_u32_slab(hints::RENDER_CONTEXT_SUSPEND, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let context = storage.cast::<RenderContext>();

        unsafe {
            let old_ops = RENDER_CONTEXT_SUSPEND_OPS;
            RENDER_CONTEXT_SUSPEND_OPS = TEST_OPS;

            reset_context(context);
            ptr::addr_of_mut!((*context).suspend_state).write(1);
            assert_eq!(render_context_set_suspended(storage, 1), 1);
            assert_eq!(ptr::addr_of!((*context).suspend_state).read(), 1);

            reset_context(context);
            ptr::addr_of_mut!((*context).rendering_enabled).write(0);
            assert_eq!(render_context_set_suspended(storage, 1), 0);
            assert_eq!(ptr::addr_of!((*context).suspend_state).read(), 1);

            reset_context(context);
            assert_eq!(render_context_set_suspended(storage, 1), 0);
            assert_eq!(RELEASE_LOG.load(Ordering::SeqCst), 0);

            reset_context(context);
            ptr::addr_of_mut!((*context).presentation).write(0x44);
            ptr::addr_of_mut!((*context).presentation_in_use).write(0x55);
            assert_eq!(render_context_set_suspended(storage, 1), 0x55);
            assert_eq!(ptr::addr_of!((*context).presentation).read(), 0x44);

            reset_context(context);
            ptr::addr_of_mut!((*context).presentation).write(0x44);
            ptr::addr_of_mut!((*context).presentation_resource).write(0x33);
            RELEASE_LOG.store(0, Ordering::SeqCst);
            assert_eq!(render_context_set_suspended(storage, 1), 0);
            assert_eq!(RELEASE_LOG.load(Ordering::SeqCst), 11);
            assert_eq!(ptr::addr_of!((*context).presentation_resource).read(), 0);
            assert_eq!(ptr::addr_of!((*context).presentation).read(), 0);

            reset_context(context);
            ptr::addr_of_mut!((*context).suspend_state).write(1);
            ptr::addr_of_mut!((*context).bounds).write(Rect { top: 0, left: 0, bottom: 0, right: 1 });
            ENSURE_CALLS.store(0, Ordering::SeqCst);
            assert_eq!(render_context_set_suspended(storage, 0), 0);
            assert_eq!(ENSURE_CALLS.load(Ordering::SeqCst), 0);

            ptr::addr_of_mut!((*context).suspend_state).write(1);
            ptr::addr_of_mut!((*context).bounds).write(Rect { top: 0, left: 0, bottom: 1, right: 1 });
            assert_eq!(render_context_set_suspended(storage, 0), 0);
            assert_eq!(ENSURE_CALLS.load(Ordering::SeqCst), 1);

            reset_context(context);
            ptr::addr_of_mut!((*context).presentation).write(1);
            assert_eq!(render_context_set_suspended(storage, 0x100), 0);
            assert_eq!(ptr::addr_of!((*context).suspend_state).read(), 0);
            assert_eq!(RELEASE_LOG.load(Ordering::SeqCst), 21);

            RENDER_CONTEXT_SUSPEND_OPS = old_ops;
        }
    }
}
