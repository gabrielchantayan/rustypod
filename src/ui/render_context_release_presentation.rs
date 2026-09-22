//! Releases a render context's presentation slot.
//!
//! `render_context_release_presentation` is retailOS `FUN_0828cd54` at
//! **0x0828cd54**. Raw `osos.dec` words establish the exact 60-byte extent:
//! 15 ARM instructions from `push {r4,lr}` through `pop {r4,pc}`, followed by
//! the next distinct function at 0x0828cd90. Decoding inbound ARM branch words
//! finds three direct, unconditional `bl` callers and zero predicated callers.
//! The body contains one plain `bl` to the unresolved zero-argument routine at
//! 0x082929fc and one predicated indirect `blxne` through vtable slot +0x04.
//!
//! # Algorithm
//!
//! If context byte +0xf8 is zero, call 0x082929fc. Otherwise, release the
//! non-null presentation through its vtable's +0x04 slot with `context` in r0.
//! Clear the presentation slot in either case.
//!
//! # Deliberate deviations
//!
//! The direct callee has no established semantic identity, so host builds use
//! an installable recording seam. ARM builds preserve the recovered instruction
//! sequence, including the fixed-address `bl` and predicated virtual call.

#[cfg(not(target_arch = "arm"))]
use core::ptr;

#[cfg(not(target_arch = "arm"))]
use crate::ui::render_context_release_resource::render_context_release_resource;

type PresentationCleanup = unsafe extern "C" fn();

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_presentation_cleanup() {
    let cleanup: PresentationCleanup = core::mem::transmute(0x0829_29fcusize);
    cleanup();
}

#[cfg(target_os = "none")]
const PRESENTATION_CLEANUP: PresentationCleanup = retail_presentation_cleanup;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_presentation_cleanup() {
    panic!("install presentation cleanup host operation before calling")
}

#[cfg(not(target_os = "none"))]
pub static mut PRESENTATION_CLEANUP: PresentationCleanup = missing_presentation_cleanup;

#[cfg(not(target_arch = "arm"))]
/// Releases the presentation selected by `slot`, then clears `slot`.
///
/// # Safety
///
/// `context` must have a readable byte at +0xf8 and `slot` must be writable.
/// A nonzero slot with a nonzero context byte must identify a valid presentation
/// object accepted by [`render_context_release_resource`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn render_context_release_presentation(context: *mut u8, slot: *mut u32) {
    let presentation = ptr::read(slot);
    if ptr::read(context.add(0xf8)) == 0 {
        PRESENTATION_CLEANUP();
    } else if presentation != 0 {
        render_context_release_resource(context, slot);
        return;
    }
    ptr::write(slot, 0);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl render_context_release_presentation
    .type render_context_release_presentation, %function
render_context_release_presentation:
    push    {{r4, lr}}
    mov     r4, r1
    ldrb    r1, [r0, #0xf8]
    ldr     r0, [r4]
    cmp     r1, #0
    bne     1f
    bl      0x082929fc
    b       2f
1:
    cmp     r0, #0
    ldrne   r1, [r0]
    ldrne   r1, [r1, #4]
    blxne   r1
2:
    mov     r0, #0
    str     r0, [r4]
    pop     {{r4, pc}}
"#
);

#[cfg(target_arch = "arm")]
extern "C" {
    pub fn render_context_release_presentation(context: *mut u8, slot: *mut u32);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::ui::render_context_release_resource::{RenderContextResource, RenderContextResourceVtable};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CLEANUP_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_CONTEXT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_cleanup() {
        CLEANUP_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_release(context: *mut u8) {
        RELEASE_CONTEXT.store(context as usize, Ordering::SeqCst);
    }

    static VTABLE: RenderContextResourceVtable = RenderContextResourceVtable {
        unresolved_00: 0,
        release: record_release,
    };

    #[test]
    fn cleans_up_or_releases_then_clears_slot() {
        let _guard = TEST_LOCK.lock();
        let Some(storage) = try_map_u32_slab(hints::RENDER_CONTEXT_RELEASE_PRESENTATION, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let context = storage;
        let slot = unsafe { storage.add(0x100).cast::<u32>() };
        let presentation = unsafe { storage.add(0x200).cast::<RenderContextResource>() };

        unsafe {
            let old_cleanup = PRESENTATION_CLEANUP;
            PRESENTATION_CLEANUP = record_cleanup;
            ptr::addr_of_mut!((*presentation).vtable).write(&VTABLE);

            context.add(0xf8).write(0);
            slot.write(presentation as usize as u32);
            CLEANUP_CALLS.store(0, Ordering::SeqCst);
            render_context_release_presentation(context, slot);
            assert_eq!(CLEANUP_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(slot.read(), 0);

            context.add(0xf8).write(1);
            slot.write(presentation as usize as u32);
            RELEASE_CONTEXT.store(0, Ordering::SeqCst);
            render_context_release_presentation(context, slot);
            assert_eq!(RELEASE_CONTEXT.load(Ordering::SeqCst), context as usize);
            assert_eq!(slot.read(), 0);

            slot.write(0);
            render_context_release_presentation(context, slot);
            assert_eq!(RELEASE_CONTEXT.load(Ordering::SeqCst), context as usize);
            PRESENTATION_CLEANUP = old_cleanup;
        }
    }
}
