//! Releases an optional render-context resource through its vtable.
//!
//! `render_context_release_resource` is retailOS `FUN_0828d4e0` at
//! **0x0828d4e0**. Raw `osos.dec` words establish the true 36-byte extent:
//! nine ARM instructions from 0x0828d4e0 through 0x0828d500, followed by the
//! next function at 0x0828d504. Decoding inbound ARM branch words finds four
//! direct, unconditional `bl` call sites and zero predicated calls. Its body
//! has no direct `bl`; it makes one indirect `blx` through vtable slot +0x04.
//!
//! # Algorithm
//!
//! Load the resource pointer from `slot`, call its vtable's +0x04 entry with
//! the incoming context still in r0, then clear `slot`. Neither pointer is
//! validated.
//!
//! # Deliberate deviations
//!
//! The unlifted vtable target has no established identity, so the host uses a
//! typed slot rather than treating 64-bit host pointers as target u32 words.
//! ARM uses the exact recovered instruction sequence.

#[cfg(not(target_arch = "arm"))]
use core::ptr;

/// Resource object whose vtable's second entry is its release operation.
#[repr(C)]
pub struct RenderContextResource {
    pub vtable: *const RenderContextResourceVtable,
}

/// Recovered prefix of a render-context resource vtable.
#[repr(C)]
pub struct RenderContextResourceVtable {
    /// +0x00: unresolved virtual entry.
    pub unresolved_00: usize,
    /// +0x04: releases this resource with its owning render context.
    pub release: unsafe extern "C" fn(*mut u8),
}

/// render_context_release_resource — original: `FUN_0828d4e0` @ **0x0828d4e0**
/// (36 bytes; next function begins at 0x0828d504).
///
/// # Safety
///
/// `slot` must be readable and writable. Its nonzero target word must identify
/// a resource with a readable vtable and callable release entry; `context` is
/// passed through unchanged to that entry.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn render_context_release_resource(context: *mut u8, slot: *mut u32) {
    let resource = ptr::read(slot) as usize as *mut RenderContextResource;
    let vtable = ptr::read(ptr::addr_of!((*resource).vtable));
    ((*vtable).release)(context);
    ptr::write(slot, 0);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl render_context_release_resource
    .type render_context_release_resource, %function
render_context_release_resource:
    push    {{r4, lr}}
    ldr     r0, [r1]
    mov     r4, r1
    ldr     r1, [r0]
    ldr     r1, [r1, #4]
    blx     r1
    mov     r0, #0
    str     r0, [r4]
    pop     {{r4, pc}}
    .size render_context_release_resource, . - render_context_release_resource
"#
);

#[cfg(target_arch = "arm")]
extern "C" {
    pub fn render_context_release_resource(context: *mut u8, slot: *mut u32);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static RELEASE_CONTEXT: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_SLOT: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_SLOT_VALUE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release(context: *mut u8) {
        RELEASE_CONTEXT.store(context as usize, Ordering::SeqCst);
        RELEASE_SLOT_VALUE.store((RELEASE_SLOT.load(Ordering::SeqCst) as *const u32).read() as usize, Ordering::SeqCst);
    }

    static VTABLE: RenderContextResourceVtable = RenderContextResourceVtable {
        unresolved_00: 0,
        release: record_release,
    };

    #[test]
    fn releases_before_clearing_the_target_word() {
        let _guard = TEST_LOCK.lock();
        let Some(storage) = try_map_u32_slab(hints::RENDER_CONTEXT_RELEASE_RESOURCE, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let resource = unsafe { storage.add(0x100).cast::<RenderContextResource>() };
        let slot = unsafe { storage.add(0x200).cast::<u32>() };
        let context = unsafe { storage.add(0x300) };

        unsafe {
            addr_of_mut!((*resource).vtable).write(&VTABLE);
            slot.write(resource as usize as u32);
            RELEASE_SLOT.store(slot as usize, Ordering::SeqCst);
            RELEASE_SLOT_VALUE.store(0, Ordering::SeqCst);
            render_context_release_resource(context, slot);
            assert_eq!(RELEASE_CONTEXT.load(Ordering::SeqCst), context as usize);
            assert_eq!(slot.read(), 0);
            assert_eq!(RELEASE_SLOT_VALUE.load(Ordering::SeqCst), resource as usize);
            assert!(addr_of!((*resource).vtable).read() == &VTABLE);
        }
    }
}
