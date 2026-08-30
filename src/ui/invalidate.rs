//! `ui_element_invalidate` — original: `FUN_0826ec9c` @ 0x0826ec9c
//! (8 bytes, extent binary-verified: the next function's
//! `push {r4,r5,r6,lr}` opens at 0x0826eca4; **32 `bl` + 3 predicated
//! `blne` + 17 `b` + 7 predicated `b` call sites** = 59 branch
//! references, binary-verified by decoding every B/BL word in osos.dec —
//! Ghidra's "35 bl" is the 32 + 3 `bl`/`blne` split. No data-word
//! references to 0x0826ec9c anywhere in the image, so the thunk is never
//! dispatched virtually).
//!
//! # Algorithm
//!
//! An 8-byte thunk — NOT a veneer (a veneer is `ldr pc,[pc,#-4]` plus a
//! target word; this is a register fix-up plus a plain `b`) and NOT an
//! empty destructor (`bx lr`):
//!
//! ```text
//! 0826ec9c  add  r1, r0, #0x80   @ region = &element->bounds
//! 0826eca0  b    0x0826ec14      @ tail -> invalidate_region(element, region)
//! ```
//!
//! It tail-branches to the unported region form `FUN_0826ec14` with the
//! second argument forced to the element's own bounds rectangle at +0x80:
//! "mark the element's whole bounds dirty". The target (verified from raw
//! bytes at 0x0826ec14) pushes r0-r6 as a 16-byte stack rect frame, then,
//! gated on `(element->flags_48 & 0x1800) == 0x800` (the 20-byte flag test
//! @ 0x082a26c8), `element->byte_a0 == 0`, and the global redraw-enable
//! byte @ 0x089cc888, intersects the argument rect with the element's
//! bounds (+0x80, `rect_intersect_into` @ 0x0826c24c, ported) and the
//! parent's clip rect (+0xd0 of element->parent +0x34, `rect_intersect` @
//! 0x0826c1c8, ported), resolves the render context
//! ([`crate::ui::render_context::ui_element_resolve_render_context`] @
//! 0x082a2670, ported) and, when one exists, hands the clipped rect to
//! the origin-adjust/dirty-region pair @ 0x0828cb64 / 0x0828d9b4 — the
//! latter unions it into the context's accumulated dirty rect at +0xdc
//! (`rect_union` @ 0x0826c3d8, ported) under the +0xd4 lock. Its closing
//! `pop {r0-r6,pc}` restores r0 = element and r1 = element + 0x80.
//!
//! # Call-site protocol
//!
//! The predicated forms are the tell: the thunk has no NULL guard of its
//! own (and the body dereferences element +0x48/+0xa0 immediately), so
//! callers test the pointer first — `cmp r0,#0; blne 0x0826ec9c` at
//! 0x0812af7c, 0x0812af88 and 0x081bac1c, and `beq`/`bne` tail forms at
//! 0x0816b074 / 0x0812af98 / 0x08198ae8 gating on a computed flag.
//!
//! # Deliberate deviations
//!
//! - The original is a tail branch; the port *calls* the seam and then
//!   returns `element`. This preserves the observable r0 across the
//!   boundary (the original body's `pop {r0-r6,pc}` hands back
//!   r0 = element). The original also restores r1 = element + 0x80, but
//!   r1 is a caller-saved scratch register no AAPCS caller can legally
//!   consume — sampled sites (0x0812af60, 0x081430dc, 0x081a0fdc)
//!   overwrite r0 immediately and never read r1.
//! - The region form `FUN_0826ec14` is unported (not in names.yaml), so
//!   it rides the [`UI_ELEMENT_INVALIDATE_REGION`] seam, the house
//!   pattern: target builds transmute the retail address 0x0826ec14 (the
//!   port is hook-ready on device), host tests install a recording model
//!   and the host default is inert.
//! - `wrapping_add` for the +0x80 bounds pointer: identical machine code
//!   to the original's bare `add r1, r0, #0x80` on ARMv5TE, with the
//!   wrap-around semantics pinned by a test.

/// Byte offset of a UI element's bounds rectangle (`add r1, r0, #0x80`).
/// The same +0x80 field the region form intersects against, and the same
/// base [`crate::ui::render_context`] callers treat as the element rect.
const BOUNDS_OFFSET: usize = 0x80;

/// The unported region form's retail address — original: `FUN_0826ec14`
/// @ 0x0826ec14. Reached by the seam default on the firmware target only.
#[cfg(target_os = "none")]
const INVALIDATE_REGION_ADDRESS: usize = 0x0826_ec14;

/// ABI of the region form `FUN_0826ec14`: `(element, region)` where
/// `region` is a four-word `Rect` pointer. Its r0/r1 results (element,
/// region) are restored-scratch, not a returned value, so the seam is
/// void and [`ui_element_invalidate`] returns `element` itself.
pub type UiElementInvalidateRegion = unsafe extern "C" fn(element: *mut u8, region: *mut u8);

/// Target default: the retail `FUN_0826ec14` body at 0x0826ec14.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_invalidate_region(element: *mut u8, region: *mut u8) {
    let invalidate: UiElementInvalidateRegion =
        core::mem::transmute(INVALIDATE_REGION_ADDRESS);
    invalidate(element, region)
}

/// Host default: inert. Faithful in that the thunk's only observable
/// behaviour without a body is the return of `element`.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_invalidate_region(_element: *mut u8, _region: *mut u8) {}

/// The active region form — the dispatch seam for `FUN_0826ec14` @
/// 0x0826ec14. Host tests install a recording model; the real port
/// replaces the default when it lands.
#[cfg(target_os = "none")]
pub static mut UI_ELEMENT_INVALIDATE_REGION: UiElementInvalidateRegion = firmware_invalidate_region;

/// The active region form — inert host default (see above).
#[cfg(not(target_os = "none"))]
pub static mut UI_ELEMENT_INVALIDATE_REGION: UiElementInvalidateRegion = missing_invalidate_region;

/// ui_element_invalidate — original: `FUN_0826ec9c` @ 0x0826ec9c
/// (8 bytes).
///
/// Marks the element's entire bounds rectangle dirty: tail-dispatches the
/// region form with `region = element + 0x80`. Returns `element` (the
/// original's r0 on exit). No NULL guard, matching the original —
/// callers predicate the branch themselves.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_invalidate(element: *mut u8) -> *mut u8 {
    // Volatile: LLVM must not fold the default in and delete the dispatch
    // (the event_hub.rs rationale), and a host test's installed model must
    // be observed.
    let invalidate_region =
        core::ptr::read_volatile(core::ptr::addr_of!(UI_ELEMENT_INVALIDATE_REGION));
    invalidate_region(element, element.wrapping_add(BOUNDS_OFFSET));
    element
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    /// Serializes access to the process-global seam slot.
    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    static mut SEEN_ELEMENT: *mut u8 = ptr::null_mut();
    static mut SEEN_REGION: *mut u8 = ptr::null_mut();
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn recording_invalidate_region(element: *mut u8, region: *mut u8) {
        SEEN_ELEMENT = element;
        SEEN_REGION = region;
        CALLS += 1;
    }

    /// Installs the recording model and returns the lock guard; the slot is
    /// restored to the inert default when the guard drops.
    struct SeamGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                UI_ELEMENT_INVALIDATE_REGION = missing_invalidate_region;
            }
        }
    }

    fn install_recorder() -> SeamGuard {
        let lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            SEEN_ELEMENT = ptr::null_mut();
            SEEN_REGION = ptr::null_mut();
            CALLS = 0;
            UI_ELEMENT_INVALIDATE_REGION = recording_invalidate_region;
        }
        SeamGuard { _lock: lock }
    }

    #[test]
    fn dispatches_the_region_form_with_the_bounds_pointer_at_plus_0x80() {
        let _guard = install_recorder();
        let mut element = [0u8; 4];

        let returned = unsafe { ui_element_invalidate(element.as_mut_ptr()) };

        unsafe {
            assert_eq!(CALLS, 1, "exactly one dispatch into the region form");
            assert_eq!(SEEN_ELEMENT, element.as_mut_ptr(), "r0 passes through unchanged");
            assert_eq!(
                SEEN_REGION,
                element.as_mut_ptr().wrapping_add(BOUNDS_OFFSET),
                "r1 = element + 0x80, the bounds rectangle"
            );
        }
        assert_eq!(returned, element.as_mut_ptr(), "r0 = element on exit");
    }

    #[test]
    fn bounds_pointer_addition_wraps_like_the_original_add() {
        let _guard = install_recorder();
        // A raw `add r1, r0, #0x80` wraps mod 2^32; the port must not
        // saturate or trap. On a 64-bit host the same wrap is observed at
        // the usize boundary.
        let element = (-0x40isize) as usize as *mut u8;

        let returned = unsafe { ui_element_invalidate(element) };

        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_REGION, 0x40usize as *mut u8, "wrapped bounds pointer");
        }
        assert_eq!(returned, element);
    }

    #[test]
    fn default_host_stub_is_inert_and_still_returns_the_element() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            CALLS = 0;
            UI_ELEMENT_INVALIDATE_REGION = missing_invalidate_region;
        }
        let mut element = [0u8; 4];

        let returned = unsafe { ui_element_invalidate(element.as_mut_ptr()) };

        assert_eq!(returned, element.as_mut_ptr());
        assert_eq!(unsafe { CALLS }, 0, "no recorder installed, nothing records");
    }
}
