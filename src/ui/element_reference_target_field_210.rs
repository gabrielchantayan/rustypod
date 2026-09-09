//! Resolve-gated +0x210 field reader on a UI element reference.
//!
//! - `ui_element_reference_target_field_210` — original: `FUN_082a63c0` @
//!   0x082a63c0 (44 bytes; 15 direct `bl` call sites, all unconditional).
//!
//! The reference is the same vtable-headed record used by
//! [`crate::ui::element_reference_cookie`]: its target is the 32-bit word at
//! +0x04 and vtable slot +0x0c decides whether that target resolves.

/// Byte offset of the resolve method inside the reference's vtable
/// (`ldr r1,[r0,#0xc]` — slot 3).
const VTABLE_RESOLVE_OFFSET: usize = 0x0c;

/// Byte offset of the reference's target pointer (`ldrne r0,[r4,#4]`).
const TARGET_OFFSET: usize = 0x04;

/// Byte offset of the returned target field (`ldrne r0,[r0,#0x210]`).
const TARGET_FIELD_OFFSET: usize = 0x210;

/// Vtable slot 3 signature: takes the reference, returning nonzero when it
/// currently resolves.
type ResolveSlot = unsafe extern "C" fn(*const u8) -> u32;

/// ui_element_reference_target_field_210 — original: `FUN_082a63c0` @
/// 0x082a63c0 (44 bytes, exact: 0x082a63ec starts the next separately linked
/// function's `push {r4,lr}` prologue; **15 direct `bl` call sites**, all
/// plain unconditional `bl`, no predicated forms, verified by decoding every
/// ARM B/BL word in `osos.dec`).
///
/// ```text
/// 082a63c0  push    {r4,lr}
/// 082a63c4  mov     r4,r0
/// 082a63c8  ldr     r0,[r0]
/// 082a63cc  ldr     r1,[r0,#0xc]
/// 082a63d0  mov     r0,r4
/// 082a63d4  blx     r1
/// 082a63d8  cmp     r0,#0
/// 082a63dc  ldrne   r0,[r4,#4]
/// 082a63e0  ldrne   r0,[r0,#0x210]
/// 082a63e4  moveq   r0,#0
/// 082a63e8  pop     {r4,pc}
/// ```
///
/// Calls the reference's vtable slot +0x0c with the reference itself. Zero
/// short-circuits to zero without reading the target; any nonzero result
/// returns the target's word at +0x210. The field's semantic identity is not
/// established, so the symbol names its verified storage location rather than
/// inventing a meaning.
///
/// Deliberate host deviation: fixtures store the +0x0c vtable slot as a
/// native function pointer (8 bytes on this host, 4 bytes on ARM), while the
/// reference and target fields remain firmware `u32` words. The static
/// descriptor 0x089a6600's +0x0c word, 0x0826acd8, is a selector/implementation
/// data pair rather than a decodable function entry; this port preserves the
/// raw load-and-call and does not name the runtime target.
///
/// # Safety
///
/// `reference` must be readable through +0x04 and its vtable through +0x0c.
/// If its resolve slot returns nonzero, the target word at +0x04 must name an
/// object readable through +0x214; the original has no target NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reference_target_field_210(
    reference: *const u8,
) -> u32 {
    // ldr r0,[r0]; ldr r1,[r0,#0xc]; mov r0,r4; blx r1.
    let vtable = reference.cast::<u32>().read() as usize as *const u8;
    let resolve: ResolveSlot = vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().read();
    // cmp r0,#0; moveq r0,#0 — no target read on a failed resolve.
    if resolve(reference) == 0 {
        return 0;
    }
    // ldrne r0,[r4,#4]; ldrne r0,[r0,#0x210].
    let target = reference.add(TARGET_OFFSET).cast::<u32>().read() as usize as *const u8;
    target.add(TARGET_FIELD_OFFSET).cast::<u32>().read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOLVE_RESULT: u32 = 0;
    static mut RESOLVE_REFERENCE: *const u8 = ptr::null();
    static mut RESOLVE_CALLS: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn resolve_stub(reference: *const u8) -> u32 {
        RESOLVE_REFERENCE = reference;
        RESOLVE_CALLS += 1;
        RESOLVE_RESULT
    }

    unsafe extern "C" fn wrong_slot_stub(_reference: *const u8) -> u32 {
        WRONG_SLOT_CALLS += 1;
        1
    }

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ELEMENT_REFERENCE_TARGET_FIELD_210,
                0x1000,
            )
            .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    unsafe fn reference() -> *mut u8 {
        slab()
    }

    unsafe fn vtable() -> *mut u8 {
        slab().add(0x100)
    }

    unsafe fn target() -> *mut u8 {
        slab().add(0x400)
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    unsafe fn prepare(resolve_result: u32, field: u32) {
        RESOLVE_RESULT = resolve_result;
        RESOLVE_REFERENCE = ptr::null();
        RESOLVE_CALLS = 0;
        WRONG_SLOT_CALLS = 0;

        write_word(reference(), 0x0, vtable() as u32);
        write_word(reference(), TARGET_OFFSET, target() as u32);
        let slot_end = VTABLE_RESOLVE_OFFSET + core::mem::size_of::<ResolveSlot>();
        for slot in 0..8usize {
            let offset = slot * 4;
            if !(VTABLE_RESOLVE_OFFSET..slot_end).contains(&offset) {
                write_word(vtable(), offset, wrong_slot_stub as u32);
            }
        }
        vtable()
            .add(VTABLE_RESOLVE_OFFSET)
            .cast::<ResolveSlot>()
            .write(resolve_stub);
        write_word(target(), TARGET_FIELD_OFFSET, field);
    }

    #[test]
    fn failed_resolve_returns_zero_without_reading_target() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_target_field_210");
            return;
        }
        unsafe {
            prepare(0, 0xfeed_face);
            // Dereferencing this target would fault, proving the resolve guard.
            write_word(reference(), TARGET_OFFSET, 1);

            assert_eq!(ui_element_reference_target_field_210(reference()), 0);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(RESOLVE_REFERENCE, reference());
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }

    #[test]
    fn nonzero_resolve_returns_target_field_verbatim() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_target_field_210");
            return;
        }
        unsafe {
            prepare(0xffff_ffff, 0xa5c3_1e7f);

            assert_eq!(ui_element_reference_target_field_210(reference()), 0xa5c3_1e7f);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(RESOLVE_REFERENCE, reference());
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }

    #[test]
    fn resolved_reference_preserves_zero_field() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_target_field_210");
            return;
        }
        unsafe {
            prepare(1, 0);

            assert_eq!(ui_element_reference_target_field_210(reference()), 0);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }
}
