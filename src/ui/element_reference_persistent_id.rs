//! Resolve-gated persistent-ID getter on a UI element reference.
//!
//! - `ui_element_reference_target_persistent_id` — original:
//!   `FUN_082a6524` @ 0x082a6524 (48 bytes; 21 direct `bl` call sites, all
//!   unconditional, verified by decoding every ARM B/BL word in `osos.dec`).
//!
//! The reference is the same 20-byte vtable-headed record used by
//! `element_reference_cookie`: its target is the 32-bit word at +0x04 and its
//! vtable's slot +0x0c decides whether that target resolves.

/// Byte offset of the resolve method inside the reference's vtable
/// (`ldr r1,[r0,#0xc]` — slot 3).
const VTABLE_RESOLVE_OFFSET: usize = 0x0c;

/// Byte offset of the reference's target pointer (`ldrne r1,[r4,#4]`).
const TARGET_OFFSET: usize = 0x04;

/// Byte offset of the target's persistent identifier (`ldrdne r0,r1,[r1,#0x30]`).
const PERSISTENT_ID_OFFSET: usize = 0x30;

/// Vtable slot 3 signature: takes the reference, returning nonzero when it
/// currently resolves.
type ResolveSlot = unsafe extern "C" fn(*const u8) -> u32;

/// ui_element_reference_target_persistent_id — original: `FUN_082a6524` @
/// 0x082a6524 (48 bytes, exact: 0x082a6554 starts the next separately linked
/// function's `push {r4,r5,lr}`; **21 direct `bl` call sites**, all plain
/// unconditional `bl`, no predicated forms, binary-scanned over every ARM
/// B/BL word in `osos.dec`).
///
/// ```text
/// 082a6524  push    {r4,lr}
/// 082a6528  mov     r4,r0
/// 082a652c  ldr     r0,[r0]
/// 082a6530  ldr     r1,[r0,#0xc]
/// 082a6534  mov     r0,r4
/// 082a6538  blx     r1
/// 082a653c  cmp     r0,#0
/// 082a6540  ldrne   r1,[r4,#4]
/// 082a6544  moveq   r0,#0
/// 082a6548  ldrdne  r0,r1,[r1,#0x30]
/// 082a654c  moveq   r1,#0
/// 082a6550  pop     {r4,pc}
/// ```
///
/// Calls the reference's vtable slot +0x0c with the reference itself. A zero
/// result returns the zero 64-bit identifier without reading the target; any
/// nonzero result reads and returns the target's aligned 64-bit value at
/// +0x30. The persistent-ID name is call-site grounded: 0x080b558c and
/// 0x080b55a8 serialize it under `playlistPersistentID`, while 0x0813cc50
/// and 0x0813cc68 compare it against another object's virtual identity.
///
/// Deliberate deviations: host fixtures store the +0x0c vtable slot as a
/// native function pointer (8 bytes on this host, 4 bytes on ARM), while the
/// reference and target fields remain firmware `u32` words. The descriptor
/// 0x089a6600's static +0x0c word, 0x0826acd8, is a selector/implementation
/// data pair rather than a function entry; as with the sibling cookie getter,
/// the port performs the raw load-and-call without inventing a callee name.
///
/// # Safety
///
/// `reference` must be readable through +0x04 and its vtable through +0x0c.
/// If its resolve slot returns nonzero, the target word at +0x04 must name an
/// object readable through +0x38 and aligned for the original ARMv5TE `ldrd`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reference_target_persistent_id(
    reference: *const u8,
) -> u64 {
    // ldr r0,[r0]; ldr r1,[r0,#0xc]; mov r0,r4; blx r1.
    let vtable = reference.cast::<u32>().read() as usize as *const u8;
    let resolve: ResolveSlot = vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().read();
    // cmp r0,#0; moveq r0,#0; moveq r1,#0 — no target read on failure.
    if resolve(reference) == 0 {
        return 0;
    }
    // ldrne r1,[r4,#4]; ldrdne r0,r1,[r1,#0x30].
    let target = reference.add(TARGET_OFFSET).cast::<u32>().read() as usize as *const u8;
    target.add(PERSISTENT_ID_OFFSET).cast::<u64>().read()
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
                crate::testing::hints::ELEMENT_REFERENCE_PERSISTENT_ID,
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

    unsafe fn prepare(resolve_result: u32, persistent_id: u64) {
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
        target()
            .add(PERSISTENT_ID_OFFSET)
            .cast::<u64>()
            .write(persistent_id);
    }

    #[test]
    fn failed_resolve_returns_zero_without_reading_target() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_persistent_id");
            return;
        }
        unsafe {
            prepare(0, 0x8877_6655_4433_2211);
            // A poisoned target would fault if the failed-resolve path read it.
            write_word(reference(), TARGET_OFFSET, 1);

            assert_eq!(ui_element_reference_target_persistent_id(reference()), 0);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(RESOLVE_REFERENCE, reference());
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }

    #[test]
    fn resolved_reference_returns_full_persistent_id_in_aapcs_order() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_persistent_id");
            return;
        }
        unsafe {
            // Distinct low/high halves prove the target +0x30 doubleword is
            // returned r0-low/r1-high, not truncated or swapped.
            let persistent_id = 0x1122_3344_5566_7788;
            prepare(0xffff_ffff, persistent_id);

            assert_eq!(ui_element_reference_target_persistent_id(reference()), persistent_id);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(RESOLVE_REFERENCE, reference());
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }

    #[test]
    fn resolved_reference_preserves_zero_persistent_id() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_persistent_id");
            return;
        }
        unsafe {
            prepare(1, 0);

            assert_eq!(ui_element_reference_target_persistent_id(reference()), 0);
            assert_eq!(RESOLVE_CALLS, 1);
        }
    }
}
