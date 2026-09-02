//! Resolve-gated cookie check on a UI element reference's target.
//!
//! - `ui_element_reference_target_has_cookie` — original: `FUN_082a66f0` @
//!   0x082a66f0 (72 bytes; 22 direct `bl` call sites, all unconditional —
//!   verified by decoding every B/BL word in osos.dec, none predicated).
//!
//! The argument is the same vtable-headed element-reference object the
//! sibling [`crate::ui::element_reference`] predicate takes: vtable pointer
//! at +0x0, typed target element at +0x4. The reference constructors
//! 0x082840e8/0x08284118/0x0828414c all install the vtable at 0x089a6600,
//! and the second-stage initializer 0x08283f3c fills +0x4 (target), +0x8
//! (context) and +0xc (captured element snapshot) without touching +0x0.

/// Byte offset of the resolve method inside the reference's vtable
/// (`ldr r1,[r0,#0xc]` — slot 3).
const VTABLE_RESOLVE_OFFSET: usize = 0xc;

/// Byte offset of the reference's typed target pointer
/// (`ldr r0,[r4,#0x4]`).
const TARGET_OFFSET: usize = 0x4;

/// Byte offset of the 64-bit cookie inside the target element
/// (`add r0,r0,#0x218; ldrd r0,r1,[r0]`). The original reads it with a
/// single `ldrd`, which on ARMv5TE requires 8-byte alignment, so the
/// firmware guarantees the target record keeps +0x218 doubleword-aligned;
/// the port makes the same assumption with one aligned `u64` read.
const COOKIE_OFFSET: usize = 0x218;

/// Vtable slot 3 signature: takes the reference, returns nonzero when the
/// reference currently resolves.
type ResolveSlot = unsafe extern "C" fn(*const u8) -> u32;

/// ui_element_reference_target_has_cookie — original: `FUN_082a66f0` @
/// 0x082a66f0 (72 bytes, 0x082a66f0..0x082a6738; extent confirmed against
/// the next function's `push {r4,lr}` prologue at 0x082a6738).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/029/082a66f0_FUN_082a66f0.c`;
/// assembly: `decomp/osos.asm` @ `0x082a66f0..0x082a6738` (raw bytes in
/// osos.dec verified to match that listing exactly).
///
/// Algorithm: call the reference's vtable slot 3 (`blx` through
/// `*(*reference + 0xc)`) with the reference itself. When it returns 0 the
/// predicate returns 0 without touching the target (the `cmp r0,#0x0;
/// beq` short-circuit). Otherwise it dereferences the target at +0x4 with
/// no NULL guard and returns 1 only when the 64-bit cookie at
/// `target + 0x218` is nonzero — the original's `ldrd` + `cmp r1,#0;
/// cmpeq r0,r2; movne r0,#1` sequence, i.e. hi-half set OR lo-half set.
///
/// Family context: this is one of several resolve-gated property readers
/// on the same reference object — 0x082a63c0 reads target+0x210,
/// 0x082a66c0 target+0x1ac bit 0, 0x082a6738 target+0x18c bit 6 — all
/// sharing the identical slot-3 guard. The cookie itself is written at
/// 0x0816edc8: the {+0x110, +0x114} pair of the context's current object
/// is copied into target+0x218/+0x21c while flag target+0x18c gains 0x80,
/// or both halves are set to 0xFFFFFFFF (0x0816edd4) — never zeroed there,
/// so zero is the never-assigned state. Callers use the predicate as a
/// reference-identity component (0x0813cbd4 compares it against a second
/// object's vtable slot +0x54 result) and as a wait gate (0x080b53b4 in
/// the iTunes-control path waits on a lock while it holds).
///
/// Unresolved anomaly, documented not invented: vtable 0x089a6600's slot
/// +0xc statically contains 0x0826acd8, which does NOT decode as a
/// function entry — it is the first word of a {0x801e, 0x08ae5474}
/// selector/impl data pair, and the value is referenced as data by
/// hundreds of tables in the 0x0898bxxx region. The runtime value is most
/// plausibly established by a boot-time table fixup pass. The port
/// reproduces the raw load-and-`blx` sequence and deliberately does not
/// name the callee.
///
/// All pointer fields are 32-bit target words, exactly as the ARM `ldr`s
/// load them, so the reference's vtable and target pointers are read as
/// `u32` and widened — the same shape [`crate::ui::element_reference`]
/// uses, and host fixtures for them must live below 4 GiB (see
/// `src/testing.rs`). The vtable slot word alone is read as a native
/// function pointer (4 bytes on the ARM target, matching the original's
/// single `ldr`; 8 on host so tests can install an untruncated stub — no
/// other field is read from the vtable record, so the wider host read
/// overlaps nothing).
///
/// # Safety
///
/// Like the original, there is no NULL guard on `reference`: it must be
/// readable at +0x0, its vtable at +0xc, and — once the resolve call
/// returns nonzero — the target at +0x4 must be readable through
/// +0x218..+0x220 with 8-byte alignment.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reference_target_has_cookie(
    reference: *const u8,
) -> u32 {
    // ldr r0,[r0,#0x0]; ldr r1,[r0,#0xc]; mov r0,r4; blx r1 —
    // resolve through vtable slot 3.
    let vtable = reference.cast::<u32>().read() as usize as *const u8;
    let resolve: ResolveSlot = vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().read();
    // cmp r0,#0x0; beq — a failed resolve short-circuits before the
    // target is touched.
    if resolve(reference) == 0 {
        return 0;
    }
    // ldr r0,[r4,#0x4]; add r0,r0,#0x218; ldrd r0,r1,[r0] —
    // the target's 64-bit cookie.
    let target = reference.add(TARGET_OFFSET).cast::<u32>().read() as usize as *const u8;
    let cookie = target.add(COOKIE_OFFSET).cast::<u64>().read();
    // cmp r1,#0x0; cmpeq r0,r2; movne r0,#0x1 — nonzero in EITHER half.
    u32::from(cookie != 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    /// The shared slab fixture is global, so the tests serialize on one
    /// lock.
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

    /// Installed in every vtable slot except +0xc: any call through it
    /// proves the port picked the wrong slot.
    unsafe extern "C" fn wrong_slot_stub(_reference: *const u8) -> u32 {
        WRONG_SLOT_CALLS += 1;
        1
    }

    /// Maps the fixture slab once per process. The port widens `u32`
    /// vtable/target words into host pointers and dereferences them, so
    /// every fixture record must live below 4 GiB; `None` means this host
    /// cannot supply such a mapping and the tests skip rather than crash.
    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ELEMENT_REFERENCE_COOKIE,
                0x2000,
            )
            .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    /// The fixture base. Only reached once [`try_slab`] has confirmed the
    /// mapping exists, so the panic here is a programming error, not a
    /// host-capability shortfall.
    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    /// The reference record under test (+0x0 vtable, +0x4 target).
    unsafe fn reference() -> *mut u8 {
        slab()
    }

    /// The vtable record; only slot +0xc is read by the port (host-sized,
    /// so +0x10..+0x14 is its padding on 64-bit hosts).
    unsafe fn vtable() -> *mut u8 {
        slab().add(0x100)
    }

    /// The target element record; its 64-bit cookie lives at +0x218.
    unsafe fn target() -> *mut u8 {
        slab().add(0x400)
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    /// Resets every fixture word a test can observe, installs the resolve
    /// stub returning `resolve_result`, and zeroes the cookie.
    unsafe fn prepare(resolve_result: u32) {
        RESOLVE_RESULT = resolve_result;
        RESOLVE_REFERENCE = ptr::null();
        RESOLVE_CALLS = 0;
        WRONG_SLOT_CALLS = 0;

        write_word(reference(), 0x0, vtable() as u32);
        write_word(reference(), TARGET_OFFSET, target() as u32);
        // Every slot but +0xc is a tripwire; the port must pick +0xc.
        // The slot itself is read host-sized, so on 64-bit hosts it spans
        // +0xc..+0x14 — leave those padding bytes to the native-pointer
        // write below.
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
        target().add(COOKIE_OFFSET).cast::<u64>().write(0);
    }

    #[test]
    fn failed_resolve_short_circuits_to_zero() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_cookie");
            return;
        }
        unsafe {
            prepare(0);
            // A poisoned target word proves the short-circuit never reads
            // it: dereferencing 1 would fault.
            write_word(reference(), TARGET_OFFSET, 1);

            assert_eq!(ui_element_reference_target_has_cookie(reference()), 0);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(RESOLVE_REFERENCE, reference());
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }

    #[test]
    fn resolved_reference_with_zero_cookie_returns_zero() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_cookie");
            return;
        }
        unsafe {
            prepare(1);

            assert_eq!(ui_element_reference_target_has_cookie(reference()), 0);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }

    #[test]
    fn cookie_set_in_low_half_returns_one() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_cookie");
            return;
        }
        unsafe {
            prepare(1);
            // Only +0x218 set: the original's `cmpeq r0,r2` path must
            // still yield 1 (`cmp r1,#0` equal, then lo half nonzero).
            target().add(COOKIE_OFFSET).cast::<u64>().write(0x1122_3344);

            assert_eq!(ui_element_reference_target_has_cookie(reference()), 1);
        }
    }

    #[test]
    fn cookie_set_in_high_half_returns_one() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_cookie");
            return;
        }
        unsafe {
            prepare(1);
            // Only +0x21c set: the original's `cmp r1,#0` alone yields 1
            // without ever comparing the low half.
            target()
                .add(COOKIE_OFFSET)
                .cast::<u64>()
                .write(0x5566_7788_0000_0000);

            assert_eq!(ui_element_reference_target_has_cookie(reference()), 1);
        }
    }

    #[test]
    fn cookie_minus_one_returns_one() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_cookie");
            return;
        }
        unsafe {
            prepare(1);
            // The firmware's other write path (0x0816edd4) stores
            // 0xFFFFFFFF to both halves; that must read as "has cookie".
            target().add(COOKIE_OFFSET).cast::<u64>().write(u64::MAX);

            assert_eq!(ui_element_reference_target_has_cookie(reference()), 1);
        }
    }

    #[test]
    fn resolve_result_is_only_tested_against_zero() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_cookie");
            return;
        }
        unsafe {
            // Any nonzero resolve result, not just 1, opens the gate.
            prepare(0xffff_ffff);
            target().add(COOKIE_OFFSET).cast::<u64>().write(1);

            assert_eq!(ui_element_reference_target_has_cookie(reference()), 1);
        }
    }
}
