//! Re-validating a captured UI element reference against its context.
//!
//! - `ui_element_reference_is_current` — original: `FUN_082a6620` @
//!   0x082a6620 (64 bytes; 65 direct `bl` call sites).
//!
//! The argument is the small vtable-headed reference object built by
//! 0x082840e8/0x08283f3c: a typed target at +0x4, the owning context at
//! +0x8, and a snapshot at +0xc of the element that was current in that
//! context when the reference was created (`*(*(context + 0xf60) + 0x18)`).
//! This predicate answers "is the captured element still the current one":
//! callers such as 0x08060fcc abort with an error when it returns 0, and
//! 0x0816eb38/0x0816f060 only mutate through the reference when it
//! returns 1.

/// Byte offset of the reference's typed target pointer (`ldr r0,[r0,#0x4]`),
/// the argument the stock class check 0x080613e0 validates.
const TARGET_OFFSET: usize = 0x4;

/// Byte offset of the reference's owning context pointer
/// (`ldrne r0,[r4,#0x8]`). Never NULL-checked by the original.
const CONTEXT_OFFSET: usize = 0x8;

/// Byte offset of the element snapshot captured at reference-creation time
/// (`ldr r1,[r4,#0xc]`).
const CAPTURED_ELEMENT_OFFSET: usize = 0xc;

/// Byte offset of the context's active sub-object pointer
/// (`ldrne r0,[r0,#0xf60]`).
const CONTEXT_ACTIVE_OFFSET: usize = 0xf60;

/// Byte offset of the current element inside the active sub-object
/// (`ldr r0,[r0,#0x18]`).
const ACTIVE_ELEMENT_OFFSET: usize = 0x18;

/// Class-check signature shared with the host-test interception slot.
type TargetClassCheck = unsafe extern "C" fn(*const u8) -> u32;

/// Calls the stock target class check, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x080613e0. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original returns 1 when `target` is non-NULL
/// and the word at `target + 4` equals the class tag held in its literal
/// pool at 0x08061404, 0 otherwise — a "live object of the expected class"
/// check.
unsafe extern "C" fn firmware_target_class_check(target: *const u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        let target_class_check: TargetClassCheck = core::mem::transmute(0x0806_13e0usize);
        target_class_check(target)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = target;
        0
    }
}

/// Narrow boundary for the unported 0x080613e0 dependency.
static mut TARGET_CLASS_CHECK: TargetClassCheck = firmware_target_class_check;

#[inline(always)]
unsafe fn target_class_check_fn() -> TargetClassCheck {
    core::ptr::read_volatile(core::ptr::addr_of!(TARGET_CLASS_CHECK))
}

/// ui_element_reference_is_current — original: `FUN_082a6620` @ 0x082a6620
/// (64 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/029/082a6620_FUN_082a6620.c`;
/// assembly: `decomp/osos.asm` @ `0x082a6620..0x082a6660`.
///
/// Runs the stock class check 0x080613e0 on the reference's target at
/// +0x4; if it reports 0 the predicate returns 0 without touching the
/// context (the `cmp`/`ldrne` short-circuit). Otherwise it dereferences
/// the context at +0x8 with no NULL guard — exactly like the original's
/// unconditional `ldrne` pair — and loads the active sub-object at
/// `context + 0xf60`. A NULL active sub-object also yields 0. Finally it
/// returns 1 only when the active sub-object's current element at +0x18
/// equals the reference's captured element snapshot at +0xc.
///
/// Call-site evidence: 0x08060fcc builds a reference on its stack from an
/// object's +0xf50 field and returns error 0xfffeffff when the predicate
/// fails; 0x0816eb38/0x0816f060 gate mutation through an embedded
/// reference (at object +0x14) on it; 0x08113cc0 gates a vtable call on
/// the reference embedded at object +0x888 + 0x60. Together with the
/// reference initializer 0x08283f3c (which snapshots
/// `*(*(context + 0xf60) + 0x18)` into +0xc at creation), the predicate
/// establishes "the element this reference captured is still the context's
/// current element" — a staleness check on a captured UI element
/// reference.
///
/// All pointer fields are 32-bit target words, exactly as the ARM `ldr`s
/// load them, so the port reads `u32` and widens — the same shape
/// [`crate::ui::resource_release`] uses. Host fixtures must therefore live
/// below 4 GiB (see `src/testing.rs`).
///
/// # Safety
///
/// Like the original, there is no NULL guard on `reference`: it must be
/// readable through offset +0xc. When the class check passes, the context
/// pointer at +0x8 must be readable at +0xf60, and a non-NULL active
/// sub-object must be readable at +0x18.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reference_is_current(reference: *const u8) -> u32 {
    let target = reference.add(TARGET_OFFSET).cast::<u32>().read();
    if target_class_check_fn()(target as usize as *const u8) == 0 {
        return 0;
    }

    let context = reference.add(CONTEXT_OFFSET).cast::<u32>().read();
    let active = (context as usize as *const u8)
        .add(CONTEXT_ACTIVE_OFFSET)
        .cast::<u32>()
        .read();
    if active == 0 {
        return 0;
    }

    let current = (active as usize as *const u8)
        .add(ACTIVE_ELEMENT_OFFSET)
        .cast::<u32>()
        .read();
    let captured = reference.add(CAPTURED_ELEMENT_OFFSET).cast::<u32>().read();
    u32::from(current == captured)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    /// The class-check seam and the shared slab fixture are global, so the
    /// tests serialize on one lock.
    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut STUB_RESULT: u32 = 0;
    static mut STUB_TARGET: *const u8 = ptr::null();
    static mut STUB_CALLS: u32 = 0;

    unsafe extern "C" fn target_class_check_stub(target: *const u8) -> u32 {
        STUB_TARGET = target;
        STUB_CALLS += 1;
        STUB_RESULT
    }

    /// Maps the fixture slab once per process. The port widens `u32` target
    /// words into host pointers and dereferences them, so every fixture
    /// record must live below 4 GiB; `None` means this host cannot supply
    /// such a mapping and the tests skip rather than crash.
    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::ELEMENT_REFERENCE, 0x2000)
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

    /// The reference record under test (+0x4 target, +0x8 context, +0xc
    /// captured element).
    unsafe fn reference() -> *mut u8 {
        slab()
    }

    /// Stand-in for the typed target object; only its address is observed
    /// (the stub never dereferences it).
    unsafe fn target() -> *mut u8 {
        slab().add(0x100)
    }

    /// The owning context record; its active sub-object word lives at
    /// +0xf60.
    unsafe fn context() -> *mut u8 {
        slab().add(0x200)
    }

    /// The context's active sub-object; its current element word lives at
    /// +0x18.
    unsafe fn active() -> *mut u8 {
        slab().add(0x1200)
    }

    /// Stand-in for the current/captured element; only its address is
    /// compared.
    unsafe fn element() -> *mut u8 {
        slab().add(0x1400)
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    /// Resets every fixture word a test can observe, then installs the
    /// class-check stub returning `stub_result`.
    unsafe fn prepare(stub_result: u32) {
        STUB_RESULT = stub_result;
        STUB_TARGET = ptr::null();
        STUB_CALLS = 0;
        TARGET_CLASS_CHECK = target_class_check_stub;

        write_word(reference(), TARGET_OFFSET, target() as u32);
        write_word(reference(), CONTEXT_OFFSET, context() as u32);
        write_word(reference(), CAPTURED_ELEMENT_OFFSET, element() as u32);
        write_word(context(), CONTEXT_ACTIVE_OFFSET, active() as u32);
        write_word(active(), ACTIVE_ELEMENT_OFFSET, element() as u32);
    }

    #[test]
    fn class_check_failure_short_circuits_to_zero() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference");
            return;
        }
        unsafe {
            prepare(0);
            // A poisoned context word proves the short-circuit never reads
            // it: dereferencing 1 would fault.
            write_word(reference(), CONTEXT_OFFSET, 1);

            assert_eq!(ui_element_reference_is_current(reference()), 0);
            assert_eq!(STUB_CALLS, 1);
            assert_eq!(STUB_TARGET, target());
        }
    }

    #[test]
    fn null_active_subobject_returns_zero() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference");
            return;
        }
        unsafe {
            prepare(1);
            write_word(context(), CONTEXT_ACTIVE_OFFSET, 0);

            assert_eq!(ui_element_reference_is_current(reference()), 0);
            assert_eq!(STUB_CALLS, 1);
        }
    }

    #[test]
    fn mismatched_current_element_returns_zero() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference");
            return;
        }
        unsafe {
            prepare(1);
            // The active sub-object now reports a different current element
            // than the reference captured.
            write_word(active(), ACTIVE_ELEMENT_OFFSET, target() as u32);

            assert_eq!(ui_element_reference_is_current(reference()), 0);
            assert_eq!(STUB_CALLS, 1);
        }
    }

    #[test]
    fn matching_current_element_returns_one() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference");
            return;
        }
        unsafe {
            prepare(7);

            assert_eq!(ui_element_reference_is_current(reference()), 1);
            assert_eq!(STUB_CALLS, 1);
            assert_eq!(STUB_TARGET, target());
        }
    }
}
