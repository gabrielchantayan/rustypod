//! Resolve-gated bit-0 reader on a UI element reference target.
//!
//! - `ui_element_reference_target_flag_bit_0` — original: `FUN_082a66c0` @
//!   0x082a66c0 (48 bytes; 3 direct `bl` call sites, all unconditional).

/// Byte offset of the resolve method inside the reference's vtable.
const VTABLE_RESOLVE_OFFSET: usize = 0x0c;
/// Byte offset of the reference's target pointer.
const TARGET_OFFSET: usize = 0x04;
/// Byte offset of the target byte whose bit 0 is returned.
const TARGET_FLAG_OFFSET: usize = 0x1ac;

type ResolveSlot = unsafe extern "C" fn(*const u8) -> u32;

/// ui_element_reference_target_flag_bit_0 — original: `FUN_082a66c0` @
/// 0x082a66c0 (48 bytes, 0x082a66c0..0x082a66f0; extent confirmed against
/// the next `push {r4,lr}` prologue at 0x082a66f0). Three direct call sites
/// decode as plain unconditional `bl`; none is predicated. The body itself
/// makes one indirect `blx` through vtable slot 3.
///
/// ```text
/// 082a66c0  push    {r4,lr}
/// 082a66c4  mov     r4,r0
/// 082a66c8  ldr     r0,[r0]
/// 082a66cc  ldr     r1,[r0,#0xc]
/// 082a66d0  mov     r0,r4
/// 082a66d4  blx     r1
/// 082a66d8  cmp     r0,#0
/// 082a66dc  ldrne   r0,[r4,#4]
/// 082a66e0  ldrbne  r0,[r0,#0x1ac]
/// 082a66e4  andne   r0,r0,#1
/// 082a66e8  moveq   r0,#0
/// 082a66ec  pop     {r4,pc}
/// ```
///
/// Calls vtable slot 3 with `reference`. A zero result short-circuits to zero
/// without reading the target. Any nonzero result reads target byte +0x1ac
/// and returns only its least-significant bit. The flag's semantic meaning is
/// unestablished, so the export names its verified storage and bit.
///
/// Deliberate host deviation: test vtables store the resolve slot as a native
/// function pointer (8 bytes on this host, 4 on ARM); reference and target
/// pointers remain 32-bit firmware words. The static descriptor's slot value
/// is selector/implementation data rather than a function entry, so this port
/// deliberately preserves the raw load-and-`blx` without naming a callee.
///
/// # Safety
///
/// `reference` must be readable through +0x04 and its vtable through +0x0c.
/// When resolve succeeds, its 32-bit target pointer must be readable through
/// +0x1ac. Like retailOS, neither pointer has a NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reference_target_flag_bit_0(
    reference: *const u8,
) -> u32 {
    let vtable = reference.cast::<u32>().read() as usize as *const u8;
    let resolve: ResolveSlot = vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().read();
    if resolve(reference) == 0 {
        return 0;
    }
    let target = reference.add(TARGET_OFFSET).cast::<u32>().read() as usize as *const u8;
    target.add(TARGET_FLAG_OFFSET).read() as u32 & 1
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

    unsafe extern "C" fn resolve_stub(reference: *const u8) -> u32 {
        RESOLVE_REFERENCE = reference;
        RESOLVE_CALLS += 1;
        RESOLVE_RESULT
    }

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ELEMENT_REFERENCE_TARGET_FLAG_BIT_0,
                0x1000,
            ).map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    unsafe fn prepare(resolve_result: u32, flag: u8) -> (*mut u8, *mut u8) {
        let slab = try_slab().unwrap();
        let reference = slab;
        let vtable = slab.add(0x100);
        let target = slab.add(0x400);
        RESOLVE_RESULT = resolve_result;
        RESOLVE_REFERENCE = ptr::null();
        RESOLVE_CALLS = 0;
        write_word(reference, 0, vtable as u32);
        write_word(reference, TARGET_OFFSET, target as u32);
        vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().write(resolve_stub);
        target.add(TARGET_FLAG_OFFSET).write(flag);
        (reference, target)
    }

    #[test]
    fn failed_resolve_does_not_read_target() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_target_flag_bit_0");
            return;
        }
        unsafe {
            let (reference, _) = prepare(0, 0xff);
            write_word(reference, TARGET_OFFSET, 1);
            assert_eq!(ui_element_reference_target_flag_bit_0(reference), 0);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(RESOLVE_REFERENCE, reference);
        }
    }

    #[test]
    fn resolved_returns_only_target_bit_zero() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_target_flag_bit_0");
            return;
        }
        unsafe {
            let (reference, _) = prepare(0xffff_ffff, 0xfe);
            assert_eq!(ui_element_reference_target_flag_bit_0(reference), 0);
            let (reference, _) = prepare(1, 0xfd);
            assert_eq!(ui_element_reference_target_flag_bit_0(reference), 1);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(RESOLVE_REFERENCE, reference);
        }
    }
}
