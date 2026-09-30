//! Resolve-gated bit-6 reader on a UI element reference target.
//!
//! Original: `FUN_082a6738` @ 0x082a6738 (52 bytes; two unconditional
//! direct `bl` callers, zero predicated callers; one indirect `blx` in body).

const VTABLE_RESOLVE_OFFSET: usize = 0x0c;
const TARGET_OFFSET: usize = 0x04;
const TARGET_FLAG_OFFSET: usize = 0x18c;

type ResolveSlot = unsafe extern "C" fn(*const u8) -> u32;

/// ui_element_reference_target_flag_bit_6 — original: `FUN_082a6738` @
/// 0x082a6738 (52 bytes, ending at 0x082a676c). The next real function
/// begins there with `add r0,r0,#0x34; b 0x083d68dc`. Decoding the raw
/// firmware's ARM branch words finds two plain BL callers at 0x081749d0
/// and 0x08239a5c, and no predicated BL callers. The body calls one
/// indirect BLX through vtable slot 3 (+0x0c).
///
/// Calls the resolve slot with the reference. Zero returns zero without
/// reading the target; any nonzero result loads the target pointer at +4,
/// reads its byte at +0x18c, and returns `(byte & 0x40) >> 6`. The flag's
/// meaning remains unestablished, so the name records its location and bit.
/// No named callee seam: the runtime vtable target is unresolved, matching
/// the existing sibling readers' raw dispatch convention.
///
/// Deliberate host deviation: the resolve slot stores a native-width
/// function pointer; reference links remain firmware-width u32 words.
/// Target behavior has no deliberate deviations.
///
/// # Safety
/// `reference` must be readable through +4, its vtable slot at +0x0c must
/// contain a callable resolve method, and on success its updated target
/// must be readable through +0x18c. Neither pointer has a NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reference_target_flag_bit_6(
    reference: *const u8,
) -> u32 {
    let vtable = reference.cast::<u32>().read() as usize as *const u8;
    let resolve: ResolveSlot = vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().read();
    if resolve(reference) == 0 {
        return 0;
    }
    let target = reference.add(TARGET_OFFSET).cast::<u32>().read() as usize as *const u8;
    (target.add(TARGET_FLAG_OFFSET).read() as u32 & 0x40) >> 6
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{LazyLock, Mutex};

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOLVE_RESULT: u32 = 0;
    static mut REPLACEMENT_TARGET: u32 = 0;

    unsafe extern "C" fn resolve_stub(reference: *const u8) -> u32 {
        if REPLACEMENT_TARGET != 0 {
            (reference as *mut u8).add(TARGET_OFFSET).cast::<u32>().write(REPLACEMENT_TARGET);
        }
        RESOLVE_RESULT
    }

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ELEMENT_REFERENCE_TARGET_FLAG_BIT_6,
                0x1000,
            ).map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    #[test]
    fn resolve_gates_target_and_extracts_only_bit_six() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(reference) = try_slab() else {
            crate::testing::note_missing_u32_fixture("ui::element_reference_target_flag_bit_6");
            return;
        };
        unsafe {
            let vtable = reference.add(0x100);
            let target = reference.add(0x400);
            reference.cast::<u32>().write(vtable as u32);
            vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().write(resolve_stub);
            REPLACEMENT_TARGET = 0;
            RESOLVE_RESULT = 0;
            // An unreadable target proves failed resolve short-circuits.
            reference.add(TARGET_OFFSET).cast::<u32>().write(1);
            assert_eq!(ui_element_reference_target_flag_bit_6(reference), 0);
            reference.add(TARGET_OFFSET).cast::<u32>().write(target as u32);
            for result in [1, 0x8000_0000, u32::MAX] {
                RESOLVE_RESULT = result;
                for flag in 0..=255u32 {
                    target.add(TARGET_FLAG_OFFSET).write(flag as u8);
                    assert_eq!(ui_element_reference_target_flag_bit_6(reference), (flag >> 6) & 1);
                }
            }
            // Resolve may replace the target; loading it before dispatch is wrong.
            let replacement = reference.add(0x800);
            target.add(TARGET_FLAG_OFFSET).write(0);
            replacement.add(TARGET_FLAG_OFFSET).write(0x40);
            REPLACEMENT_TARGET = replacement as u32;
            assert_eq!(ui_element_reference_target_flag_bit_6(reference), 1);
            REPLACEMENT_TARGET = 0;
        }
    }
}
