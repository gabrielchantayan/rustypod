//! Resolve-gated zero predicate on a UI element reference target.
//!
//! Original: `FUN_082a5e0c` @ 0x082a5e0c, exactly 60 bytes ending at
//! 0x082a5e48 (the next function's push {r4,lr}). Raw ARM branch decoding
//! finds two plain BL callers, 0x0813e1f4 and 0x0813e258, no predicated BL;
//! the body contains one indirect BLX through vtable slot 3 (+0x0c).
//!
//! Resolve the reference; zero returns zero without loading its target.
//! Any nonzero result loads the updated target at +4 and returns one iff
//! its entire u32 word at +0x10 is zero. The callers filter two enumerations
//! by this predicate; the target word's semantic meaning is unestablished.
//! No invented callee seam: dispatch follows the runtime vtable directly.
//! Target behavior has no deliberate deviations. Host fixtures use a native
//! function pointer at vtable+0x0c; reference links stay firmware-width u32.

const VTABLE_RESOLVE_OFFSET: usize = 0x0c;
const TARGET_OFFSET: usize = 0x04;
const TARGET_WORD_OFFSET: usize = 0x10;
type ResolveSlot = unsafe extern "C" fn(*const u8) -> u32;

/// # Safety
/// `reference` must contain aligned readable u32 vtable and target links.
/// Its vtable must contain a callable resolve slot at +0x0c. On success,
/// the updated target must be aligned and readable through +0x13; there
/// is no NULL guard. Resolve may mutate the reference through an alias.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reference_target_word_10_is_zero(
    reference: *const u8,
) -> u32 {
    let vtable = reference.cast::<u32>().read() as usize as *const u8;
    let resolve: ResolveSlot = vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().read();
    if resolve(reference) == 0 {
        return 0;
    }
    let target = reference.add(TARGET_OFFSET).cast::<u32>().read() as usize as *const u8;
    (target.add(TARGET_WORD_OFFSET).cast::<u32>().read() == 0) as u32
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

    #[test]
    fn resolution_gates_full_word_comparison_and_can_replace_target() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ELEMENT_REFERENCE_TARGET_WORD_10_IS_ZERO,
                0x1000,
            ).map(|p| p as usize)
        });
        let Some(base) = *SLAB else {
            crate::testing::note_missing_u32_fixture("ui::element_reference_target_word_10_is_zero");
            return;
        };
        unsafe {
            let reference = base as *mut u8;
            let vtable = reference.add(0x104);
            let target = reference.add(0x400);
            let replacement = reference.add(0x800);
            reference.cast::<u32>().write(vtable as u32);
            vtable.add(VTABLE_RESOLVE_OFFSET).cast::<ResolveSlot>().write(resolve_stub);
            REPLACEMENT_TARGET = 0;
            RESOLVE_RESULT = 0;
            reference.add(TARGET_OFFSET).cast::<u32>().write(1);
            assert_eq!(ui_element_reference_target_word_10_is_zero(reference), 0);
            reference.add(TARGET_OFFSET).cast::<u32>().write(target as u32);
            for result in [1, 0x8000_0000, u32::MAX] {
                RESOLVE_RESULT = result;
                for word in [0, 1, 0x100, 0x10000, 0x8000_0000, u32::MAX] {
                    target.add(TARGET_WORD_OFFSET).cast::<u32>().write(word);
                    assert_eq!(ui_element_reference_target_word_10_is_zero(reference), (word == 0) as u32);
                }
            }
            target.add(TARGET_WORD_OFFSET).cast::<u32>().write(1);
            replacement.add(TARGET_WORD_OFFSET).cast::<u32>().write(0);
            REPLACEMENT_TARGET = replacement as u32;
            assert_eq!(ui_element_reference_target_word_10_is_zero(reference), 1);
            REPLACEMENT_TARGET = 0;
        }
    }
}
