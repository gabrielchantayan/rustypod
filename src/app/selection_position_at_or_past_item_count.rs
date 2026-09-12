//! Selection-position bound predicate.
//!
//! `selection_position_is_at_or_past_item_count` — original: `FUN_0816eefc` @
//! `0x0816eefc` (52 bytes, exact: the next separately linked function begins
//! at `0x0816ef30`; **8 direct `bl` call sites**, all plain unconditional
//! `bl`, verified by decoding every ARM B/BL word in `osos.dec`).
//!
//! Raw ARM reads the gate byte at state+0x10. When it is zero, it returns zero
//! without touching state+0x14. Otherwise it calls
//! [`crate::ui::element_reference_item_count::ui_element_reference_target_item_count`]
//! on the embedded reference at +0x14 and returns one precisely when that
//! zero-extended item count is less than or equal to the u32 position at +0x0c.
//! The eight direct callers all invoke the predicate unconditionally; no
//! predicated `bl` form supplies an external NULL guard.
//!
//! Deliberate deviation: the partially identified state is a `#[repr(C)]`
//! target-word layout, rather than a guessed complete class. This preserves the
//! observed byte and embedded-reference offsets on both the 32-bit target and
//! 64-bit host. The direct ARM `bl` is a typed call to the already ported
//! item-count reader.

use crate::ui::element_reference_item_count::ui_element_reference_target_item_count;

/// The observed prefix of the state accepted by
/// [`selection_position_is_at_or_past_item_count`].
#[repr(C)]
struct SelectionPositionCheck {
    _words_before_position: [u32; 3],
    selection_position: u32,
    item_count_check_enabled: u8,
    _padding_before_item_reference: [u8; 3],
    item_reference: [u32; 2],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::size_of::<SelectionPositionCheck>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(SelectionPositionCheck, selection_position)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(SelectionPositionCheck, item_count_check_enabled)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(SelectionPositionCheck, item_reference)];

/// selection_position_is_at_or_past_item_count — original: `FUN_0816eefc` @
/// `0x0816eefc` (52 bytes; 8 direct unconditional `bl` call sites, no
/// predicated forms).
///
/// Returns zero when `state`'s item-count check gate is zero. Otherwise,
/// returns whether the state's selection position is at or past its embedded
/// element reference's current item count. Equality is deliberately included:
/// ARM uses unsigned `cmp` followed by `movcs`.
///
/// # Safety
///
/// `state` must be non-NULL, aligned for [`SelectionPositionCheck`], and
/// readable through its embedded reference at +0x14. When its gate byte is
/// nonzero, that reference must meet the safety requirements of
/// [`ui_element_reference_target_item_count`]. The ARM body has no NULL or
/// bounds guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_position_is_at_or_past_item_count(state: *const u8) -> u32 {
    let state = state.cast::<SelectionPositionCheck>();
    if (*state).item_count_check_enabled == 0 {
        return 0;
    }

    let item_count = ui_element_reference_target_item_count(
        core::ptr::addr_of!((*state).item_reference).cast(),
    );
    u32::from(item_count >= (*state).selection_position)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const VTABLE_RESOLVE_OFFSET: usize = 0x0c;
    const TARGET_OFFSET: usize = 0x04;
    const TARGET_COLLECTION_OFFSET: usize = 0x40;
    const COLLECTION_ITEM_COUNT_OFFSET: usize = 0x2e;

    type ResolveSlot = unsafe extern "C" fn(*const u8) -> u32;

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOLVE_RESULT: u32 = 0;
    static mut RESOLVE_CALLS: u32 = 0;

    unsafe extern "C" fn resolve_stub(_reference: *const u8) -> u32 {
        RESOLVE_CALLS += 1;
        RESOLVE_RESULT
    }

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::SELECTION_POSITION_AT_OR_PAST_ITEM_COUNT,
                0x2000,
            )
            .map(|pointer| pointer as usize)
        });
        SLAB.map(|pointer| pointer as *mut u8)
    }

    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    unsafe fn vtable() -> *mut u8 {
        slab().add(0x100)
    }

    unsafe fn target() -> *mut u8 {
        slab().add(0x400)
    }

    unsafe fn collection() -> *mut u8 {
        slab().add(0x800)
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    unsafe fn prepare(
        state: &mut SelectionPositionCheck,
        enabled: u8,
        position: u32,
        resolve_result: u32,
        item_count: u16,
    ) {
        state.selection_position = position;
        state.item_count_check_enabled = enabled;
        RESOLVE_RESULT = resolve_result;
        RESOLVE_CALLS = 0;

        let reference = ptr::addr_of_mut!(state.item_reference).cast::<u8>();
        write_word(reference, 0, vtable() as u32);
        write_word(reference, TARGET_OFFSET, target() as u32);
        vtable()
            .add(VTABLE_RESOLVE_OFFSET)
            .cast::<ResolveSlot>()
            .write_unaligned(resolve_stub);
        write_word(target(), TARGET_COLLECTION_OFFSET, collection() as u32);
        collection()
            .add(COLLECTION_ITEM_COUNT_OFFSET)
            .cast::<u16>()
            .write(item_count);
    }

    fn empty_state() -> SelectionPositionCheck {
        SelectionPositionCheck {
            _words_before_position: [0; 3],
            selection_position: 0,
            item_count_check_enabled: 0,
            _padding_before_item_reference: [0; 3],
            item_reference: [0; 2],
        }
    }

    #[test]
    fn disabled_gate_does_not_touch_embedded_reference() {
        let mut state = empty_state();
        state.selection_position = u32::MAX;
        state.item_reference = [1, 1];

        assert_eq!(unsafe { selection_position_is_at_or_past_item_count(ptr::addr_of!(state).cast()) }, 0);
    }

    #[test]
    fn enabled_gate_uses_unsigned_inclusive_item_count_bound() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("app::selection_position_at_or_past_item_count");
            return;
        }

        let mut state = empty_state();
        for (position, item_count, expected) in [
            (0, 0, 1),
            (u16::MAX as u32, u16::MAX, 1),
            (u16::MAX as u32 + 1, u16::MAX, 0),
            (u32::MAX, 0, 0),
        ] {
            unsafe {
                prepare(&mut state, 1, position, 1, item_count);
                assert_eq!(selection_position_is_at_or_past_item_count(ptr::addr_of!(state).cast()), expected);
                assert_eq!(RESOLVE_CALLS, 1);
            }
        }
    }

    #[test]
    fn every_nonzero_gate_byte_enables_count_comparison() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("app::selection_position_at_or_past_item_count");
            return;
        }

        let mut state = empty_state();
        for gate in [1, 0x80, u8::MAX] {
            unsafe {
                prepare(&mut state, gate, 4, u32::MAX, 4);
                assert_eq!(selection_position_is_at_or_past_item_count(ptr::addr_of!(state).cast()), 1);
                assert_eq!(RESOLVE_CALLS, 1);
            }
        }
    }

    #[test]
    fn unresolved_reference_count_is_compared_as_zero() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("app::selection_position_at_or_past_item_count");
            return;
        }

        let mut state = empty_state();
        unsafe {
            prepare(&mut state, 1, 0, 0, u16::MAX);
            assert_eq!(selection_position_is_at_or_past_item_count(ptr::addr_of!(state).cast()), 1);
            assert_eq!(RESOLVE_CALLS, 1);

            state.selection_position = 1;
            assert_eq!(selection_position_is_at_or_past_item_count(ptr::addr_of!(state).cast()), 0);
            assert_eq!(RESOLVE_CALLS, 2);
        }
    }
}
