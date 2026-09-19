//! `choice_state_prune_duplicate_tail` — original: `FUN_080d7610` @
//! `0x080d7610`.
//!
//! Load address: `0x080d7610`; true size: 152 bytes (`0x98`), from its
//! `push {r4,lr}` through `pop {r4,pc}` at `0x080d76a4`. The next real
//! function starts with `push {r4-r9,sl,lr}` at `0x080d76a8`. Raw ARM decoding
//! verifies zero plain and zero predicated `bl` instructions in the body; a
//! complete-image scan finds four inbound plain `bl` calls (0x080e00b0,
//! 0x080e00e8, 0x080e011c, 0x080e0d3c) and no predicated forms.
//!
//! The owner holds a target-width pointer at +0x14 to a choice state. When the
//! state has at least two entries, identical final and predecessor-selected
//! `(u32, u32)` pairs with a final marker byte of one collapse the final entry.
//! If the state has frames, its final predecessor index is then set to the new
//! final entry. Deliberate deviation: none.

const OWNER_CHOICE_STATE: usize = 0x14;
const STATE_FRAME_COUNT: usize = 0;
const STATE_ENTRY_COUNT: usize = 2;
const STATE_PAIRS: usize = 4;
const STATE_FINAL_MARKERS: usize = 8;
const STATE_PREDECESSOR_INDICES: usize = 12;

/// Collapses a duplicate terminal choice entry and refreshes the active frame's
/// predecessor index.
///
/// # Safety
/// `owner` must contain a valid target-width choice-state pointer at +0x14, or
/// a null pointer. A non-null state must expose the raw layout through +0x0f;
/// its pair, marker, and predecessor buffers must be valid for every index the
/// state fields select. The original performs no bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn choice_state_prune_duplicate_tail(owner: *mut u8) {
    let state = (owner.add(OWNER_CHOICE_STATE) as *const u32).read_volatile() as usize as *mut u8;
    if state.is_null() {
        return;
    }

    let entry_count = (state.add(STATE_ENTRY_COUNT) as *const i16).read_volatile();
    if entry_count > 1 {
        let pairs = (state.add(STATE_PAIRS) as *const u32).read_volatile() as usize as *const u32;
        let final_markers = (state.add(STATE_FINAL_MARKERS) as *const u32).read_volatile() as usize as *const u8;
        let predecessor_indices = (state.add(STATE_PREDECESSOR_INDICES) as *const u32).read_volatile() as usize as *mut u16;
        let frame_count = (state.add(STATE_FRAME_COUNT) as *const i16).read_volatile();
        let selected_entry = if frame_count > 1 {
            i32::from((predecessor_indices.offset(isize::from(frame_count) - 2) as *const i16).read_volatile()) + 1
        } else {
            0
        };
        let final_entry = i32::from(entry_count) - 1;
        let selected_pair = pairs.offset(selected_entry as isize * 2);
        let final_pair = pairs.offset(final_entry as isize * 2);

        if selected_pair.read_volatile() == final_pair.read_volatile()
            && selected_pair.add(1).read_volatile() == final_pair.add(1).read_volatile()
            && final_markers.offset(final_entry as isize).read_volatile() == 1
        {
            (state.add(STATE_ENTRY_COUNT) as *mut i16).write_volatile(entry_count - 1);
        }
    }

    let frame_count = (state.add(STATE_FRAME_COUNT) as *const i16).read_volatile();
    if frame_count > 0 {
        let entry_count = (state.add(STATE_ENTRY_COUNT) as *const i16).read_volatile();
        let predecessor_indices = (state.add(STATE_PREDECESSOR_INDICES) as *const u32).read_volatile() as usize as *mut u16;
        predecessor_indices.offset(isize::from(frame_count) - 1).write_volatile((entry_count - 1) as u16);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CHOICE_STATE_PRUNE_DUPLICATE_TAIL, 0x1000).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<(*mut u8, *mut u8, *mut u32, *mut u8, *mut u16)> {
        let base = (*FIXTURE)? as *mut u8;
        base.write_bytes(0, 0x1000);
        let owner = base;
        let state = base.add(0x100);
        let pairs = base.add(0x200) as *mut u32;
        let markers = base.add(0x300);
        let predecessors = base.add(0x400) as *mut u16;
        (owner.add(OWNER_CHOICE_STATE) as *mut u32).write(state as usize as u32);
        (state.add(STATE_PAIRS) as *mut u32).write(pairs as usize as u32);
        (state.add(STATE_FINAL_MARKERS) as *mut u32).write(markers as usize as u32);
        (state.add(STATE_PREDECESSOR_INDICES) as *mut u32).write(predecessors as usize as u32);
        Some((owner, state, pairs, markers, predecessors))
    }

    #[test]
    fn duplicate_marked_tail_is_collapsed_and_last_frame_is_retargeted() {
        let _guard = FIXTURE_LOCK.lock();
        let Some((owner, state, pairs, markers, predecessors)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            (state.add(STATE_FRAME_COUNT) as *mut i16).write(2);
            (state.add(STATE_ENTRY_COUNT) as *mut i16).write(3);
            pairs.add(2).write(0x1111_2222); pairs.add(3).write(0x3333_4444);
            pairs.add(4).write(0x1111_2222); pairs.add(5).write(0x3333_4444);
            markers.add(2).write(1);
            predecessors.write(0); predecessors.add(1).write(1);
            choice_state_prune_duplicate_tail(owner);
            assert_eq!((state.add(STATE_ENTRY_COUNT) as *const i16).read(), 2);
            assert_eq!(predecessors.read(), 0);
            assert_eq!(predecessors.add(1).read(), 1);
        }
    }

    #[test]
    fn unmarked_or_different_tail_is_kept_but_frame_still_tracks_it() {
        let _guard = FIXTURE_LOCK.lock();
        let Some((owner, state, pairs, markers, predecessors)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            (state.add(STATE_FRAME_COUNT) as *mut i16).write(1);
            (state.add(STATE_ENTRY_COUNT) as *mut i16).write(2);
            pairs.write(1); pairs.add(1).write(2);
            pairs.add(2).write(1); pairs.add(3).write(2);
            markers.add(1).write(0);
            choice_state_prune_duplicate_tail(owner);
            assert_eq!((state.add(STATE_ENTRY_COUNT) as *const i16).read(), 2);
            assert_eq!(predecessors.read(), 1);
            markers.add(1).write(1);
            pairs.add(3).write(3);
            choice_state_prune_duplicate_tail(owner);
            assert_eq!((state.add(STATE_ENTRY_COUNT) as *const i16).read(), 2);
            assert_eq!(predecessors.read(), 1);
        }
    }

    #[test]
    fn null_state_and_empty_frame_count_do_not_access_state_buffers() {
        let _guard = FIXTURE_LOCK.lock();
        let Some((owner, state, pairs, markers, predecessors)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            (owner.add(OWNER_CHOICE_STATE) as *mut u32).write(0);
            choice_state_prune_duplicate_tail(owner);
            (owner.add(OWNER_CHOICE_STATE) as *mut u32).write(state as usize as u32);
            (state.add(STATE_FRAME_COUNT) as *mut i16).write(0);
            (state.add(STATE_ENTRY_COUNT) as *mut i16).write(1);
            pairs.write(0xdead_beef); markers.write(0xaa); predecessors.write(0xbeef);
            choice_state_prune_duplicate_tail(owner);
            assert_eq!((state.add(STATE_ENTRY_COUNT) as *const i16).read(), 1);
            assert_eq!(predecessors.read(), 0xbeef);
        }
    }
}
