//! `layout_apply_pending_offsets` — original: `FUN_0804c5c8` @
//! **0x0804c5c8**. The raw `osos.dec` body is exactly **112 bytes**: it
//! opens with `cmp r0, #0` at 0x0804c5c8, tail-branches at 0x0804c634, and
//! the distinct sibling `FUN_0804c638` starts with `push {r1-r11,lr}`.
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds **7 direct `bl`
//! call sites**: six unconditional and one `bleq` at 0x080afa94. The routine
//! itself has no `bl`; its final `b 0x0804c94c` is a tail branch.
//!
//! # Algorithm
//!
//! When the layout state is non-null, add its pending offset increment
//! (`+0x36`) to the current offset (`+0x16`), add its pending entry count
//! (`+0x34`) to the logical entry count (`+0x14`), and add its pending record
//! count (`+0x4c`) to the record cursor (`+0x2c`). Each existing entry offset
//! in the `+0x40` u16 array is increased by the former current offset. It
//! then tail-calls `FUN_0804c94c`, which clears the pending fields, refreshes
//! dependent state, and derives the record pointer. The six unconditional
//! callers use live layout states; the sole predicated caller invokes this
//! only when its preceding condition is equal, while the callee still has its
//! own null guard.
//!
//! # Deliberate deviations
//!
//! `FUN_0804c94c` is absent from `names.yaml`. This port preserves its tail
//! transfer via a volatile seam: target builds call the verified retail
//! address, while host tests install a recorder. The state identity is not
//! inferred beyond the fields established by the raw ARM body.

#[cfg(test)]
extern crate std;

/// The verified retail target of the final `b` at 0x0804c634.
#[cfg(target_os = "none")]
const LAYOUT_FINALIZE_PENDING_ADDRESS: usize = 0x0804_c94c;

/// Partial target-width layout state used by `FUN_0804c5c8`.
///
/// The `u32` entry-offset pointer intentionally remains a target-width word;
/// host fixtures map that storage below 4 GiB before placing it here.
#[repr(C)]
pub struct TextLayoutPendingState {
    _prefix: [u32; 5],
    pub logical_entry_count: u16,
    pub current_offset: i16,
    _between_counts_and_cursor: [u32; 5],
    pub record_cursor: u32,
    _record_base: u32,
    pub pending_entry_count: i16,
    pub pending_offset_increment: u16,
    _before_entry_offsets: [u32; 2],
    pub entry_offsets: u32,
    _between_entry_offsets_and_pending_records: [u32; 2],
    pub pending_record_count: u32,
    _record_pointer: u32,
}

/// ABI of the unported tail target `FUN_0804c94c`.
pub type LayoutFinalizePending = unsafe extern "C" fn(*mut TextLayoutPendingState);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_layout_finalize_pending(state: *mut TextLayoutPendingState) {
    let finalize: LayoutFinalizePending =
        unsafe { core::mem::transmute(LAYOUT_FINALIZE_PENDING_ADDRESS) };
    unsafe { finalize(state) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_layout_finalize_pending(_state: *mut TextLayoutPendingState) {}

/// The unported tail target. A volatile load prevents LLVM from folding the
/// device default into this port and lets host tests replace it.
#[cfg(target_os = "none")]
pub static mut LAYOUT_FINALIZE_PENDING: LayoutFinalizePending = firmware_layout_finalize_pending;
#[cfg(not(target_os = "none"))]
pub static mut LAYOUT_FINALIZE_PENDING: LayoutFinalizePending = missing_layout_finalize_pending;

/// Applies the layout state's queued offset and record-count changes.
///
/// # Safety
///
/// When non-null, `state` must be writable and its `entry_offsets` target
/// must hold at least `pending_entry_count` writable, aligned u16 values.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layout_apply_pending_offsets(state: *mut TextLayoutPendingState) {
    if state.is_null() {
        return;
    }

    let previous_offset = unsafe { (*state).current_offset };
    let pending_entries = unsafe { (*state).pending_entry_count as i32 as u32 };
    unsafe {
        (*state).current_offset = previous_offset.wrapping_add((*state).pending_offset_increment as i16);
        (*state).logical_entry_count = (*state)
            .logical_entry_count
            .wrapping_add((*state).pending_entry_count as u16);
        (*state).record_cursor = (*state)
            .record_cursor
            .wrapping_add((*state).pending_record_count);
    }

    let entry_offsets = unsafe { (*state).entry_offsets as usize as *mut u16 };
    for entry_index in 0..pending_entries {
        let entry = unsafe { entry_offsets.add(entry_index as usize) };
        unsafe { *entry = (*entry).wrapping_add(previous_offset as u16) };
    }

    let finalize = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(LAYOUT_FINALIZE_PENDING))
    };
    unsafe { finalize(state) };
}

#[cfg(test)]
pub static LAYOUT_FINALIZE_PENDING_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static FINALIZE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FINALIZED_STATE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_finalize(state: *mut TextLayoutPendingState) {
        FINALIZED_STATE.store(state as usize, Ordering::SeqCst);
        FINALIZE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    struct FinalizeGuard(LayoutFinalizePending);

    impl Drop for FinalizeGuard {
        fn drop(&mut self) {
            unsafe { LAYOUT_FINALIZE_PENDING = self.0 };
        }
    }

    fn install_recorder() -> FinalizeGuard {
        let previous = unsafe { LAYOUT_FINALIZE_PENDING };
        unsafe { LAYOUT_FINALIZE_PENDING = record_finalize };
        FinalizeGuard(previous)
    }

    #[test]
    fn applies_pending_changes_and_offsets_before_finalizing() {
        let _guard = LAYOUT_FINALIZE_PENDING_TEST_LOCK.lock();
        let _restore = install_recorder();
        let Some(entries) = try_map_u32_slab(hints::TEXT_LAYOUT_APPLY_PENDING_OFFSETS, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let entries = entries.cast::<u16>();
        unsafe {
            *entries.add(0) = 4;
            *entries.add(1) = 17;
            *entries.add(2) = u16::MAX;
        }
        let mut state = TextLayoutPendingState {
            _prefix: [0; 5],
            logical_entry_count: u16::MAX,
            current_offset: -3,
            _between_counts_and_cursor: [0; 5],
            record_cursor: u32::MAX - 1,
            _record_base: 0,
            pending_entry_count: 3,
            pending_offset_increment: 5,
            _before_entry_offsets: [0; 2],
            entry_offsets: entries as usize as u32,
            _between_entry_offsets_and_pending_records: [0; 2],
            pending_record_count: 4,
            _record_pointer: 0,
        };

        FINALIZE_CALLS.store(0, Ordering::SeqCst);
        FINALIZED_STATE.store(0, Ordering::SeqCst);
        unsafe { layout_apply_pending_offsets(&mut state) };

        assert_eq!(state.current_offset, 2);
        assert_eq!(state.logical_entry_count, 2);
        assert_eq!(state.record_cursor, 2);
        assert_eq!(unsafe { *entries.add(0) }, 1);
        assert_eq!(unsafe { *entries.add(1) }, 14);
        assert_eq!(unsafe { *entries.add(2) }, u16::MAX - 3);
        assert_eq!(FINALIZE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FINALIZED_STATE.load(Ordering::SeqCst), &mut state as *mut _ as usize);
    }

    #[test]
    fn null_state_returns_without_finalizing() {
        let _guard = LAYOUT_FINALIZE_PENDING_TEST_LOCK.lock();
        let _restore = install_recorder();
        FINALIZE_CALLS.store(0, Ordering::SeqCst);

        unsafe { layout_apply_pending_offsets(core::ptr::null_mut()) };

        assert_eq!(FINALIZE_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn zero_pending_entries_dereference_no_offset_array() {
        let _guard = LAYOUT_FINALIZE_PENDING_TEST_LOCK.lock();
        let _restore = install_recorder();
        let mut state = TextLayoutPendingState {
            _prefix: [0; 5],
            logical_entry_count: 10,
            current_offset: -1,
            _between_counts_and_cursor: [0; 5],
            record_cursor: 3,
            _record_base: 0,
            pending_entry_count: 0,
            pending_offset_increment: 1,
            _before_entry_offsets: [0; 2],
            entry_offsets: 0,
            _between_entry_offsets_and_pending_records: [0; 2],
            pending_record_count: 0,
            _record_pointer: 0,
        };
        FINALIZE_CALLS.store(0, Ordering::SeqCst);

        unsafe { layout_apply_pending_offsets(&mut state) };

        assert_eq!(state.current_offset, 0);
        assert_eq!(state.logical_entry_count, 10);
        assert_eq!(state.record_cursor, 3);
        assert_eq!(FINALIZE_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn state_layout_matches_retail_offsets() {
        assert_eq!(size_of::<TextLayoutPendingState>(), 0x54);
        assert_eq!(core::mem::offset_of!(TextLayoutPendingState, logical_entry_count), 0x14);
        assert_eq!(core::mem::offset_of!(TextLayoutPendingState, current_offset), 0x16);
        assert_eq!(core::mem::offset_of!(TextLayoutPendingState, record_cursor), 0x2c);
        assert_eq!(core::mem::offset_of!(TextLayoutPendingState, pending_entry_count), 0x34);
        assert_eq!(core::mem::offset_of!(TextLayoutPendingState, pending_offset_increment), 0x36);
        assert_eq!(core::mem::offset_of!(TextLayoutPendingState, entry_offsets), 0x40);
        assert_eq!(core::mem::offset_of!(TextLayoutPendingState, pending_record_count), 0x4c);
    }
}
