//! Refreshes a selection state's materialized count and emits its context-sensitive notification.
//!
//! `selection_state_refresh_if_count_changed` — original: `FUN_08111968` @
//! `0x08111968` (80 bytes, `0x08111968..0x081119b7`). Raw A32 decoding shows
//! the final `bx r3` at `0x081119b4`; `0x081119b8..0x081119c0` is its
//! three-word literal pool and `ldr r0,[r0,#0x430]` at `0x081119c4` begins the
//! next real function. It has two plain direct `bl` instructions (to the
//! materialize-and-count target at `0x080542a0` and
//! `context_index_matches_context_field_f40` at `0x082982e4`), no predicated
//! direct `bl` instructions, three inbound plain `bl` call sites
//! (`0x08109fb4`, `0x0811521c`, and `0x08116d80`), and no predicated inbound
//! forms, all verified from `osos.dec`.
//!
//! It materializes the inner object's result count, compares it with the
//! cached count at `+0xd4`, and returns without a notification if unchanged.
//! Otherwise it updates the cache, tests the one-based context index at
//! `+0x444`, and dispatches vtable slot `+0x58` with action `"VMax"` and kind
//! `0x6381` when the context entry matches, or `0x639a` otherwise. Deliberate
//! deviations: the ARM tail dispatch is an ordinary final Rust call, and the
//! unported materialize-and-count target uses its existing host seam.

#[cfg(target_os = "none")]
use core::mem;

const NOTIFICATION_ACTION: u32 = 0x564d_6178;
const MATCHING_CONTEXT_KIND: u32 = 0x6381;
const DIFFERING_CONTEXT_KIND: u32 = 0x639a;
const NOTIFICATION_SLOT_WORD: usize = 0x58 / 4;

type NotificationDispatch = unsafe extern "C" fn(*mut SelectionState, u32, u32);

/// Target-width selection-state fields read by the retail routine.
#[repr(C)]
pub struct SelectionState {
    vtable: u32,
    _unknown_04_2f: [u8; 0x2c],
    inner: u32,
    _unknown_34_d3: [u8; 0xa0],
    cached_count: u32,
    _unknown_d8_443: [u8; 0x36c],
    context_index: u32,
}


#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn materialize_and_count(inner: *mut u8) -> u32 {
    let target: unsafe extern "C" fn(*mut u8) -> u32 = unsafe { core::mem::transmute(0x0805_42a0usize) };
    unsafe { target(inner) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn materialize_and_count(inner: *mut u8) -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(crate::util::inner_state::INNER_MATERIALIZE_COUNT))(inner) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_notification_dispatch(_: *mut SelectionState, _: u32, _: u32) {
    panic!("install selection-state count-refresh host notification seam")
}

#[cfg(not(target_os = "none"))]
pub static mut SELECTION_STATE_COUNT_REFRESH_DISPATCH: NotificationDispatch = missing_notification_dispatch;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_notification(state: *mut SelectionState, kind: u32) {
    let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*state).vtable)) };
    let address = unsafe { core::ptr::read_volatile((vtable as *const u32).add(NOTIFICATION_SLOT_WORD)) };
    let dispatch: NotificationDispatch = unsafe { mem::transmute(address as usize) };
    unsafe { dispatch(state, NOTIFICATION_ACTION, kind); }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_notification(state: *mut SelectionState, kind: u32) {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(SELECTION_STATE_COUNT_REFRESH_DISPATCH))(
            state,
            NOTIFICATION_ACTION,
            kind,
        );
    }
}

/// # Safety
///
/// `state`, its target-width inner and context pointers, the materialize-count
/// seam, and its vtable notification slot must satisfy retailOS's unchecked
/// contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_state_refresh_if_count_changed(state: *mut SelectionState) {
    unsafe {
        let count = materialize_and_count((*state).inner as usize as *mut u8);
        if (*state).cached_count == count {
            return;
        }
        (*state).cached_count = count;
        let kind = if crate::app::context_index_matches_context_field_f40::context_index_matches_context_field_f40(
            state.cast(),
            (*state).context_index,
        ) != 0 {
            MATCHING_CONTEXT_KIND
        } else {
            DIFFERING_CONTEXT_KIND
        };
        dispatch_notification(state, kind);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    const FIXTURE_LEN: usize = 0x4000;
    const INNER_OFFSET: usize = 0x1000;
    const CONTEXT_OFFSET: usize = 0x2000;
    const TABLE_OFFSET: usize = 0x3000;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut MATERIALIZED_COUNT: u32 = 0;
    static mut DISPATCH: (usize, u32, u32) = (0, 0, 0);
    static mut DISPATCH_COUNT: usize = 0;

    unsafe extern "C" fn materialize_count(_: *mut u8) -> u32 { unsafe { MATERIALIZED_COUNT } }
    unsafe extern "C" fn default_materialize_count(inner: *mut u8) -> u32 {
        unsafe { inner.add(0xef4).cast::<u32>().read() }
    }
    unsafe extern "C" fn record_dispatch(state: *mut SelectionState, action: u32, kind: u32) {
        unsafe {
            DISPATCH = (state as usize, action, kind);
            DISPATCH_COUNT += 1;
        }
    }
    unsafe fn fixture(indexed_word_matches: bool, cached_count: u32) -> Option<*mut SelectionState> {
        let base = try_map_u32_slab(hints::SELECTION_STATE_COUNT_REFRESH, FIXTURE_LEN)?;
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            let state = base.cast::<SelectionState>();
            let inner = base.add(INNER_OFFSET);
            let context = inner;
            let table = base.add(TABLE_OFFSET).cast::<u32>();
            (*state).inner = inner as usize as u32;
            (*state).cached_count = cached_count;
            (*state).context_index = 2;
            context.add(0xf64).cast::<u32>().write(table as usize as u32);
            context.add(0xf40).cast::<u32>().write(0x55aa);
            table.add(3).write(if indexed_word_matches { 0x55aa } else { 0x44bb });
            Some(state)
        }
    }

    #[test]
    fn changed_count_caches_and_dispatches_matching_context_kind() {
        let _lock = TEST_LOCK.lock();
        let Some(state) = (unsafe { fixture(true, 4) }) else { return };
        unsafe {
            MATERIALIZED_COUNT = 7;
            DISPATCH_COUNT = 0;
            crate::util::inner_state::INNER_MATERIALIZE_COUNT = materialize_count;
            SELECTION_STATE_COUNT_REFRESH_DISPATCH = record_dispatch;
            selection_state_refresh_if_count_changed(state);
            crate::util::inner_state::INNER_MATERIALIZE_COUNT = default_materialize_count;
            SELECTION_STATE_COUNT_REFRESH_DISPATCH = missing_notification_dispatch;
            assert_eq!((*state).cached_count, 7);
            assert_eq!(DISPATCH_COUNT, 1);
            assert_eq!(DISPATCH, (state as usize, NOTIFICATION_ACTION, MATCHING_CONTEXT_KIND));
        }
    }

    #[test]
    fn unchanged_count_suppresses_context_test_and_notification() {
        let _lock = TEST_LOCK.lock();
        let Some(state) = (unsafe { fixture(false, 7) }) else { return };
        unsafe {
            MATERIALIZED_COUNT = 7;
            DISPATCH_COUNT = 0;
            crate::util::inner_state::INNER_MATERIALIZE_COUNT = materialize_count;
            SELECTION_STATE_COUNT_REFRESH_DISPATCH = record_dispatch;
            selection_state_refresh_if_count_changed(state);
            crate::util::inner_state::INNER_MATERIALIZE_COUNT = default_materialize_count;
            SELECTION_STATE_COUNT_REFRESH_DISPATCH = missing_notification_dispatch;
            assert_eq!(DISPATCH_COUNT, 0);
        }
    }

    #[test]
    fn changed_count_dispatches_differing_context_kind() {
        let _lock = TEST_LOCK.lock();
        let Some(state) = (unsafe { fixture(false, 1) }) else { return };
        unsafe {
            MATERIALIZED_COUNT = 2;
            DISPATCH_COUNT = 0;
            crate::util::inner_state::INNER_MATERIALIZE_COUNT = materialize_count;
            SELECTION_STATE_COUNT_REFRESH_DISPATCH = record_dispatch;
            selection_state_refresh_if_count_changed(state);
            crate::util::inner_state::INNER_MATERIALIZE_COUNT = default_materialize_count;
            SELECTION_STATE_COUNT_REFRESH_DISPATCH = missing_notification_dispatch;
            assert_eq!(DISPATCH_COUNT, 1);
            assert_eq!(DISPATCH.2, DIFFERING_CONTEXT_KIND);
        }
    }
}
