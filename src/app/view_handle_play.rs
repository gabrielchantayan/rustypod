//! Handle a view's `HandlePlay` event — FUN_0810c664 @ 0x0810c664.
//! True extent: 32 bytes, [0x0810c664, 0x0810c684); the next function
//! begins with PUSH at 0x0810c684. Full-image aligned A32 scan: zero plain
//! inbound BLs, two BLNEs (0x08156fc0, 0x0819a4f0), zero outbound BLs
//! (plain or predicated), and one conditional tail BX through virtual +0x13c.
//!
//! Read associated state +0x8e0 through the pointer at view +0x13c.
//! Zero returns one without reading the vtable. Any nonzero byte dispatches
//! the existing play/pause virtual slot with the original view and event,
//! returning its full result. HandlePlay is established by both callers;
//! the concrete virtual target and deeper state-byte meaning are unresolved.
//!
//! Deliberate deviations: reuse the pause handler's repr(C) object layout;
//! native pointers and vtable entries widen on hosts, preserving ARM offsets
//! on target. Rust expresses the tail BX as a final call. The result in r0
//! is preserved even though both known callers ignore it.

use super::view_handle_pause::PauseView;

/// # Safety
/// `view` and its associated state must be readable using their ARM layout
/// (native repr(C) layout on hosts). When the state byte is nonzero, the
/// vtable's +0x13c method must accept this view and the unchanged event.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_handle_play(view: *mut PauseView, event: u32) -> u32 {
    let state = core::ptr::addr_of!((*view).state).read();
    if core::ptr::addr_of!((*state).pause_gate).read() == 0 {
        return 1;
    }
    let vtable = core::ptr::addr_of!((*view).vtable).read();
    ((*vtable).handle_play_pause)(view, event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::view_handle_pause::{PauseViewState, PauseViewVtable};

    #[test]
    fn zero_state_returns_one_without_accessing_null_vtable() {
        let state = PauseViewState { reserved: [0xa5; 0x8e0], pause_gate: 0 };
        let mut view = PauseView {
            vtable: core::ptr::null(),
            reserved_004_138: [0x12345678; (0x13c - 4) / 4],
            state: &state,
        };
        for event in [0, 1, 0x80000000, u32::MAX] {
            assert_eq!(unsafe { view_handle_play(&mut view, event) }, 1);
            assert_eq!(view.reserved_004_138, [0x12345678; (0x13c - 4) / 4]);
            assert_eq!(state.pause_gate, 0);
            assert_eq!(state.reserved, [0xa5; 0x8e0]);
        }
    }

    unsafe extern "C" fn apply_play_pause(view: *mut PauseView, event: u32) -> u32 {
        (*view).reserved_004_138[0] = event;
        (*view).reserved_004_138[1] += 1;
        event ^ 0x80000000
    }

    #[test]
    fn every_nonzero_state_dispatches_with_full_event_and_result() {
        let mut state = PauseViewState { reserved: [0x5a; 0x8e0], pause_gate: 0 };
        let vtable = PauseViewVtable { reserved: [0; 0x13c / 4], handle_play_pause: apply_play_pause };
        let mut view = PauseView {
            vtable: &vtable,
            reserved_004_138: [0; (0x13c - 4) / 4],
            state: &state,
        };
        let mut calls = 0;
        for gate in 1..=u8::MAX {
            state.pause_gate = gate;
            for event in [0, 1, 0x80000000, u32::MAX] {
                assert_eq!(unsafe { view_handle_play(&mut view, event) }, event ^ 0x80000000);
                calls += 1;
                assert_eq!(view.reserved_004_138[0], event);
                assert_eq!(view.reserved_004_138[1], calls);
                assert_eq!(state.pause_gate, gate);
                assert_eq!(state.reserved, [0x5a; 0x8e0]);
            }
        }
    }
}
