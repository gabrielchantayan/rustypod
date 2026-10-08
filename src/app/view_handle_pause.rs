//! Handle a view's `HandlePause` event — FUN_0810c9bc @ 0x0810c9bc.
//! True extent: 32 bytes, [0x0810c9bc, 0x0810c9dc); the next function
//! begins with PUSH at 0x0810c9dc. Raw A32 scan: zero plain inbound BLs,
//! two predicated BLNEs (0x08156fe8, 0x0819a518), zero outbound BLs
//! (plain or predicated), and one conditional tail BX through virtual +0x13c.
//!
//! Read the byte at associated state +0x8e0 (state pointer at view +0x13c).
//! If nonzero, return one without touching the vtable. Otherwise dispatch
//! virtual slot +0x13c with the original view and event, returning its result.
//! Callers identify this as HandlePause; the byte's deeper meaning and the
//! concrete virtual implementation remain unresolved. No invented callee seam.
//!
//! Deliberate deviations: repr(C) pointers and vtable slots widen on hosts;
//! their field order preserves the ARM layout. Rust expresses the tail BX
//! as a final call, retaining r0's result although both callers ignore it.

#[repr(C)]
pub struct PauseViewVtable {
    pub reserved: [usize; 0x13c / 4],
    pub handle_play_pause: unsafe extern "C" fn(*mut PauseView, u32) -> u32,
}

#[repr(C)]
pub struct PauseViewState {
    pub reserved: [u8; 0x8e0],
    pub pause_gate: u8,
}

#[repr(C)]
pub struct PauseView {
    pub vtable: *const PauseViewVtable,
    pub reserved_004_138: [u32; (0x13c - 4) / 4],
    pub state: *const PauseViewState,
}

/// # Safety
/// `view` and its associated state must be readable using their ARM layout
/// (native repr(C) layout on hosts). When pause_gate is zero, the vtable's
/// +0x13c method must be callable with this view and the unchanged event.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_handle_pause(view: *mut PauseView, event: u32) -> u32 {
    let state = core::ptr::addr_of!((*view).state).read();
    if core::ptr::addr_of!((*state).pause_gate).read() != 0 {
        return 1;
    }
    let vtable = core::ptr::addr_of!((*view).vtable).read();
    ((*vtable).handle_play_pause)(view, event)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(state: *const PauseViewState, vtable: *const PauseViewVtable) -> PauseView {
        PauseView { vtable, reserved_004_138: [0x12345678; (0x13c - 4) / 4], state }
    }

    #[test]
    fn every_nonzero_gate_returns_one_without_reading_null_vtable() {
        let mut state = PauseViewState { reserved: [0xa5; 0x8e0], pause_gate: 0 };
        let mut view = fixture(&state, core::ptr::null());
        for gate in 1..=u8::MAX {
            state.pause_gate = gate;
            assert_eq!(unsafe { view_handle_pause(&mut view, u32::MAX) }, 1);
            assert_eq!(state.pause_gate, gate);
            assert_eq!(state.reserved, [0xa5; 0x8e0]);
            assert_eq!(view.reserved_004_138, [0x12345678; (0x13c - 4) / 4]);
        }
    }

    unsafe extern "C" fn dispatch(view: *mut PauseView, event: u32) -> u32 {
        // Consumer-visible state mutation proves dispatch used the original self.
        (*view).reserved_004_138[0] = event;
        (*view).reserved_004_138[1] += 1;
        event ^ 0x80000000
    }

    #[test]
    fn zero_gate_preserves_event_self_and_full_virtual_return() {
        let state = PauseViewState { reserved: [0x5a; 0x8e0], pause_gate: 0 };
        let vtable = PauseViewVtable { reserved: [0; 0x13c / 4], handle_play_pause: dispatch };
        let mut view = fixture(&state, &vtable);
        view.reserved_004_138[1] = 0;
        for (index, event) in [0, 1, 0x80000000, u32::MAX].into_iter().enumerate() {
            assert_eq!(unsafe { view_handle_pause(&mut view, event) }, event ^ 0x80000000);
            assert_eq!(view.reserved_004_138[0], event);
            assert_eq!(view.reserved_004_138[1], index as u32 + 1);
            assert_eq!(state.pause_gate, 0);
            assert_eq!(state.reserved, [0x5a; 0x8e0]);
        }
    }
}
