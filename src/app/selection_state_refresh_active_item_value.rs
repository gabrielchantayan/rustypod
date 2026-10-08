//! Refresh the selection state's cached active-item payload value.
//!
//! Original FUN_081134ec @ 0x081134ec: true extent 156 bytes through
//! 0x08113588 (140 instruction bytes, 16 literal bytes). Raw A32 decoding
//! verifies two plain BL instructions, zero predicated BL; two inbound plain
//! BL sites at 0x08114020/0x08114910, zero predicated inbound BL. Two indirect
//! BLX calls and a final tail BX dispatch through vtable slot +0x58.
//!
//! Configure inner state +0x30 with selectors (1,0), reload that pointer,
//! resolve its active item, and read payload +0x40's unsigned halfword +0x2e.
//! Missing items yield zero. Compare against cache +0xf0; store changes before
//! notifying VMax resources 0x6389, 0x63d0, 0x63d1, reloading the vtable each
//! time. The value's higher-level meaning is not established.
//! Deliberate deviations: use the existing configuration seam and active-item
//! Rust port; host operations supply configuration and virtual dispatch with
//! target-width data pointers. The final tail dispatch is an ordinary call
//! whose result is unobserved.

#[cfg(not(target_os = "none"))]
pub struct ActiveItemValueRefreshOps {
    pub configure: unsafe extern "C" fn(*mut u8, u32, u32),
    pub dispatch: unsafe extern "C" fn(*mut u32, u32, u32),
}

/// # Safety
/// State must be writable through +0xf0 and contain a valid inner object for
/// `ui_backend_active_item`. Nonzero items require a valid payload pointer
/// readable through halfword +0x2e. Target vtable slot +0x58 must be callable;
/// callbacks must leave the state and subsequent vtable valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_state_refresh_active_item_value(
    state: *mut u32,
    #[cfg(not(target_os = "none"))] ops: &ActiveItemValueRefreshOps,
) {
    let inner = state.add(0x30 / 4).read() as usize as *mut u8;
    #[cfg(target_os = "none")]
    super::media_player_reset_default_resource::firmware_configure_inner_state(inner, 1, 0);
    #[cfg(not(target_os = "none"))]
    (ops.configure)(inner, 1, 0);
    let inner = state.add(0x30 / 4).read() as usize as *mut u8;
    let item = crate::ui::backend_active_item::ui_backend_active_item(inner);
    let value = if item.is_null() {
        0
    } else {
        let payload = item.add(0x40).cast::<u32>().read();
        (payload as usize as *const u16).add(0x2e / 2).read() as u32
    };
    if state.add(0xf0 / 4).read() == value {
        return;
    }
    state.add(0xf0 / 4).write(value);
    for resource in [0x6389, 0x63d0, 0x63d1] {
        #[cfg(target_os = "none")]
        {
            let vtable = state.read_volatile() as usize as *const u32;
            let address = vtable.add(0x58 / 4).read_volatile();
            let dispatch: unsafe extern "C" fn(*mut u32, u32, u32) =
                core::mem::transmute(address as usize);
            dispatch(state, 0x564d_6178, resource);
        }
        #[cfg(not(target_os = "none"))]
        (ops.dispatch)(state, 0x564d_6178, resource);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    use parking_lot::Mutex;

    static EVENTS: Mutex<Vec<(u32, u32, u32)>> = Mutex::new(Vec::new());

    unsafe extern "C" fn configure(inner: *mut u8, first: u32, second: u32) {
        assert_eq!((first, second), (1, 0));
        // The old inner is deliberately invalid for lookup. Replace the state
        // pointer to prove the post-configuration reload uses the real backend.
        let state = inner.cast::<u32>().read() as usize as *mut u32;
        let replacement = inner.add(4).cast::<u32>().read();
        state.add(0x30 / 4).write(replacement);
    }

    unsafe extern "C" fn dispatch(state: *mut u32, action: u32, resource: u32) {
        EVENTS.lock().push((state.add(0xf0 / 4).read(), action, resource));
    }

    #[test]
    fn missing_unchanged_and_unsigned_halfword_changes_notify_after_store() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::SELECTION_STATE_ACTIVE_ITEM_VALUE, 0x4000,
        ).expect("target-width active-item fixture");
        let ops = ActiveItemValueRefreshOps { configure, dispatch };
        unsafe {
            slab.write_bytes(0, 0x4000);
            let state = slab.cast::<u32>();
            let old_inner = slab.add(0x400);
            let inner = slab.add(0x1000);
            let item = slab.add(0x2000);
            let payload = slab.add(0x2400);
            let tdat = slab.add(0x2800);
            old_inner.cast::<u32>().write(state as usize as u32);
            old_inner.add(4).cast::<u32>().write(inner as usize as u32);
            inner.add(0xf60).cast::<u32>().write(tdat as usize as u32);
            tdat.add(4).cast::<u32>().write(0x7464_6174);
            item.add(0x40).cast::<u32>().write(payload as usize as u32);
            for (selected, value, cached, changed) in [
                (false, 0, 0, false),
                (false, 0, 7, true),
                (true, 0xffff, 0xffff, false),
                (true, 0xffff, 0, true),
                (true, 0, 0xffff, true),
                (true, 0x8001, 0xffff_8001, true),
            ] {
                state.add(0x30 / 4).write(old_inner as usize as u32);
                inner.add(0xf44).cast::<u32>().write(if selected { item as usize as u32 } else { 0 });
                payload.add(0x2e).cast::<u16>().write(value);
                state.add(0xf0 / 4).write(cached);
                EVENTS.lock().clear();
                selection_state_refresh_active_item_value(state, &ops);
                let expected_value = if selected { value as u32 } else { 0 };
                assert_eq!(state.add(0xf0 / 4).read(), expected_value);
                let expected = if changed {
                    std::vec![(expected_value, 0x564d_6178, 0x6389),
                              (expected_value, 0x564d_6178, 0x63d0),
                              (expected_value, 0x564d_6178, 0x63d1)]
                } else { Vec::new() };
                assert_eq!(*EVENTS.lock(), expected);
            }
        }
    }
}
