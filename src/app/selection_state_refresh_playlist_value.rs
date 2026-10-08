//! Refresh the selection state's cached flagged-playlist value.
//!
//! Original FUN_08113680 @ 0x08113680: true extent 156 bytes through
//! 0x0811371c (140 instruction bytes, 16 literal bytes). Verified from raw
//! A32 words: two plain BL instructions, zero predicated BL; two plain
//! inbound BL sites at 0x08114028/0x08114918, zero predicated inbound BL.
//! Two virtual BLX calls and one virtual tail BX use slot +0x58.
//!
//! Configure inner state +0x30 with selectors (1,0), then obtain its flagged
//! playlist. Read the payload pointer at playlist +0x40 and its u16 +0x2e,
//! or use zero for a missing playlist. Compare with cache +0xf4; on change,
//! store before notifying VMax resources 0x638a, 0x63d2, 0x63d3. Reload the
//! vtable on every notification. Deliberate deviations: the final tail
//! dispatch is an ordinary call with unobserved result; host-only operations
//! supply configuration and virtual dispatch while keeping target-width
//! data pointers. The unported configuration uses the existing retail seam.

#[cfg(not(target_os = "none"))]
pub struct PlaylistValueRefreshOps {
    pub configure: unsafe extern "C" fn(*mut u8, u32, u32),
    pub dispatch: unsafe extern "C" fn(*mut u32, u32, u32),
}

/// # Safety
/// State must be writable through +0xf4, with a valid inner object through
/// the playlist lookup's fields. Nonzero playlists require a valid payload
/// pointer and readable halfword +0x2e. Target vtable slot +0x58 must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_state_refresh_playlist_value(
    state: *mut u32,
    #[cfg(not(target_os = "none"))] ops: &PlaylistValueRefreshOps,
) {
    let inner = state.add(0x30 / 4).read() as usize as *mut u8;
    #[cfg(target_os = "none")]
    super::media_player_reset_default_resource::firmware_configure_inner_state(inner, 1, 0);
    #[cfg(not(target_os = "none"))]
    (ops.configure)(inner, 1, 0);
    // Configuration may replace the state's inner pointer.
    let inner = state.add(0x30 / 4).read() as usize as *mut u8;
    let playlist = crate::ui::tdat_flagged_plst::ui_tdat_flagged_plst(inner);
    let value = if playlist == 0 {
        0
    } else {
        let payload = (playlist as usize as *const u32).add(0x40 / 4).read();
        (payload as usize as *const u16).add(0x2e / 2).read() as u32
    };
    if state.add(0xf4 / 4).read() == value {
        return;
    }
    state.add(0xf4 / 4).write(value);
    for resource in [0x638a, 0x63d2, 0x63d3] {
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
        // Make lookup observe configuration's effect, rather than a mock return.
        let selected = inner.add(0xf44).cast::<u32>().read();
        inner.add(0xf48).cast::<u32>().write(selected);
    }

    unsafe extern "C" fn dispatch(state: *mut u32, action: u32, resource: u32) {
        EVENTS.lock().push((state.add(0xf4 / 4).read(), action, resource));
    }

    #[test]
    fn handles_missing_unchanged_and_full_width_halfword_transitions() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::SELECTION_STATE_PLAYLIST_VALUE, 0x3000,
        ).expect("target-width playlist fixture");
        let ops = PlaylistValueRefreshOps { configure, dispatch };
        unsafe {
            slab.write_bytes(0, 0x3000);
            let state = slab.cast::<u32>();
            let inner = slab.add(0x1000);
            let playlist = slab.add(0x2000);
            let payload = slab.add(0x2400);
            state.add(0x30 / 4).write(inner as usize as u32);
            playlist.add(0x40).cast::<u32>().write(payload as usize as u32);
            for (selected, value, cached, changed) in [
                (false, 0, 0, false),
                (false, 0, 7, true),
                (true, 0xffff, 0xffff, false),
                (true, 0xffff, 0, true),
                (true, 0, 0xffff, true),
                (true, 0x8001, 0xffff_8001, true),
            ] {
                inner.add(0xf44).cast::<u32>().write(if selected { playlist as usize as u32 } else { 0 });
                payload.add(0x2e).cast::<u16>().write(value);
                state.add(0xf4 / 4).write(cached);
                EVENTS.lock().clear();
                selection_state_refresh_playlist_value(state, &ops);
                let expected_value = if selected { value as u32 } else { 0 };
                assert_eq!(state.add(0xf4 / 4).read(), expected_value);
                let expected = if changed {
                    std::vec![(expected_value, 0x564d_6178, 0x638a),
                              (expected_value, 0x564d_6178, 0x63d2),
                              (expected_value, 0x564d_6178, 0x63d3)]
                } else { Vec::new() };
                assert_eq!(*EVENTS.lock(), expected);
            }
        }
    }
}
