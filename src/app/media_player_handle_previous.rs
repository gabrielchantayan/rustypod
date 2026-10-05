//! `media_player_handle_previous` — `FUN_081cf4bc` @ **0x081cf4bc**.
//! True size **72 bytes**, ending at the independent prologue at 0x081cf504.
//! Raw A32 words verify one plain BL, zero predicated BLs, one register BLX,
//! and two conditional BX tail dispatches. Incoming: one BL and one BLNE.
//!
//! HandlePrevious obtains the existing media-player interface, subtracts
//! 0x14 only when non-NULL to recover the complete player, and queries its
//! vtable +0x1a0. Reload the vtable afterward: a zero query dispatches +0x10c
//! with argument 1; any nonzero query dispatches +0xfc without that argument.
//! Virtual identities are unresolved; the final r0 result passes through.
//!
//! Deliberate deviations: reuse the crate-owned singleton getter (its existing
//! not-hook-ready caveat applies). Host fixtures use native-width vtable words;
//! target slots remain four bytes apart. NULL is not made a safe no-op.

const QUERY_SLOT: usize = 0x1a0 / 4;
const PREVIOUS_SLOT: usize = 0xfc / 4;
const PREVIOUS_WITH_FLAG_SLOT: usize = 0x10c / 4;
type Query = unsafe extern "C" fn(*mut u8) -> u32;
type Previous = unsafe extern "C" fn(*mut u8) -> u32;
type PreviousWithFlag = unsafe extern "C" fn(*mut u8, u32) -> u32;

unsafe fn vtable_word(player: *mut u8, slot: usize) -> usize {
    let vtable = player.cast::<*const usize>().read_volatile();
    vtable.add(slot).read_volatile()
}

unsafe fn dispatch(interface: *mut u8) -> u32 {
    let player = if interface.is_null() { interface } else { interface.sub(0x14) };
    let query: Query = core::mem::transmute(vtable_word(player, QUERY_SLOT));
    if query(player) == 0 {
        let previous: PreviousWithFlag =
            core::mem::transmute(vtable_word(player, PREVIOUS_WITH_FLAG_SLOT));
        previous(player, 1)
    } else {
        let previous: Previous = core::mem::transmute(vtable_word(player, PREVIOUS_SLOT));
        previous(player)
    }
}

/// Dispatches the HandlePrevious action on the complete media player.
///
/// # Safety
/// The singleton must exist, with a valid complete-object vtable containing
/// callable +0x1a0, +0xfc, and +0x10c slots of the signatures above.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_handle_previous() -> u32 {
    dispatch(super::singletons::media_player_interface_get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Player {
        vtable: *const usize,
        replacement: *const usize,
        query_result: u32,
        action: u32,
        // Keep interface +0x14 within the allocation on both host and target.
        padding: [u8; 20],
    }

    unsafe extern "C" fn query(player: *mut u8) -> u32 {
        let player = &mut *player.cast::<Player>();
        assert_eq!(player.action, 0);
        player.action = 1;
        player.vtable = player.replacement;
        player.query_result
    }
    unsafe extern "C" fn previous(player: *mut u8) -> u32 {
        let player = &mut *player.cast::<Player>();
        assert_eq!(player.action, 1);
        player.action = 2;
        0xfedc_ba98
    }
    unsafe extern "C" fn previous_with_flag(player: *mut u8, flag: u32) -> u32 {
        assert_eq!(flag, 1);
        let player = &mut *player.cast::<Player>();
        assert_eq!(player.action, 1);
        player.action = 3;
        0x8765_4321
    }

    #[test]
    fn query_zero_and_all_nonzero_classes_reload_complete_object_vtable() {
        let mut initial = [0usize; QUERY_SLOT + 1];
        let mut replacement = [0usize; QUERY_SLOT + 1];
        initial[QUERY_SLOT] = query as *const () as usize;
        // Only the post-query table has dispatch targets: stale-table access
        // cannot accidentally satisfy the expected action and return value.
        replacement[PREVIOUS_SLOT] = previous as *const () as usize;
        replacement[PREVIOUS_WITH_FLAG_SLOT] = previous_with_flag as *const () as usize;
        for result in [0, 1, 0x8000_0000, u32::MAX] {
            let mut player = Player { vtable: initial.as_ptr(), replacement: replacement.as_ptr(),
                query_result: result, action: 0, padding: [0; 20] };
            let interface = unsafe { (&mut player as *mut Player).cast::<u8>().add(0x14) };
            let value = unsafe { dispatch(interface) };
            assert_eq!(player.action, if result == 0 { 3 } else { 2 });
            assert_eq!(value, if result == 0 { 0x8765_4321 } else { 0xfedc_ba98 });
        }
    }
}
