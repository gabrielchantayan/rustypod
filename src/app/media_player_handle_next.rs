//! `media_player_handle_next` — `FUN_081cdf0c` @ **0x081cdf0c**.
//! True size **72 bytes**, 0x081cdf0c..0x081cdf54. Both conditional tail
//! branches terminate before the independent cmp/bne/bx helper at 0x081cdf54;
//! 0x081cdf60 is another independently referenced getter, not part of this port.
//! Raw words verify one plain BL, zero predicated BLs, one register BLX,
//! and two conditional BX tail dispatches. Incoming: one BL and one BLNE.
//!
//! HandleNext obtains the media-player interface, subtracts 0x14 only when
//! non-NULL to recover the complete player, and queries vtable +0x1a0.
//! Reload the vtable afterward: zero dispatches +0x108 with argument 1;
//! any nonzero value dispatches +0xfc. The final r0 result passes through.
//! Virtual identities remain unresolved; HandleNext is proven by its caller.
//!
//! Deliberate deviations: reuse the existing singleton getter (its existing
//! not-hook-ready caveat applies). Host fixtures use native-width vtable words;
//! target slots remain four bytes apart. NULL is not made a safe no-op.

const QUERY_SLOT: usize = 0x1a0 / 4;
const ACTIVE_ACTION_SLOT: usize = 0xfc / 4;
const NEXT_WITH_FLAG_SLOT: usize = 0x108 / 4;
type Query = unsafe extern "C" fn(*mut u8) -> u32;
type ActiveAction = unsafe extern "C" fn(*mut u8) -> u32;
type NextWithFlag = unsafe extern "C" fn(*mut u8, u32) -> u32;

unsafe fn vtable_word(player: *mut u8, slot: usize) -> usize {
    let vtable = player.cast::<*const usize>().read_volatile();
    vtable.add(slot).read_volatile()
}

unsafe fn dispatch(interface: *mut u8) -> u32 {
    let player = if interface.is_null() { interface } else { interface.sub(0x14) };
    let query: Query = core::mem::transmute(vtable_word(player, QUERY_SLOT));
    if query(player) == 0 {
        let next: NextWithFlag =
            core::mem::transmute(vtable_word(player, NEXT_WITH_FLAG_SLOT));
        next(player, 1)
    } else {
        let action: ActiveAction = core::mem::transmute(vtable_word(player, ACTIVE_ACTION_SLOT));
        action(player)
    }
}

/// Dispatches the HandleNext action on the complete media player.
///
/// # Safety
/// The singleton must exist, with a valid complete-object vtable containing
/// callable +0x1a0, +0xfc, and +0x108 slots of the signatures above.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_handle_next() -> u32 {
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
        padding: [u8; 20],
    }

    unsafe extern "C" fn query(player: *mut u8) -> u32 {
        let player = &mut *player.cast::<Player>();
        assert_eq!(player.action, 0);
        player.action = 1;
        player.vtable = player.replacement;
        player.query_result
    }
    unsafe extern "C" fn active_action(player: *mut u8) -> u32 {
        let player = &mut *player.cast::<Player>();
        assert_eq!(player.action, 1);
        player.action = 2;
        0xfedc_ba98
    }
    unsafe extern "C" fn next_with_flag(player: *mut u8, flag: u32) -> u32 {
        assert_eq!(flag, 1);
        let player = &mut *player.cast::<Player>();
        assert_eq!(player.action, 1);
        player.action = 3;
        0x8765_4321
    }

    #[test]
    fn zero_and_nonzero_queries_reload_complete_object_vtable() {
        let mut initial = [0usize; QUERY_SLOT + 1];
        let mut replacement = [0usize; QUERY_SLOT + 1];
        initial[QUERY_SLOT] = query as *const () as usize;
        // Only the replacement has action targets: using the stale vtable fails.
        replacement[ACTIVE_ACTION_SLOT] = active_action as *const () as usize;
        replacement[NEXT_WITH_FLAG_SLOT] = next_with_flag as *const () as usize;
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
