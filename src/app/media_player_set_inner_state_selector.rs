//! Media-player inner-state selector update.

const PLAYER_INNER_STATE: usize = 0x30;
const INNER_STATE_SELECTOR: usize = 0xe38;
const INNER_STATE_SELECTOR_IS_SIX: usize = 0xe3c;

/// media_player_set_inner_state_selector — original: `FUN_08111338` @
/// `0x08111338` (160 bytes; the next independent function starts at
/// `0x081113d8`).
///
/// Raw A32 decoding verifies three inbound plain unconditional `bl` call
/// sites (`0x08109fac`, `0x081116d4`, and `0x08230158`) and zero predicated
/// `bl` call sites. The body uses a bounded jump table for selectors 0..=6:
/// it writes the selector word to `player->inner_state + 0xe38`, then writes
/// whether the selector is six to byte `+0xe3c`. Selectors above six return
/// without touching either field. Deliberate deviation: the two tiny retailOS
/// helpers at `0x08067ca4` and `0x08067c9c` are inlined because raw words prove
/// them to be precisely these stores; no callee identity is inferred.
///
/// # Safety
///
/// `player` must contain a valid target-width inner-state pointer at `+0x30`.
/// For selectors through six, that object must be writable through `+0xe3c`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_set_inner_state_selector(player: *mut u8, selector: u32) {
    if selector > 6 {
        return;
    }

    let inner_state = (player.add(PLAYER_INNER_STATE) as *const u32).read() as usize as *mut u8;
    (inner_state.add(INNER_STATE_SELECTOR) as *mut u32).write(selector);
    inner_state.add(INNER_STATE_SELECTOR_IS_SIX).write((selector == 6) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_each_valid_selector_and_only_six_sets_marker() {
        use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

        let Some(player) = try_map_u32_slab(hints::MEDIA_PLAYER_SET_INNER_STATE_SELECTOR, 0x3000) else {
            assert!(note_missing_u32_fixture("app/media_player_set_inner_state_selector"));
            return;
        };

        unsafe {
            core::ptr::write_bytes(player, 0, 0x3000);
            let inner_state = player.add(0x1000);
            player.add(PLAYER_INNER_STATE).cast::<u32>().write(inner_state as usize as u32);

            for selector in 0..=6 {
                (inner_state.add(INNER_STATE_SELECTOR) as *mut u32).write(u32::MAX);
                inner_state.add(INNER_STATE_SELECTOR_IS_SIX).write(0xff);

                media_player_set_inner_state_selector(player, selector);

                assert_eq!((inner_state.add(INNER_STATE_SELECTOR) as *const u32).read(), selector);
                assert_eq!(inner_state.add(INNER_STATE_SELECTOR_IS_SIX).read(), (selector == 6) as u8);
            }
        }
    }

    #[test]
    fn ignores_out_of_range_selector() {
        use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

        let Some(player) = try_map_u32_slab(hints::MEDIA_PLAYER_SET_INNER_STATE_SELECTOR_INVALID, 0x3000) else {
            assert!(note_missing_u32_fixture("app/media_player_set_inner_state_selector"));
            return;
        };

        unsafe {
            core::ptr::write_bytes(player, 0, 0x3000);
            let inner_state = player.add(0x1000);
            player.add(PLAYER_INNER_STATE).cast::<u32>().write(inner_state as usize as u32);
            (inner_state.add(INNER_STATE_SELECTOR) as *mut u32).write(0xfeed_beef);
            inner_state.add(INNER_STATE_SELECTOR_IS_SIX).write(0xa5);

            for selector in [7, u32::MAX] {
                media_player_set_inner_state_selector(player, selector);
                assert_eq!((inner_state.add(INNER_STATE_SELECTOR) as *const u32).read(), 0xfeed_beef);
                assert_eq!(inner_state.add(INNER_STATE_SELECTOR_IS_SIX).read(), 0xa5);
            }
        }
    }
}
