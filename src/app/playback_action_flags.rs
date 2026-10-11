//! `playback_action_flags` — original: `FUN_0817b958` @ **0x0817b958**.
//!
//! Raw `osos.dec` establishes the exact 96-byte extent
//! `0x0817b958..0x0817b9b8`; the next separately linked function starts at
//! `0x0817b9b8`. A complete A32 `B`/`BL` decode finds four inbound plain,
//! unconditional `bl` calls (0x0817918c, 0x081799ec, 0x0817b2bc, and
//! 0x0817b3bc), with no predicated `bl` calls. The function contains one
//! plain direct `bl`, to the ported metadata action selector at 0x08054de0.
//!
//! Algorithm: command 3 is normalized through the nested-state selector on
//! the target-width word at `player+0x9a8`; other command values pass through.
//! The normalized value produces a nonzero flag and an exactly-two flag.
//!
//! Deliberate deviations: call the Rust metadata action port directly.

use crate::ft::service::metadata::ft_service_metadata_action;

/// `playback_action_flags` — original: `FUN_0817b958` @ **0x0817b958**
/// (96 bytes; four plain inbound `bl` call sites and no predicated calls).
///
/// # Safety
///
/// `player` must be readable through its target-width word at `+0x9a8`.
/// `has_action` and `is_action_two` must each designate writable bytes. For
/// command 3, the target-width word must identify a valid nested state object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn playback_action_flags(
    player: *mut u8,
    command: u32,
    has_action: *mut u8,
    is_action_two: *mut u8,
) {
    let action = if command == 3 {
        let nested_state = unsafe {
            core::ptr::read_volatile(player.add(0x9a8).cast::<u32>()) as usize as *mut u8
        };
        unsafe { ft_service_metadata_action(nested_state) }
    } else {
        command
    };

    unsafe {
        has_action.write((action != 0) as u8);
        is_action_two.write((action == 2) as u8);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn maps_commands_to_flags_and_normalizes_command_three() {
        let _guard = TEST_LOCK.lock();
        let Some(player) = try_map_u32_slab(hints::PLAYBACK_ACTION_FLAGS, 0x3000) else {
            assert!(note_missing_u32_fixture("app/playback_action_flags"));
            return;
        };
        unsafe {
            player.write_bytes(0, 0x3000);
            let nested_state = player.add(0x1000);
            let metadata = player.add(0x2000);
            player.add(0x9a8).cast::<u32>().write(nested_state as usize as u32);
            nested_state.add(0xf00).cast::<*const u8>().write(metadata);

            for (command, gate, secondary, expected_has_action, expected_is_action_two) in [
                (0, 0, 0, 0, 0),
                (1, 0, 0, 1, 0),
                (2, 0, 0, 1, 1),
                (u32::MAX, 0, 0, 1, 0),
                (3, 0, 255, 0, 0),
                (3, 128, 0, 1, 0),
                (3, 255, 128, 1, 1),
            ] {
                metadata.add(0x1c).write(gate);
                metadata.add(0x8e).write(secondary);
                let mut has_action = 0xff;
                let mut is_action_two = 0xff;
                playback_action_flags(
                    player,
                    command,
                    addr_of_mut!(has_action),
                    addr_of_mut!(is_action_two),
                );
                assert_eq!(has_action, expected_has_action, "command={command:#x}");
                assert_eq!(is_action_two, expected_is_action_two, "command={command:#x}");
            }
        }
    }
}
