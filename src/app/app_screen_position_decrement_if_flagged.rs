//! `app_screen_position_decrement_if_flagged` — original: `FUN_0817790c` @
//! `0x0817790c` (**28 bytes**, `0x0817790c..0x08177928`; the next separately
//! linked entry starts at `0x08177928`). Decoding every aligned ARM `B`/`BL`
//! immediate in `work/firmware/osos.dec` finds exactly eight inbound direct
//! `bl` calls, all unconditional: `0x0817696c`, `0x08176aa4`, `0x08176e0c`,
//! `0x0823911c`, `0x08239140`, `0x0823916c`, `0x082391d4`, and `0x082391e8`.
//! Three unconditional direct tail `b` transfers also target it:
//! `0x08239c34`, `0x08239c4c`, and `0x08260a30`. No aligned data word names
//! this address.
//!
//! # Algorithm
//!
//! Read the two opaque state bytes at `screen + 0x25` and `screen + 0x26`.
//! Preserve `position` only when both are zero; otherwise return its wrapping
//! predecessor. The ARM instruction sequence short-circuits the second load
//! when the first byte is nonzero, so this port does too.
//!
//! # Deliberate deviations
//!
//! None.

const FIRST_STATE_FLAG_OFFSET: usize = 0x25;
const SECOND_STATE_FLAG_OFFSET: usize = 0x26;

/// Returns `position - 1` when either app-screen state flag is nonzero.
///
/// # Safety
///
/// `screen` must be non-NULL and readable through `+0x26`. The retail code
/// performs no pointer validation before either byte load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.app_screen_position_decrement_if_flagged")]
pub unsafe extern "C" fn app_screen_position_decrement_if_flagged(
    screen: *const u8,
    position: u32,
) -> u32 {
    if screen.add(FIRST_STATE_FLAG_OFFSET).read() != 0
        || screen.add(SECOND_STATE_FLAG_OFFSET).read() != 0
    {
        position.wrapping_sub(1)
    } else {
        position
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct AppScreenStatePrefix {
        before_flags: [u8; FIRST_STATE_FLAG_OFFSET],
        first_state_flag: u8,
        second_state_flag: u8,
        after_flags: [u8; 4],
    }

    fn state(first_state_flag: u8, second_state_flag: u8) -> AppScreenStatePrefix {
        AppScreenStatePrefix {
            before_flags: [0xa5; FIRST_STATE_FLAG_OFFSET],
            first_state_flag,
            second_state_flag,
            after_flags: [0x5a; 4],
        }
    }

    #[test]
    fn preserves_position_only_when_both_state_flags_are_zero() {
        for position in [0, 1, 0x8000_0000, u32::MAX] {
            let screen = state(0, 0);

            assert_eq!(
                unsafe { app_screen_position_decrement_if_flagged((&screen as *const AppScreenStatePrefix).cast(), position) },
                position,
                "position={position:#010x}"
            );
        }
    }

    #[test]
    fn decrements_for_each_nonzero_flag_combination_with_wrapping() {
        for (first, second) in [(1, 0), (0, 1), (0xff, 0), (0, 0x80), (1, 1)] {
            let screen = state(first, second);

            assert_eq!(
                unsafe { app_screen_position_decrement_if_flagged((&screen as *const AppScreenStatePrefix).cast(), 0) },
                u32::MAX,
                "first={first:#04x}, second={second:#04x}"
            );
            assert_eq!(
                unsafe { app_screen_position_decrement_if_flagged((&screen as *const AppScreenStatePrefix).cast(), 1) },
                0,
                "first={first:#04x}, second={second:#04x}"
            );
        }
    }

    #[test]
    fn only_reads_the_two_flag_bytes_without_mutating_the_screen_prefix() {
        let screen = state(0, 0xff);
        let before_flags = screen.before_flags;
        let after_flags = screen.after_flags;

        assert_eq!(
            unsafe { app_screen_position_decrement_if_flagged((&screen as *const AppScreenStatePrefix).cast(), 0x1234_5678) },
            0x1234_5677
        );
        assert_eq!(screen.before_flags, before_flags);
        assert_eq!(screen.after_flags, after_flags);
    }
}
