//! `app_screen_cached_position` — original: `FUN_08177944` @ `0x08177944`
//! (**8 bytes**, `0x08177944..0x0817794c`; the next separately linked entry
//! starts at `0x0817794c`). Decoding every aligned ARM `B`/`BL` immediate in
//! `work/firmware/osos.dec` finds exactly eight direct inbound `bl` calls,
//! all unconditional: `0x0812ff50`, `0x08229984`, `0x08229a04`, `0x0823b074`,
//! `0x0823b250`, `0x0823b2cc`, `0x0823b32c`, and `0x0823b3b0`. There are no
//! predicated call forms, direct tail `b` transfers, or aligned data-word
//! references to this address.
//!
//! # Algorithm
//!
//! Return the 32-bit cached position stored at `screen + 0x2c`. The retail
//! `ldr` has no NULL or bounds guard; callers obtain `screen` from the
//! app-screen singleton before invoking this accessor.
//!
//! # Deliberate deviations
//!
//! None.

const CACHED_POSITION_OFFSET: usize = 0x2c;

/// Returns the app screen's cached position word.
///
/// # Safety
///
/// `screen` must be non-NULL, four-byte aligned, and readable through `+0x2f`.
/// The retail code performs no validation before its word load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.app_screen_cached_position")]
pub unsafe extern "C" fn app_screen_cached_position(screen: *const u8) -> u32 {
    screen.add(CACHED_POSITION_OFFSET).cast::<u32>().read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AppScreenPrefix {
        before_position: [u8; CACHED_POSITION_OFFSET],
        cached_position: u32,
        after_position: [u8; 4],
    }

    #[test]
    fn reads_the_aligned_cached_position_word_without_mutating_neighbors() {
        let mut screen = AppScreenPrefix {
            before_position: [0xa5; CACHED_POSITION_OFFSET],
            cached_position: 0,
            after_position: [0x5a; 4],
        };

        for expected in [0, 1, 0x8000_0000, u32::MAX] {
            screen.cached_position = expected;
            let before = screen;

            let actual = unsafe { app_screen_cached_position((&screen as *const AppScreenPrefix).cast()) };

            assert_eq!(actual, expected);
            assert_eq!(screen.before_position, before.before_position);
            assert_eq!(screen.after_position, before.after_position);
        }
    }
}
