//! `singleton_selection_predecessor` — original: `FUN_0812ce60` @
//! `0x0812ce60` (**20 bytes**, `0x0812ce60..0x0812ce74`; the next separately
//! linked entry starts at `0x0812ce74`). Decoding every aligned ARM `B`/`BL`
//! immediate in `work/firmware/osos.dec` finds exactly eight inbound direct
//! `bl` calls, all unconditional: `0x08225dcc`, `0x08225edc`, `0x08225fb0`,
//! `0x08226370`, `0x08226644`, `0x08226858`, `0x0822691c`, and `0x08226b7c`.
//! No direct tail `b` transfers or aligned data words name this address.
//!
//! # Algorithm
//!
//! Read the opaque singleton byte at `+0x54`. When it is zero, return the
//! selection's wrapping predecessor by two; otherwise return its wrapping
//! predecessor by one. The retail body has no pointer or range guard.
//!
//! # Deliberate deviations
//!
//! None.

const STATE_FLAG_OFFSET: usize = 0x54;

/// Returns the prior singleton selection selected by its state-flag byte.
///
/// # Safety
///
/// `singleton` must be non-NULL and readable through `+0x54`. The retail code
/// performs no pointer validation before its byte load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.singleton_selection_predecessor")]
pub unsafe extern "C" fn singleton_selection_predecessor(
    singleton: *const u8,
    selection: u32,
) -> u32 {
    if singleton.add(STATE_FLAG_OFFSET).read() == 0 {
        selection.wrapping_sub(2)
    } else {
        selection.wrapping_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct SingletonPrefix {
        before_state_flag: [u8; STATE_FLAG_OFFSET],
        state_flag: u8,
        after_state_flag: u8,
    }

    fn singleton(state_flag: u8) -> SingletonPrefix {
        SingletonPrefix {
            before_state_flag: [0xa5; STATE_FLAG_OFFSET],
            state_flag,
            after_state_flag: 0x5a,
        }
    }

    #[test]
    fn zero_state_flag_skips_two_selections_with_wrapping() {
        let singleton = singleton(0);

        for selection in [0, 1, 2, 0x8000_0000, u32::MAX] {
            assert_eq!(
                unsafe { singleton_selection_predecessor((&singleton as *const SingletonPrefix).cast(), selection) },
                selection.wrapping_sub(2),
                "selection={selection:#010x}"
            );
        }
    }

    #[test]
    fn every_nonzero_state_flag_skips_one_selection_with_wrapping() {
        for state_flag in [1, 2, 0x80, u8::MAX] {
            let singleton = singleton(state_flag);

            for selection in [0, 1, 2, 0x8000_0000, u32::MAX] {
                assert_eq!(
                    unsafe { singleton_selection_predecessor((&singleton as *const SingletonPrefix).cast(), selection) },
                    selection.wrapping_sub(1),
                    "state_flag={state_flag:#04x}, selection={selection:#010x}"
                );
            }
        }
    }

    #[test]
    fn reads_the_state_flag_without_mutating_its_neighbours() {
        let singleton = singleton(0xff);
        let before_state_flag = singleton.before_state_flag;
        let after_state_flag = singleton.after_state_flag;

        assert_eq!(
            unsafe { singleton_selection_predecessor((&singleton as *const SingletonPrefix).cast(), 0x1234_5678) },
            0x1234_5677
        );
        assert_eq!(singleton.before_state_flag, before_state_flag);
        assert_eq!(singleton.after_state_flag, after_state_flag);
    }
}
