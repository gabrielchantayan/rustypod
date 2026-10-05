//! `slideshow_at_end` — original: `FUN_081cd4e4` @ `0x081cd4e4`.
//! True extent: 24 bytes (`0x081cd4e4..0x081cd4fb`); the next function's
//! push prologue starts at `0x081cd4fc`. Raw A32 decoding verifies two inbound
//! unconditional BL calls (`0x0810cdd8`, `0x0810cf3c`), zero predicated BL
//! calls, and zero outgoing calls.
//!
//! Compare the slideshow state's full words at +0x8b8 and +0x8c0 and return
//! exactly 1 when equal, otherwise 0. The caller uses this predicate for its
//! `EnterPlayingAtEndOfSlideshow` transition. No deliberate behavioral
//! deviations; target-layout word indices remain identical on the host.

const POSITION_WORD: usize = 0x8b8 / 4;
const END_WORD: usize = 0x8c0 / 4;

/// Returns whether the slideshow position equals its end marker.
///
/// # Safety
/// `state` must address four-byte-aligned, initialized target-layout storage
/// readable through byte offset +0x8c3, with no concurrent writes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slideshow_at_end(state: *const u32) -> u32 {
    let position = unsafe { state.add(POSITION_WORD).read() };
    let end = unsafe { state.add(END_WORD).read() };
    u32::from(position == end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_uses_full_words_and_returns_canonical_boolean() {
        let mut state = [0xa5a5_a5a5u32; END_WORD + 2];
        for (position, end, expected) in [
            (0, 0, 1),
            (u32::MAX, u32::MAX, 1),
            (0x8000_0000, 0x8000_0000, 1),
            (0, 1, 0),
            (1, 0, 0),
            (0, 0x8000_0000, 0),
            (0x1234_5678, 0x9234_5678, 0),
            (u32::MAX, 0, 0),
        ] {
            state[POSITION_WORD] = position;
            state[END_WORD] = end;
            let before = state;
            assert_eq!(unsafe { slideshow_at_end(state.as_ptr()) }, expected);
            assert_eq!(state, before);
        }
    }

    #[test]
    fn intervening_word_is_not_the_end_marker() {
        let mut state = [0u32; END_WORD + 1];
        state[POSITION_WORD] = 7;
        state[POSITION_WORD + 1] = 7;
        state[END_WORD] = 8;
        assert_eq!(unsafe { slideshow_at_end(state.as_ptr()) }, 0);
        state[POSITION_WORD + 1] = 8;
        state[END_WORD] = 7;
        assert_eq!(unsafe { slideshow_at_end(state.as_ptr()) }, 1);
    }
}
