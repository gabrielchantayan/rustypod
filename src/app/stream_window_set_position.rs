//! `stream_window_set_position` — original: `FUN_0822b250` @ `0x0822b250`
//! (**88 bytes**, `0x0822b250..0x0822b2a4`). The next separately linked
//! function begins at `0x0822b2a8`.
//!
//! Raw ARM saves the requested position at `state+0x34`. A request of `-1`
//! returns immediately, leaving the previous window length at `+0x30`. Any
//! other request calls the unported mode-selected extent helper at
//! `0x0822ad9c`, subtracts the request with 32-bit wrapping arithmetic, and
//! treats a negative signed result as invalid: it replaces the saved position
//! with `-1` and again preserves `+0x30`. A nonnegative remainder becomes the
//! new window length, capped by the configured maximum at `+0x2c`.
//!
//! The helper selects its extent word from `state+0x5e8` (mode flag bit 0
//! clear) or `state+0x2f0` (set). Its owning class and the semantic unit of
//! the extent are not identified; `StreamWindowState` names only the verified
//! local window fields. On target the helper is reached through an absolute
//! veneer so this payload function retains the retail call.
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds eight direct
//! inbound `bl` calls: one predicated `bleq` at `0x081cc658`, plus
//! unconditional calls at `0x081cc938`, `0x081cca48`, `0x081cca58`,
//! `0x081cce68`, `0x081ccfb8`, `0x081ccfcc`, and `0x081ccfe0`. The predicated
//! site means this function is entered only when its caller's equality
//! condition holds; this function itself has no NULL guard.
//!
//! Deliberate deviations: none.

/// The local, word-aligned window state observed at the start of the wider
/// mode-selected state object.
///
/// The active-extent helper also requires the full wider object to contain a
/// readable mode byte at `+0x5f8` and extent words at `+0x2f0` and `+0x5e8`.
#[repr(C)]
pub struct StreamWindowState {
    _reserved_00_28: [u32; 11],
    pub maximum_window_length: i32,
    pub window_length: i32,
    pub requested_position: i32,
}

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn retail_mode_selected_extent(state: *const u8) -> u32;
}

// The host seam models only the stock callee needed to exercise this function;
// target builds use the absolute retail veneer below.
#[cfg(not(target_os = "none"))]
unsafe fn retail_mode_selected_extent(state: *const u8) -> u32 {
    if state.add(0x5f8).read() & 1 == 0 {
        state.add(0x5e8).cast::<u32>().read()
    } else {
        state.add(0x2f0).cast::<u32>().read()
    }
}

/// Saves a requested position and derives the remaining, capped window length.
///
/// # Safety
///
/// `state` must be non-NULL, four-byte aligned, and writable through `+0x34`.
/// Except for `position == -1`, it must additionally address the full wider
/// state object required by `retail_mode_selected_extent`: readable words at
/// `+0x2f0` and `+0x5e8`, and a readable byte at `+0x5f8`. There is no NULL,
/// bounds, or alignment guard in the retail ARM implementation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_window_set_position(state: *mut StreamWindowState, position: i32) {
    (*state).requested_position = position;
    if position == -1 {
        return;
    }

    let remaining = retail_mode_selected_extent(state.cast()).wrapping_sub(position as u32) as i32;
    if remaining < 0 {
        (*state).requested_position = -1;
        return;
    }

    (*state).window_length = core::cmp::min(remaining, (*state).maximum_window_length);
}

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_mode_selected_extent
    .type retail_mode_selected_extent, %function
retail_mode_selected_extent:
    ldr     pc, [pc, #-4]
    .word   0x0822ad9c
    .size retail_mode_selected_extent, . - retail_mode_selected_extent
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    const MODE_EXTENT_OFFSET: usize = 0x2f0;
    const DEFAULT_EXTENT_OFFSET: usize = 0x5e8;
    const FLAGS_OFFSET: usize = 0x5f8;
    const STATE_BYTES: usize = FLAGS_OFFSET + 4;

    #[repr(align(4))]
    struct Fixture([u8; STATE_BYTES]);

    fn fixture(maximum_window_length: i32, window_length: i32, requested_position: i32) -> Fixture {
        let mut fixture = Fixture([0xa5; STATE_BYTES]);
        unsafe {
            fixture.0.as_mut_ptr().cast::<StreamWindowState>().write(StreamWindowState {
                _reserved_00_28: [0; 11],
                maximum_window_length,
                window_length,
                requested_position,
            });
        }
        fixture
    }

    unsafe fn write_word(fixture: &mut Fixture, offset: usize, value: u32) {
        fixture.0.as_mut_ptr().add(offset).cast::<u32>().write(value);
    }

    unsafe fn window(fixture: &mut Fixture) -> &mut StreamWindowState {
        &mut *fixture.0.as_mut_ptr().cast::<StreamWindowState>()
    }

    #[test]
    fn caps_remaining_window_using_the_selected_extent() {
        let cases = [
            (0x00, 100_u32, 3_u32, 40_i32, 128_i32, 60_i32),
            (0x01, 3, 100, 40, 16, 16),
            (0x80, 40, 3, 40, 128, 0),
            (0x81, 3, 40, 0, 64, 40),
        ];

        for (flags, default_extent, mode_extent, position, maximum, expected_length) in cases {
            let mut fixture = fixture(maximum, 0x7777, 0x5555);
            unsafe {
                write_word(&mut fixture, DEFAULT_EXTENT_OFFSET, default_extent);
                write_word(&mut fixture, MODE_EXTENT_OFFSET, mode_extent);
                fixture.0[FLAGS_OFFSET] = flags;
                stream_window_set_position(fixture.0.as_mut_ptr().cast(), position);

                let state = window(&mut fixture);
                assert_eq!(state.requested_position, position, "flags={flags:#04x}");
                assert_eq!(state.window_length, expected_length, "flags={flags:#04x}");
            }
        }
    }

    #[test]
    fn sentinel_and_negative_remainder_preserve_the_previous_window() {
        let mut sentinel = fixture(32, 19, 7);
        unsafe {
            stream_window_set_position(sentinel.0.as_mut_ptr().cast(), -1);
            let state = window(&mut sentinel);
            assert_eq!(state.requested_position, -1);
            assert_eq!(state.window_length, 19);
        }

        let mut beyond_extent = fixture(32, 19, 7);
        unsafe {
            write_word(&mut beyond_extent, DEFAULT_EXTENT_OFFSET, 40);
            write_word(&mut beyond_extent, MODE_EXTENT_OFFSET, 3);
            beyond_extent.0[FLAGS_OFFSET] = 0;
            stream_window_set_position(beyond_extent.0.as_mut_ptr().cast(), 41);
            let state = window(&mut beyond_extent);
            assert_eq!(state.requested_position, -1);
            assert_eq!(state.window_length, 19);
        }
    }

    #[test]
    fn signed_subtraction_result_controls_invalidity() {
        let mut fixture = fixture(64, 23, 4);
        unsafe {
            write_word(&mut fixture, DEFAULT_EXTENT_OFFSET, 0x8000_0000);
            write_word(&mut fixture, MODE_EXTENT_OFFSET, 0);
            fixture.0[FLAGS_OFFSET] = 0;
            stream_window_set_position(fixture.0.as_mut_ptr().cast(), 0);
            let state = window(&mut fixture);
            assert_eq!(state.requested_position, -1);
            assert_eq!(state.window_length, 23);
        }
    }
}
