//! `completion_gate` — original: `FUN_0822ab50` @ `0x0822ab50` (**52 bytes**,
//! `0x0822ab50..0x0822ab84`; the separately linked next function begins at
//! `0x0822ab84`).
//!
//! Raw ARM has five inbound direct `bl` call sites and no predicated inbound
//! `bl`. Its body has no `bl` instructions. A missing request interface, an
//! inactive request, or a low-bit-clear selected source permits completion.
//! For an active request it selects the default source at `+0x5ec` unless mode
//! flags at `+0x5f8` select the source at `+0x2f4`, then returns that source
//! byte with bit zero inverted.
//!
//! Deliberate deviations: none. As in retailOS, this has no NULL, bounds, or
//! alignment guard.

const REQUEST_INTERFACE_OFFSET: usize = 0x14;
const REQUEST_FLAGS_OFFSET: usize = 0x24;
const MODE_SOURCE_OFFSET: usize = 0x2f4;
const DEFAULT_SOURCE_OFFSET: usize = 0x5ec;
const MODE_FLAGS_OFFSET: usize = 0x5f8;

/// Determines whether the current request may complete.
///
/// # Safety
///
/// `state` must be readable at `+0x14`. If that word is nonzero and `+0x24`
/// has bit zero set, it must also be readable at `+0x2f4`, `+0x5ec`, and
/// `+0x5f8`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn completion_gate(state: *const u8) -> u32 {
    if state.add(REQUEST_INTERFACE_OFFSET).cast::<u32>().read() == 0
        || state.add(REQUEST_FLAGS_OFFSET).read() & 1 == 0
    {
        return 1;
    }

    let source = if state.add(MODE_FLAGS_OFFSET).read() & 1 == 0 {
        state.add(DEFAULT_SOURCE_OFFSET).read()
    } else {
        state.add(MODE_SOURCE_OFFSET).read()
    };
    u32::from(source ^ 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE_WORDS: usize = (MODE_FLAGS_OFFSET + 4) / 4;

    fn state() -> [u32; STATE_WORDS] { [0; STATE_WORDS] }

    #[test]
    fn missing_or_inactive_request_permits_completion() {
        let mut state = state();
        let bytes = state.as_mut_ptr().cast::<u8>();
        unsafe {
            bytes.add(REQUEST_FLAGS_OFFSET).write(1);
            assert_eq!(completion_gate(bytes), 1);
            bytes.add(REQUEST_INTERFACE_OFFSET).cast::<u32>().write(0x1234);
            bytes.add(REQUEST_FLAGS_OFFSET).write(0);
            assert_eq!(completion_gate(bytes), 1);
        }
    }

    #[test]
    fn active_request_inverts_default_source_low_bit() {
        let mut state = state();
        let bytes = state.as_mut_ptr().cast::<u8>();
        unsafe {
            bytes.add(REQUEST_INTERFACE_OFFSET).cast::<u32>().write(1);
            bytes.add(REQUEST_FLAGS_OFFSET).write(1);
            bytes.add(MODE_FLAGS_OFFSET).write(0);
            bytes.add(DEFAULT_SOURCE_OFFSET).write(0);
            assert_eq!(completion_gate(bytes), 1);
            bytes.add(DEFAULT_SOURCE_OFFSET).write(1);
            assert_eq!(completion_gate(bytes), 0);
        }
    }

    #[test]
    fn mode_flag_selects_mode_source() {
        let mut state = state();
        let bytes = state.as_mut_ptr().cast::<u8>();
        unsafe {
            bytes.add(REQUEST_INTERFACE_OFFSET).cast::<u32>().write(1);
            bytes.add(REQUEST_FLAGS_OFFSET).write(1);
            bytes.add(DEFAULT_SOURCE_OFFSET).write(1);
            bytes.add(MODE_SOURCE_OFFSET).write(0);
            bytes.add(MODE_FLAGS_OFFSET).write(1);
            assert_eq!(completion_gate(bytes), 1);
        }
    }
}
