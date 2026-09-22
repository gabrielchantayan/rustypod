//! `phta_tagged_state_set_mode` — original: `thunk_FUN_082e7c78` @
//! **0x08261d9c** (4 bytes).
//!
//! Raw `osos.dec` establishes a single `b 0x082e7c78` instruction at
//! 0x08261d9c; `mov r0,#0x52; bx lr` at 0x08261da0 begins the next real
//! function. Whole-image A32 decoding finds exactly three inbound plain `bl`
//! calls (0x0839e8dc, 0x0839ea48, and 0x0839f424) and no predicated `bl`
//! calls.
//!
//! # Algorithm
//!
//! The retail veneer tail-branches to 0x082e7c78. That target's raw words
//! validate a non-null object tag of `0x41544850` (`PHTA` in little-endian
//! byte order), accept only modes 1 and 2, store the accepted mode at +0x1c,
//! and return zero. Every rejection returns `0x1a` without a store.
//!
//! Deliberate deviation: the target has no established semantic identity or
//! `names.yaml` seam, so this port implements its verified leaf behavior
//! directly rather than inventing and calling a Rust callee.

/// The opaque first-word tag accepted by the retail target at 0x082e7c78.
pub const PHTA_TAG: u32 = 0x4154_4850;

/// Retail status returned for a null object, mismatched tag, or invalid mode.
pub const INVALID_ARGUMENT: u32 = 0x1a;

/// Target-width prefix accessed by [`phta_tagged_state_set_mode`].
#[repr(C)]
pub struct PhtaTaggedState {
    /// +0x00: opaque `PHTA` tag.
    pub tag: u32,
    _reserved: [u32; 6],
    /// +0x1c: mode, accepted only as 1 or 2.
    pub mode: u32,
}

/// Validates a PHTA-tagged state and sets its mode.
///
/// # Safety
///
/// A non-null `state` must point to a readable and writable, four-byte-aligned
/// [`PhtaTaggedState`]. RetailOS directly loads +0x00 and conditionally stores
/// +0x1c with no further bounds or lifetime checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.phta_tagged_state_set_mode")]
#[inline(never)]
pub unsafe extern "C" fn phta_tagged_state_set_mode(
    state: *mut PhtaTaggedState,
    mode: u32,
) -> u32 {
    if state.is_null()
        || unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*state).tag)) } != PHTA_TAG
        || (mode != 1 && mode != 2)
    {
        return INVALID_ARGUMENT;
    }

    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*state).mode), mode) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_modes_update_only_the_mode_word() {
        for mode in [1, 2] {
            let mut state = PhtaTaggedState {
                tag: PHTA_TAG,
                _reserved: [0xa5a5_a5a5; 6],
                mode: 0xfeed_face,
            };

            assert_eq!(unsafe { phta_tagged_state_set_mode(&mut state, mode) }, 0);
            assert_eq!(state.mode, mode);
            assert_eq!(state._reserved, [0xa5a5_a5a5; 6]);
        }
    }

    #[test]
    fn rejected_inputs_leave_mode_unchanged() {
        assert_eq!(unsafe { phta_tagged_state_set_mode(core::ptr::null_mut(), 1) }, INVALID_ARGUMENT);

        for (tag, mode) in [(0, 1), (PHTA_TAG, 0), (PHTA_TAG, 3), (PHTA_TAG, u32::MAX)] {
            let mut state = PhtaTaggedState {
                tag,
                _reserved: [0; 6],
                mode: 0xfeed_face,
            };

            assert_eq!(unsafe { phta_tagged_state_set_mode(&mut state, mode) }, INVALID_ARGUMENT);
            assert_eq!(state.mode, 0xfeed_face);
        }
    }
}
