//! AHTP-tagged state teardown.
//!
/// `ahtp_state_destroy` — original: `FUN_08261dbc` @ **0x08261dbc** (20
/// bytes; 8 verified unconditional `bl` call sites, no predicated `bl` forms).
///
/// Raw ARM saves `state`, calls the 20-byte leaf at `0x082e7b80`, restores
/// `state` to `r0`, then returns. That leaf leaves NULL and non-AHTP state
/// untouched; when word zero is the `AHTP` tag (`0x5054_4841`), it clears that
/// word. The eight direct callers are `0x081e6bac`, `0x082628b8`,
/// `0x0839e8ac`, `0x0839e968`, `0x0839ea18`, `0x0839ead4`, `0x0839f3f4`, and
/// `0x0839f4b0`; a whole-image ARM B/BL decode found no predicated form.
///
/// Deliberate deviation: the unported, fully decoded leaf at `0x082e7b80` is
/// inlined here instead of adding a dispatch seam. Its return status is
/// unobservable because this wrapper always restores and returns `state`.
///
/// # Safety
///
/// If non-NULL, `state` must be aligned and valid for one writable `u32`.
const AHTP_STATE_TAG: u32 = 0x5054_4841;

#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ahtp_state_destroy")]
#[inline(never)]
pub unsafe extern "C" fn ahtp_state_destroy(state: *mut u32) -> *mut u32 {
    if !state.is_null() && state.read() == AHTP_STATE_TAG {
        state.write(0);
    }
    state
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::ahtp_state_destroy;

    #[test]
    fn clears_only_ahtp_tag_and_returns_state() {
        let mut words = [0x1111_1111, 0x5054_4841, 0x2222_2222];
        let state = unsafe { words.as_mut_ptr().add(1) };

        let returned = unsafe { ahtp_state_destroy(state) };

        assert_eq!(returned, state);
        assert_eq!(words, [0x1111_1111, 0, 0x2222_2222]);
    }

    #[test]
    fn preserves_non_ahtp_state_and_returns_state() {
        let mut words = [0x1111_1111, 0x4148_5450, 0x2222_2222];
        let state = unsafe { words.as_mut_ptr().add(1) };

        let returned = unsafe { ahtp_state_destroy(state) };

        assert_eq!(returned, state);
        assert_eq!(words, [0x1111_1111, 0x4148_5450, 0x2222_2222]);
    }

    #[test]
    fn accepts_null_and_returns_null() {
        assert!(unsafe { ahtp_state_destroy(core::ptr::null_mut()) }.is_null());
    }
}
