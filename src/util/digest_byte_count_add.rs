//! `digest_byte_count_add` — original `FUN_082eac78` at `0x082eac78`.
//!
//! True extent: 44 bytes (`0x082eac78..0x082eaca4`), ending before the next
//! push-prologue at `0x082eaca4`. A raw ARM B/BL scan finds four direct call
//! sites: four plain `bl` and no predicated calls. The routine adds `len` to
//! the low word of the digest state's byte count at +0x44, then increments the
//! high word at +0x40 exactly when that wrapping addition carries. Deliberate
//! deviation: none.

/// Target-layout prefix of the digest state consumed by
/// [`digest_byte_count_add`].
///
/// The byte-count words are kept as words, rather than host pointers or a
/// native `u64`, so their offsets remain +0x40 (high) and +0x44 (low).
#[repr(C)]
pub struct DigestState {
    _buffer: [u32; 16],
    pub byte_count_high: u32,
    pub byte_count_low: u32,
}

/// Adds `len` to a digest state's wrapping 64-bit byte count.
///
/// # Safety
///
/// `state` must point to a writable retail digest-state prefix.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn digest_byte_count_add(state: *mut DigestState, len: u32) {
    let state = unsafe { &mut *state };
    let low = state.byte_count_low.wrapping_add(len);
    if low < len {
        state.byte_count_high = state.byte_count_high.wrapping_add(1);
    }
    state.byte_count_low = low;
}

#[cfg(test)]
mod tests {
    use super::{digest_byte_count_add, DigestState};

    fn state(high: u32, low: u32) -> DigestState {
        DigestState { _buffer: [0; 16], byte_count_high: high, byte_count_low: low }
    }

    #[test]
    fn adds_without_carry() {
        let mut state = state(0x1234_5678, 0x1000_0000);
        unsafe { digest_byte_count_add(&mut state, 0x20) };
        assert_eq!(state.byte_count_high, 0x1234_5678);
        assert_eq!(state.byte_count_low, 0x1000_0020);
    }

    #[test]
    fn carries_into_high_word() {
        let mut state = state(0xffff_ffff, 0xffff_fff0);
        unsafe { digest_byte_count_add(&mut state, 0x20) };
        assert_eq!(state.byte_count_high, 0);
        assert_eq!(state.byte_count_low, 0x10);
    }

    #[test]
    fn zero_preserves_count() {
        let mut state = state(0x89ab_cdef, 0x0123_4567);
        unsafe { digest_byte_count_add(&mut state, 0) };
        assert_eq!(state.byte_count_high, 0x89ab_cdef);
        assert_eq!(state.byte_count_low, 0x0123_4567);
    }
}
