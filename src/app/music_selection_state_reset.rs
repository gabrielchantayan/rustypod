//! Resets the transient selection state held by a music controller.

/// `music_selection_state_reset` — original: `FUN_0822e110` @ `0x0822e110`
/// (**40 bytes**, `0x0822e110..0x0822e138`; the `push {r4, lr}` at
/// `0x0822e138` starts the distinct next function).
///
/// Raw ARM is `mov r1,#0`; byte stores at `+0xb1`, `+0xbc..+0xbf`; and word
/// stores at `+0xb4`, `+0xb8`, and `+0xc0`, then `bx lr`. Decoding every ARM
/// B/BL immediate in `osos.dec` finds four direct inbound plain `bl` calls
/// (0x082305bc, 0x0823089c, 0x08231924, and 0x08233eac), with no predicated
/// BL forms. Callers reset this state before changing artist, album,
/// compilation, or Genius selections.
///
/// Deliberate deviations: the original uses independent byte stores for the
/// four-byte `+0xbc` field; this port retains those stores and their order
/// rather than coalescing them.
///
/// # Safety
///
/// `state` must be non-NULL, four-byte aligned, and writable through offset
/// `0xc3`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.music_selection_state_reset")]
#[inline(never)]
pub unsafe extern "C" fn music_selection_state_reset(state: *mut u8) -> *mut u8 {
    core::ptr::write_volatile(state.add(0xb1), 0);
    core::ptr::write_volatile(state.add(0xb4).cast::<u32>(), 0);
    core::ptr::write_volatile(state.add(0xb8).cast::<u32>(), 0);
    core::ptr::write_volatile(state.add(0xbc), 0);
    core::ptr::write_volatile(state.add(0xbd), 0);
    core::ptr::write_volatile(state.add(0xbe), 0);
    core::ptr::write_volatile(state.add(0xbf), 0);
    core::ptr::write_volatile(state.add(0xc0).cast::<u32>(), 0);
    state
}

#[cfg(test)]
mod tests {
    use super::music_selection_state_reset;

    #[test]
    fn clears_exactly_the_selection_state_fields() {
        let mut storage = [0xaaaa_aaaau32; 51];
        let state = storage.as_mut_ptr().cast::<u8>();

        let returned = unsafe { music_selection_state_reset(state) };
        let bytes = unsafe { core::slice::from_raw_parts(state, 0xcc) };

        assert_eq!(returned, state);
        assert_eq!(bytes[0xb0], 0xaa);
        assert_eq!(bytes[0xb1], 0);
        assert_eq!(&bytes[0xb4..0xc4], &[0; 16]);
        assert_eq!(bytes[0xc4], 0xaa);
    }

    #[test]
    fn preserves_the_unwritten_gap_before_aligned_words() {
        let mut storage = [u32::MAX; 51];
        let state = storage.as_mut_ptr().cast::<u8>();

        unsafe { music_selection_state_reset(state) };
        let bytes = unsafe { core::slice::from_raw_parts(state, 0xc5) };

        assert_eq!(bytes[0xb2], u8::MAX);
        assert_eq!(bytes[0xb3], u8::MAX);
    }
}
