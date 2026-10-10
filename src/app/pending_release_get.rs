//! RetailOS pending-release state byte getter.
//!
//! `pending_release_get` — `FUN_0806b438` @ `0x0806b438`, 8 bytes
//! (`0x0806b438..0x0806b440`, next function starts at `0x0806b440`).
//! Whole-image aligned A32 decoding verifies two plain incoming BLs
//! (`0x08068e14`, `0x0806e728`), zero predicated incoming BLs, and zero
//! outgoing BLs. Words: `e5d00b91` (LDRB r0,[r0,#0xb91]), `e12fff1e` (BX lr).
//! Read and zero-extend the pending-release byte in the owner's state object;
//! callers test it against zero. The field name follows application_shutdown.
//! Deliberate deviations: none; keep the full byte rather than a Boolean.

/// Return the pending-release byte without changing the state object.
///
/// # Safety
/// `state` must point to an allocation with a readable byte at offset `0xb91`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_release_get(state: *const u8) -> u32 {
    state.add(0xb91).read() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_every_byte_and_ignores_neighboring_fields() {
        let mut state = [0xa5u8; 0xb93];
        state[0xb90] = 0x17;
        state[0xb92] = 0xe8;
        for value in 0..=255u32 {
            state[0xb91] = value as u8;
            let before = state;
            assert_eq!(unsafe { pending_release_get(state.as_ptr()) }, value);
            assert_eq!(state, before);
        }
    }

    #[test]
    fn accepts_unaligned_state_with_field_at_allocation_end() {
        let mut storage = [0u8; 0xb95];
        for displacement in 0..4 {
            let state = &mut storage[displacement..displacement + 0xb92];
            state[0xb91] = 0xff;
            assert_eq!(unsafe { pending_release_get(state.as_ptr()) }, 255);
        }
    }
}
