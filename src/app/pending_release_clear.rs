//! RetailOS pending-release state byte clear.
//!
//! `pending_release_clear` — `FUN_080648fc` @ `0x080648fc`, 12 bytes
//! (`0x080648fc..0x08064908`). The next code boundary at `0x08064908`
//! resumes slot_request_release's disjoint tail, not this helper.
//! Raw words: `e3a01000` (MOV r1,#0), `e5c01b91` (STRB r1,[r0,#0xb91]),
//! `e12fff1e` (BX lr). Whole-image aligned A32 decoding finds two plain
//! incoming BLs (`0x08068e2c`, `0x0806e740`), zero predicated incoming BLs,
//! and zero outgoing BLs. Clear only the pending-release byte; callers
//! supply the state pointer from owner+0xf00 after release cleanup.
//! Deliberate deviations: none. The void ABI does not expose preserved r0.

/// Clear the pending-release byte without touching neighboring state.
///
/// # Safety
/// `state` must point to an allocation writable at byte offset `0xb91`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_release_clear(state: *mut u8) {
    state.add(0xb91).write(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn clears_every_byte_value_without_changing_neighbors() {
        let mut state = [0xa5u8; 0xb93];
        for value in 0..=255u8 {
            state[0xb91] = value;
            let mut expected = state;
            expected[0xb91] = 0;
            unsafe { pending_release_clear(state.as_mut_ptr()); }
            assert_eq!(state, expected);
        }
    }

    #[test]
    fn accepts_unaligned_bases_and_last_byte_of_allocation() {
        for displacement in 0..4 {
            let mut storage = std::vec![0x79u8; displacement + 0xb92];
            let mut expected = storage.clone();
            expected[displacement + 0xb91] = 0;
            unsafe { pending_release_clear(storage.as_mut_ptr().add(displacement)); }
            assert_eq!(storage, expected);
            unsafe { pending_release_clear(storage.as_mut_ptr().add(displacement)); }
            assert_eq!(storage, expected);
        }
    }
}
