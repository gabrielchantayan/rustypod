//! Owner handle and selection reset.
//!
//! `owner_state_reset` — `FUN_081fcae4` at 0x081fcae4, 120 bytes
//! (0x081fcae4..0x081fcb5c; next word starts a distinct PUSH prologue).
//! Two incoming plain BL callers; no predicated incoming BLs. The body has
//! three plain BLs (construct, release twice) and two BLNEs (lock/unlock).
//! Writes -1 at +0x2b4 and zero at +0x2b8 before releasing the handle at
//! +0x2b0 and replacing it with an empty constructed refcounted handle.
//!
//! Deliberate deviations: the proven-NULL temporary eliminates the stock
//! unreachable acquire/lock/unlock arm and slot-address equality check.
//! Hosts widen the four-byte stored body address into a local native pointer
//! slot for release, preserving the adjacent target-width state words.

use crate::cxx::handle::{refcounted_body_release_slot1_copy,
    refcounted_ptr_construct_secondary, RefcountedBody};

/// # Safety
/// `state` must be aligned writable owner storage through +0x2bb. Its +0x2b0
/// word must hold NULL or a valid refcounted body satisfying the release helper's
/// contract. On hosts that address must fit in u32, as in the firmware.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_state_reset(state: *mut u8) {
    state.add(0x2b4).cast::<u32>().write(u32::MAX);
    state.add(0x2b8).cast::<u32>().write(0);
    let mut empty = core::ptr::null_mut();
    refcounted_ptr_construct_secondary(&mut empty, 0, 0);
    #[cfg(target_os = "none")]
    {
        let slot = state.add(0x2b0).cast::<*mut RefcountedBody>();
        refcounted_body_release_slot1_copy(slot);
        slot.write(empty);
    }
    #[cfg(not(target_os = "none"))]
    {
        let slot = state.add(0x2b0).cast::<u32>();
        let mut body = slot.read() as usize as *mut RefcountedBody;
        refcounted_body_release_slot1_copy(&mut body);
        slot.write(empty as usize as u32);
    }
    refcounted_body_release_slot1_copy(&mut empty);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_empty_and_shared_handles_without_touching_neighbor_words() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::OWNER_STATE_RESET, 4096,
        ).expect("low-address owner reset fixture");
        let body = slab.cast::<RefcountedBody>();
        unsafe {
            body.write(RefcountedBody {
                opaque0: 0, refcount: 3, mutex: core::ptr::null_mut(),
            });
            let mut state = [0xa5a5_a5a5u32; 0x2c8 / 4];
            state[0x2b0 / 4] = body as usize as u32;
            owner_state_reset(state.as_mut_ptr().cast());
            assert_eq!((*body).refcount, 2);
            assert_eq!(state[0x2b0 / 4], 0);
            assert_eq!(state[0x2b4 / 4], u32::MAX);
            assert_eq!(state[0x2b8 / 4], 0);
            assert!(state[..0x2b0 / 4].iter().all(|&word| word == 0xa5a5_a5a5));
            assert!(state[0x2bc / 4..].iter().all(|&word| word == 0xa5a5_a5a5));
            owner_state_reset(state.as_mut_ptr().cast());
            assert_eq!((*body).refcount, 2);
            assert_eq!(state[0x2b0 / 4], 0);
            assert_eq!(state[0x2b4 / 4], u32::MAX);
            assert_eq!(state[0x2b8 / 4], 0);
        }
    }
}
