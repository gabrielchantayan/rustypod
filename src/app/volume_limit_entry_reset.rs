//! `volume_limit_entry_reset` — `FUN_0827f67c` @ **0x0827f67c**, 20 bytes.
//! Raw A32: mov r1,#1; str r1,[r0,#0xa0]; mov r1,#0;
//! str r1,[r0,#0x8c]; bx lr. The next real function starts at 0x0827f690.
//! Whole-image word decoding finds two incoming plain BLs (0x0820e878,
//! 0x08227f94), zero predicated incoming BLs, and zero outgoing BLs.
//!
//! Reset the volume-limit object's entry state: store 1 at +0xa0, then
//! clear +0x8c. Called during entry setup and before the locked volume-limit
//! screen transition. The individual field meanings remain unverified.
//! Deliberate deviations: none; volatile word stores preserve retail order.

/// Resets the two entry-state words without changing the rest of the object.
///
/// # Safety
/// `object` must point to an aligned writable retail object through +0xa3.
/// There is no NULL guard, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn volume_limit_entry_reset(object: *mut u32) {
    unsafe {
        object.add(0xa0 / 4).write_volatile(1);
        object.add(0x8c / 4).write_volatile(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_arbitrary_prior_states_and_preserves_surrounding_words() {
        for prior in [0, 1, 3, 0x8000_0000, u32::MAX] {
            let mut object = [0xa5a5_5a5au32; 0xbc / 4];
            object[0xa0 / 4] = prior;
            object[0x8c / 4] = !prior;
            let mut expected = object;
            expected[0xa0 / 4] = 1;
            expected[0x8c / 4] = 0;
            unsafe { volume_limit_entry_reset(object.as_mut_ptr()) };
            assert_eq!(object, expected);
            unsafe { volume_limit_entry_reset(object.as_mut_ptr()) };
            assert_eq!(object, expected);
        }
    }
}
