//! Opaque constant-zero probe — original: `FUN_082fd288` @ `0x082fd288`.
//!
//! Load address: `0x082fd288`; true size: 80 bytes (`0x50`), ending at the
//! literal pool at `0x082fd2d8`; the next real function begins at `0x082fd2e4`
//! with `push {r0-r11, lr}`. Raw A32 decoding verifies zero outgoing plain
//! `bl` instructions and zero predicated `bl` instructions. Whole-image branch
//! decoding finds two inbound plain `bl` sites (`0x082f5680`, `0x08314258`)
//! and no predicated inbound `bl` sites.
//!
//! The leaf volatile-reads the word at `0x089ce3d0`, multiplies it by
//! `0x4f0efc81`, then runs its encoded state transition. The transition always
//! reaches the non-1/non-2 return path because `0x4f0efc81 - 0x5251d9fc` is
//! `0xfcbd2285`, so the observable return is zero. No deliberate deviations.

const OPAQUE_SEED_WORD: *const u32 = 0x089c_e3d0 as *const u32;

/// Performs the retail opaque probe and returns its fixed zero result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.opaque_constant_zero"]
pub unsafe extern "C" fn opaque_constant_zero() -> u32 {
    let product = core::ptr::read_volatile(OPAQUE_SEED_WORD).wrapping_mul(0x4f0e_fc81);
    let initial_state = 0x5251_d9fc_u32;
    let terminal_state = 0x4f0e_fc81_u32;
    let state = terminal_state.wrapping_sub(initial_state);

    if state == 1 {
        0
    } else if state == 2 {
        product
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    static SEED_PAGE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OPAQUE_CONSTANT_ZERO, 0x1000).map(|pointer| pointer as usize)
    });

    #[test]
    fn returns_zero_for_each_observed_seed_word() {
        let Some(seed_page) = *SEED_PAGE else {
            assert!(note_missing_u32_fixture("util/opaque_constant_zero"));
            return;
        };
        if seed_page != hints::OPAQUE_CONSTANT_ZERO {
            assert!(note_missing_u32_fixture("util/opaque_constant_zero"));
            return;
        }

        let seed_word = unsafe { (seed_page as *mut u32).add(0xf4) };
        for seed in [0, 1, 0x1234_5678, u32::MAX] {
            unsafe {
                seed_word.write(seed);
                assert_eq!(opaque_constant_zero(), 0, "seed {seed:#010x}");
            }
        }
    }
}
