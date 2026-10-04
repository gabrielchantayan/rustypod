//! Conditional flagged-pair shuffle — `FUN_08214de0` @ `0x08214de0`.
//!
//! True extent: 152 bytes, `0x08214de0..0x08214e78`; the next function
//! starts with push {r4,r5,r6,lr}. Raw A32 decoding finds two inbound plain
//! BLs (0x08214988, 0x08214a60), ten outbound plain BLs, no predicated BLs.
//! When owner+0x2f1 is nonzero, iterate unsigned indices [start,end), choose
//! a partner as ansi_rand() % end, and swap records from the container at
//! +0x2d8 with three flagged_pair_copy calls. Partners may precede start;
//! this is deliberately not an unbiased Fisher-Yates shuffle. Four lookups
//! per iteration preserve virtual dispatch ordering, including self-swaps.
//! Deliberate deviations: Rust computes the remainder rather than consuming
//! the ADS division helper's r1 result. The temporary's unread second word
//! and padding remain uninitialized until copied, as in retailOS. Existing
//! container ports widen host vtable/element pointers, while owner offsets
//! and FlaggedPair words remain target-width. No new callee seams.

use crate::cxx::flagged_pair_clear::flagged_pair_clear;
use crate::cxx::flagged_pair_copy::{flagged_pair_copy, FlaggedPair};
use crate::cxx::templates::container_element_at_alias_6bc0;
use crate::runtime::random::ansi_rand;

/// # Safety
/// `owner` must be readable at +0x2f1. When enabled and start < end, its
/// container at +0x2d8 must support indices 0..end and return aligned,
/// readable/writable FlaggedPair records. The ANSI random seed must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn flagged_pair_shuffle(owner: *mut u8, start: u32, end: u32) {
    if owner.add(0x2f1).read() == 0 { return; }
    let mut temporary = core::mem::MaybeUninit::<FlaggedPair>::uninit();
    let temporary = temporary.as_mut_ptr();
    flagged_pair_clear(temporary);
    let container = owner.add(0x2d8);
    let mut index = start;
    while index < end {
        let partner = ansi_rand() % end;
        let current = container_element_at_alias_6bc0(container, index as usize).cast();
        flagged_pair_copy(temporary, current);
        let other = container_element_at_alias_6bc0(container, partner as usize).cast();
        let current = container_element_at_alias_6bc0(container, index as usize).cast();
        flagged_pair_copy(current, other);
        let other = container_element_at_alias_6bc0(container, partner as usize).cast();
        flagged_pair_copy(other, temporary);
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::random::{tests::lock_state, ANSI_RAND_STATE};

    unsafe extern "C" fn slot(container: *mut u8, index: usize) -> *mut *mut u8 {
        let slots = container.add(core::mem::size_of::<usize>()).cast::<*mut *mut u8>().read();
        slots.add(index)
    }

    #[test]
    fn matches_swaps_for_disabled_empty_reversed_self_and_partial_ranges() {
        let _guard = lock_state();
        for (enabled, start, end) in [(0, 0, 8), (1, 0, 0), (1, 8, 3),
                                     (1, 0, 1), (1, 3, 8), (0xff, 0, 8)] {
            for initial_seed in [0u32, 1, 0xffff_ffff, 0x1234_5678] {
                let mut records: [FlaggedPair; 8] = core::array::from_fn(|i| FlaggedPair {
                    first: i as u32 + 100, second: i as u32 + 200,
                    flag: 0xf0 | (i as u8 & 1), reserved: [i as u8, 0xa5, 0x5a],
                });
                let mut expected: [(u32, u32, u8); 8] = core::array::from_fn(|i|
                    (records[i].first, records[i].second, records[i].flag));
                let mut expected_seed = initial_seed;
                if enabled != 0 {
                    for i in start..end {
                        expected_seed = expected_seed.wrapping_mul(1103515245).wrapping_add(12345);
                        let j = (((expected_seed >> 16) & 32767) % end) as usize;
                        expected.swap(i as usize, j);
                        expected[i as usize].2 &= 1;
                        expected[j].2 &= 1;
                    }
                }
                let mut slots: [*mut u8; 8] = core::array::from_fn(|i|
                    (&mut records[i] as *mut FlaggedPair).cast());
                let vtable = [slot as unsafe extern "C" fn(*mut u8, usize) -> *mut *mut u8; 17];
                let mut owner = [0usize; 96];
                let owner_ptr = owner.as_mut_ptr().cast::<u8>();
                let mut seed = initial_seed;
                unsafe {
                    owner_ptr.add(0x2d8).cast::<*const ()>().write(vtable.as_ptr().cast());
                    owner_ptr.add(0x2d8 + core::mem::size_of::<usize>())
                        .cast::<*mut *mut u8>().write(slots.as_mut_ptr());
                    owner_ptr.add(0x2f1).write(enabled);
                    let previous = ANSI_RAND_STATE;
                    ANSI_RAND_STATE = &mut seed;
                    flagged_pair_shuffle(owner_ptr, start, end);
                    ANSI_RAND_STATE = previous;
                }
                assert_eq!(seed, expected_seed);
                for i in 0..8 {
                    assert_eq!((records[i].first, records[i].second, records[i].flag), expected[i]);
                    assert_eq!(records[i].reserved, [i as u8, 0xa5, 0x5a]);
                }
                assert_eq!(unsafe { owner_ptr.add(0x2f1).read() }, enabled);
            }
        }
    }
}
