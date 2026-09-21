//! Releases and clears a pair of target-width tracked-allocation fields.

use crate::heap::tracked::tracked_free;

/// release_tracked_pair — original `FUN_082c369c` @ `0x082c369c` (40 bytes).
///
/// Raw `osos.dec` words establish the exact extent `0x082c369c..0x082c36c3`:
/// `push {r4,lr}; mov r4,r0; ldr r0,[r4]; bl tracked_free; ldr r0,[r4,#4];
/// bl tracked_free; mov r0,#0; str r0,[r4]; str r0,[r4,#4]; pop {r4,pc}`.
/// The following `push {r4,lr}` starts a separately linked function at
/// `0x082c36c4`. The body has two unconditional plain `bl` calls and no
/// predicated calls, both to `tracked_free` @ `0x083906f4`.
///
/// Releases both owned payloads before clearing either target-width field.
/// Deliberate deviation: the two 32-bit target pointers remain `u32` words,
/// preserving the +0x00/+0x04 layout on 64-bit host fixtures.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_tracked_pair(pair: *mut u8) {
    let first = pair.cast::<u32>();
    let second = first.add(1);
    tracked_free(first.read() as usize as *mut u8);
    tracked_free(second.read() as usize as *mut u8);
    first.write(0);
    second.write(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    const SLAB_SIZE: usize = 0x1000;

    unsafe fn fixture() -> Option<(*mut u8, *mut u8, *mut u8, *mut u8, *mut u8)> {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::SQLITE_RELEASE_TRACKED_PAIR,
            SLAB_SIZE,
        )?;
        core::ptr::write_bytes(slab, 0, SLAB_SIZE);
        let first_raw = slab.add(0x100);
        let first_payload = first_raw.add(0x20);
        let second_raw = slab.add(0x200);
        let second_payload = second_raw.add(0x20);
        for (raw, payload) in [(first_raw, first_payload), (second_raw, second_payload)] {
            raw.cast::<i32>().write(23);
            raw.add(4).cast::<i32>().write(0);
            payload.sub(4).cast::<u32>().write((payload as usize - raw.add(8) as usize) as u32);
        }
        Some((slab, first_raw, first_payload, second_raw, second_payload))
    }

    #[test]
    fn releases_both_payloads_before_clearing_both_words() {
        let _heap_guard = crate::heap::veneers::tests::mock_heap();
        let Some((pair, first_raw, first_payload, second_raw, second_payload)) = (unsafe { fixture() }) else {
            crate::testing::note_missing_u32_fixture("sqlite/release_tracked_pair");
            return;
        };
        unsafe {
            pair.cast::<u32>().write(first_payload as u32);
            pair.add(4).cast::<u32>().write(second_payload as u32);
            release_tracked_pair(pair);
            assert_eq!(pair.cast::<u32>().read(), 0);
            assert_eq!(pair.add(4).cast::<u32>().read(), 0);
        }
        let (calls, freed, tag) = crate::heap::veneers::tests::free_log();
        assert_eq!(calls, 2);
        assert_eq!((freed, tag), (second_raw, 57));
        assert_ne!(first_raw, second_raw);
    }

    #[test]
    fn null_words_are_still_cleared_without_freeing() {
        let _heap_guard = crate::heap::veneers::tests::mock_heap();
        let Some((pair, _, _, _, _)) = (unsafe { fixture() }) else {
            crate::testing::note_missing_u32_fixture("sqlite/release_tracked_pair");
            return;
        };
        unsafe {
            release_tracked_pair(pair);
            assert_eq!(pair.cast::<u32>().read(), 0);
            assert_eq!(pair.add(4).cast::<u32>().read(), 0);
        }
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
    }
}
