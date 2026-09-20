//! Post-increment for a sparse segmented iterator.

/// `segmented_iter_post_increment` — original: `FUN_083d36a4` @ `0x083d36a4`.
///
/// Raw `osos.dec` establishes the 68-byte body at
/// `0x083d36a4..0x083d36e4`; the separately linked `push {r4-r10,lr}` at
/// `0x083d36e8` begins the next function. Decoding the raw A32 instruction
/// words finds three inbound plain `bl` calls and no predicated `bl` calls.
/// The body itself has no direct calls.
///
/// The two-word iterator holds a pointer to its current segment-map slot and
/// the current segment pointer. This post-increment first saves both words for
/// `result`, then skips zero segment entries by advancing the map slot one
/// target word at a time until it loads a nonzero segment pointer. Deliberate
/// deviations: none; target pointers remain `u32` words so their ARM layout
/// is preserved on 64-bit host test builds.
///
/// # Safety
///
/// `result` and `iterator` must each be valid for two aligned `u32` words.
/// Starting at `iterator[0]`, the segment-map slots must be readable through
/// the first slot containing a nonzero pointer. `result` may alias `iterator`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.segmented_iter_post_increment")]
#[inline(never)]
pub unsafe extern "C" fn segmented_iter_post_increment(result: *mut u32, iterator: *mut u32) {
    let saved_slot = iterator.read();
    let saved_segment = iterator.add(1).read();

    while iterator.add(1).read() == 0 {
        let next_slot = iterator.read().wrapping_add(4);
        iterator.write(next_slot);
        iterator.add(1).write((next_slot as usize as *const u32).read());
    }

    result.write(saved_slot);
    result.add(1).write(saved_segment);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::segmented_iter_post_increment;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const FIRST_SLOT_OFFSET: usize = 0x100;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SEGMENTED_ITER_POST_INCREMENT, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<*mut u32> {
        let base = (*FIXTURE)? as *mut u32;
        unsafe { core::ptr::write_bytes(base.cast::<u8>(), 0, FIXTURE_LEN) };
        Some(base)
    }

    fn lock() -> MutexGuard<'static, ()> {
        match FIXTURE_LOCK.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn returns_current_state_without_advancing_a_nonzero_segment() {
        let _lock = lock();
        let Some(base) = fixture() else {
            note_missing_u32_fixture("cxx::segmented_iter_post_increment");
            return;
        };
        let slot = unsafe { base.add(FIRST_SLOT_OFFSET / size_of::<u32>()) };
        let mut iterator = [slot as usize as u32, 0xfeed_face];
        let mut result = [0; 2];

        unsafe { segmented_iter_post_increment(result.as_mut_ptr(), iterator.as_mut_ptr()) };

        assert_eq!(result, [slot as usize as u32, 0xfeed_face]);
        assert_eq!(iterator, result);
    }

    #[test]
    fn skips_empty_slots_and_preserves_postincrement_result() {
        let _lock = lock();
        let Some(base) = fixture() else {
            note_missing_u32_fixture("cxx::segmented_iter_post_increment");
            return;
        };
        let slots = unsafe { base.add(FIRST_SLOT_OFFSET / size_of::<u32>()) };
        unsafe {
            slots.write(0);
            slots.add(1).write(0);
            slots.add(2).write(0x1234_5678);
        }
        let mut iterator = [slots as usize as u32, 0];
        let mut result = [0; 2];

        unsafe { segmented_iter_post_increment(result.as_mut_ptr(), iterator.as_mut_ptr()) };

        assert_eq!(result, [slots as usize as u32, 0]);
        assert_eq!(iterator, [unsafe { slots.add(2) } as usize as u32, 0x1234_5678]);
    }

    #[test]
    fn iterator_alias_result_restores_the_saved_state() {
        let _lock = lock();
        let Some(base) = fixture() else {
            note_missing_u32_fixture("cxx::segmented_iter_post_increment");
            return;
        };
        let slots = unsafe { base.add(FIRST_SLOT_OFFSET / size_of::<u32>()) };
        unsafe { slots.add(1).write(0x2468_ace0) };
        let mut iterator = [slots as usize as u32, 0];

        unsafe { segmented_iter_post_increment(iterator.as_mut_ptr(), iterator.as_mut_ptr()) };

        assert_eq!(iterator, [slots as usize as u32, 0]);
    }
}
