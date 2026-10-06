use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// Release the current audio buffer — `FUN_081680a4` @ 0x081680a4.
/// True extent: 72 bytes, ending before the prologue at 0x081680ec.
/// Verified calls: two inbound plain BLs, zero predicated BLs; the body
/// has one plain BL to mutex_lock and a tail branch to mutex_unlock.
/// Under the mutex at +0x14, clear the current record's length at
/// +0x38+12*read_index, reload/increment +0x334, and wrap to zero only
/// when the increment exceeds the inclusive last index at +0x338.
/// Deviations: volatile word accesses retain the firmware's reload/store
/// order; the tail branch is expressed as a return-position Rust call.
///
/// # Safety
/// `ring` must be word-aligned, contain the control words and selected
/// record, and hold a valid native-layout Mutex at +0x14. Address arithmetic
/// wraps at 32 bits as on the target; indices are not validated.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn audio_buffer_ring_release(ring: *mut u32) {
    let mutex = ring.add(5).cast::<Mutex>();
    mutex_lock(mutex);
    let index = ring.add(0x334 / 4);
    let record_offset = index.read_volatile().wrapping_mul(12).wrapping_add(0x38);
    ring.cast::<u8>().wrapping_add(record_offset as usize).cast::<u32>().write_volatile(0);
    let next = index.read_volatile().wrapping_add(1);
    index.write_volatile(next);
    if next > ring.add(0x338 / 4).read_volatile() {
        index.write_volatile(0);
    }
    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_only_current_length_and_wraps_at_inclusive_limit() {
        // Base +4 puts the mutex at +0x14 on native pointer alignment,
        // without changing the target's four-byte control/record spacing.
        for (index, last, expected_index) in [
            (0u32, 0u32, 0u32), (0, 63, 1), (62, 63, 63),
            (63, 63, 0), (1, 0, 0), (1, u32::MAX, 2),
            (u32::MAX, u32::MAX, 0),
        ] {
            let mut storage = [0u64; 106];
            let ring = unsafe { storage.as_mut_ptr().cast::<u32>().add(1) };
            let words = unsafe { core::slice::from_raw_parts_mut(ring, 0x33c / 4) };
            for (i, word) in words.iter_mut().enumerate() {
                *word = 0x1234_0000 + i as u32;
            }
            unsafe { ring.add(5).cast::<Mutex>().write(Mutex {
                sem_cell: core::ptr::null_mut(), unused: 0,
            }); }
            words[0x334 / 4] = index;
            words[0x338 / 4] = last;
            let mut expected = words.to_vec();
            let length_word = index.wrapping_mul(12).wrapping_add(0x38) / 4;
            expected[length_word as usize] = 0;
            expected[0x334 / 4] = expected_index;
            unsafe { audio_buffer_ring_release(ring); }
            assert_eq!(words, expected.as_slice(), "index={index}, last={last}");
        }
    }
}
