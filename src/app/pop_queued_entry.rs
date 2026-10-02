//! Pop the last contiguous queued entry — `FUN_0829cfc8` @ `0x0829cfc8`.
//!
//! True extent: 48 bytes, `0x0829cfc8..0x0829cff8`; the next function is
//! `active_slot_count`. Independent whole-image A32 decoding finds two inbound
//! plain BL calls (`0x080d213c`, `0x080d2168`), zero predicated BL calls, and
//! one outgoing plain BL (`0x0829cfd4` to `0x0829cff8`).
//! Counts the contiguous nonzero flags in four 20-byte slots. If nonempty,
//! clears only the last active slot's byte at +16 and returns its address;
//! otherwise returns NULL without writes. Payload and later slots are untouched.
//! Deliberate deviations: opaque byte layout preserves target stride on hosts;
//! LLVM branches instead of the original predicated arithmetic and store.

/// # Safety
/// `queue` must reference four readable 20-byte slots; active flag bytes must
/// be writable. No NULL check or synchronization is added.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pop_queued_entry(queue: *mut u8) -> *mut u8 {
    let count = crate::active_slot_count::active_slot_count(queue);
    if count == 0 {
        return core::ptr::null_mut();
    }
    let entry = queue.add((count as usize - 1) * 0x14);
    entry.add(0x10).write(0);
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pops_each_prefix_and_preserves_every_other_byte() {
        for count in 0..=4 {
            let mut slots = [0xa5u8; 80];
            for index in 0..4 {
                slots[index * 20 + 16] = if index < count { 0x80 + index as u8 } else { 0 };
            }
            let mut expected = slots;
            let base = slots.as_mut_ptr();
            let result = unsafe { pop_queued_entry(base) };
            if count == 0 {
                assert!(result.is_null());
            } else {
                assert_eq!(result, unsafe { base.add((count - 1) * 20) });
                expected[(count - 1) * 20 + 16] = 0;
            }
            assert_eq!(slots, expected);
        }
    }

    #[test]
    fn gap_stops_pop_without_consuming_later_active_slots() {
        let mut slots = [0x5au8; 80];
        slots[36] = 0;
        let mut expected = slots;
        expected[16] = 0;
        let base = slots.as_mut_ptr();
        assert_eq!(unsafe { pop_queued_entry(base) }, base);
        assert_eq!(slots, expected);
        assert!(unsafe { pop_queued_entry(base) }.is_null());
        assert_eq!(slots, expected);
    }

    #[test]
    fn full_queue_drains_in_reverse_order_then_stays_empty() {
        let mut slots = [0xffu8; 80];
        let base = slots.as_mut_ptr();
        for index in (0..4).rev() {
            assert_eq!(unsafe { pop_queued_entry(base) }, unsafe { base.add(index * 20) });
            assert_eq!(slots[index * 20 + 16], 0);
        }
        let empty = slots;
        assert!(unsafe { pop_queued_entry(base) }.is_null());
        assert_eq!(slots, empty);
    }
}
