//! Object registration/removal diagnostic history.
//!
//! `record_object_activity` — FUN_0808ccc8 at 0x0808ccc8, true extent
//! [0x0808ccc8, 0x0808cd38): 112 bytes (104 code + 8 literal bytes).
//! Raw ARM decoding finds two inbound plain BLs, zero predicated BLs;
//! the body has one plain BL to read_usec_timer_into_2 and no predicated BLs.
//! Registration caller 0x0807fd9c supplies 1; removal caller 0x0808f838
//! supplies 0. Save the object's address, word +0x12c, and four words
//! +0x20..+0x2c in the current 32-byte record; store the low event byte,
//! sample Timer E, then advance the index, wrapping at 30.
//!
//! Deliberate deviations: host builds use backing storage instead of retail
//! RAM; object identity is truncated to the target's 32-bit pointer word.
//! Target builds preserve the RAM ring at 0x08a79e84 and index at 0x089cc8ac,
//! including volatile index reloads and leaving record bytes +0x1d..+0x1f
//! untouched. No added locking or validation.

#[cfg(not(target_os = "none"))]
static mut HOST_RECORDS: [[u32; 8]; 30] = [[0; 8]; 30];
#[cfg(not(target_os = "none"))]
static mut HOST_INDEX: u32 = 0;

#[inline(always)]
unsafe fn history_storage() -> (*mut u32, *mut u32) {
    #[cfg(target_os = "none")]
    { (0x08a7_9e84 as *mut u32, 0x089c_c8ac as *mut u32) }
    #[cfg(not(target_os = "none"))]
    { (core::ptr::addr_of_mut!(HOST_RECORDS).cast(), core::ptr::addr_of_mut!(HOST_INDEX)) }
}

/// Record one activity event. `object` must be word-aligned and readable
/// through byte +0x12f. The global index must be in 0..30; callers must
/// serialize access as retailOS does. `activity` contributes only its low byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_object_activity(object: *const u32, activity: u32) {
    let (records, index) = history_storage();
    let record = records.add((index.read_volatile() as usize).wrapping_mul(8));
    record.write_volatile(object as usize as u32);
    record.add(1).write_volatile(object.add(75).read_volatile());
    let geometry = [object.add(8).read_volatile(), object.add(9).read_volatile(),
                    object.add(10).read_volatile(), object.add(11).read_volatile()];
    record.add(2).write_volatile(geometry[0]);
    record.add(3).write_volatile(geometry[1]);
    record.add(4).write_volatile(geometry[2]);
    record.add(5).write_volatile(geometry[3]);
    let record = records.add((index.read_volatile() as usize).wrapping_mul(8));
    record.cast::<u8>().add(28).write_volatile(activity as u8);
    crate::drivers::timer::read_usec_timer_into_2(record.add(6));
    let next = index.read_volatile().wrapping_add(1);
    index.write_volatile(next);
    if next >= 30 {
        index.write_volatile(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_activity_and_overwrites_oldest_after_thirty_events() {
        let _guard = crate::drivers::timer::configure_usec_timer_for_test(u32::MAX, 1);
        unsafe {
            core::ptr::addr_of_mut!(HOST_RECORDS).write([[0xa5a5_a5a5; 8]; 30]);
            core::ptr::addr_of_mut!(HOST_INDEX).write(0);
            let mut object = [0xdead_beef; 76];
            object[8..12].copy_from_slice(&[0, u32::MAX, 0x8000_0000, 7]);
            object[75] = 0x1234_5678;
            for event in 0..31u32 {
                let activity = if event & 1 == 0 { 0x1234_5601 } else { 0x100 };
                record_object_activity(object.as_ptr(), activity);
                let (records, index) = history_storage();
                assert_eq!(index.read(), (event + 1) % 30);
                let slot = records.add((event as usize % 30) * 8);
                let expected = [object.as_ptr() as usize as u32, object[75], 0,
                    u32::MAX, 0x8000_0000, 7, u32::MAX.wrapping_add(event),
                    0xa5a5_a500 | (activity & 0xff)];
                for (word, value) in expected.iter().enumerate() {
                    assert_eq!(slot.add(word).read(), *value);
                }
                if event == 0 {
                    for word in 8..240 {
                        assert_eq!(records.add(word).read(), 0xa5a5_a5a5);
                    }
                }
            }
            let (records, _) = history_storage();
            assert_eq!(records.add(6).read(), 29);
            assert_eq!(records.add(8 + 6).read(), 0);
            assert_eq!(records.add(29 * 8 + 6).read(), 28);
        }
    }
}
