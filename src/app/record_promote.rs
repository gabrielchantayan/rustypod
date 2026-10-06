//! Stable promotion of an eight-byte record within an indexed collection.

/// Target prefix: header +0, count +4, tracked index +8, records +12.
/// Native pointers widen only the final slot in host fixtures.
#[repr(C)]
pub struct RecordCollection {
    pub header: u32,
    pub count: i32,
    pub tracked_index: i32,
    pub records: *mut [u32; 2],
}

/// retailOS `FUN_0815f290` @ 0x0815f290: 100 bytes, ending before
/// the independent push at 0x0815f2f4. Raw A32 decoding verifies two
/// incoming plain BLs (0x0815f448, 0x0815f684), one outgoing plain BL
/// (0x0815f2c0 to 0x08037f70), and zero predicated BLs in either set.
///
/// Save the source record, shift [destination, source) one record right
/// through the established IRAM memmove veneer, then store the saved pair.
/// A tracked source follows the moved record; a tracked index in the shifted
/// interval increments. Comparisons are signed, including sentinel indices.
/// Count and header are untouched (the insertion caller increments count).
/// No deliberate target deviations; host fixtures use a native pointer.
///
/// # Safety
/// `collection` must be writable and its records must be aligned, readable
/// and writable through `source`. Require 0 <= destination <= source and
/// an eight-byte shift length representable in the target address space.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_promote(
    collection: *mut RecordCollection,
    source: i32,
    destination: i32,
) {
    let records = (*collection).records;
    let saved = *records.add(source as usize);
    crate::libc::iram_veneers::iram_memmove_veneer(
        records.add(destination as usize + 1).cast(),
        records.add(destination as usize).cast(),
        source.wrapping_sub(destination).wrapping_mul(8) as u32 as usize,
    );
    *(*collection).records.add(destination as usize) = saved;
    let tracked = (*collection).tracked_index;
    if tracked == source {
        (*collection).tracked_index = destination;
    } else if tracked < source && tracked >= destination {
        (*collection).tracked_index = tracked.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_rotation_and_signed_tracking_boundaries() {
        let original = core::array::from_fn::<_, 12, _>(|i|
            [0x8123_0000 + i as u32, 0xfedc_0000 + i as u32 * 17]);
        for source in 0..10 {
            for destination in 0..=source {
                for tracked in [-1, i32::MIN, 0, destination - 1, destination,
                                source - 1, source, source + 1, i32::MAX] {
                    let mut records = original;
                    let mut expected = original;
                    expected[destination as usize..=source as usize].rotate_right(1);
                    let mut collection = RecordCollection {
                        header: 0xaabbccdd, count: 10, tracked_index: tracked,
                        records: records.as_mut_ptr(),
                    };
                    unsafe { record_promote(&mut collection, source, destination); }
                    assert_eq!(records, expected);
                    let expected_index = if tracked == source { destination }
                        else if (destination..source).contains(&tracked) { tracked + 1 }
                        else { tracked };
                    assert_eq!(collection.tracked_index, expected_index);
                    assert_eq!((collection.header, collection.count), (0xaabbccdd, 10));
                    assert_eq!(collection.records, records.as_mut_ptr());
                }
            }
        }
    }
}
