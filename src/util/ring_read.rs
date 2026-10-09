//! Masked-ring byte reader — retailOS `FUN_080fe8f8`.
//!
//! Load address: `0x080fe8f8`; true size: 92 bytes (`0x5c`), ending with
//! `pop {r4,r5,r6,pc}` at `0x080fe950`; the next real function starts at
//! `0x080fe954`. Raw A32 decoding finds two plain inbound BL calls and zero
//! predicated calls, and one plain outbound BL to [`ring_buffer_used_bytes`].
//! Rejects lengths above the occupied count without changing the destination
//! or ring; otherwise copies bytes at the read cursor and advances it with
//! `& mask` after each byte. Preserves per-byte data/cursor/mask reloads and
//! the cursor reload after the destination store. No deliberate deviations.

use crate::util::ring_buffer_used_bytes::ring_buffer_used_bytes;

/// Reads exactly `length` bytes, returning one on success or zero if unavailable.
///
/// # Safety
///
/// `ring` addresses six aligned target-width words, with a u32 data pointer at
/// +4, capacity at +8, read cursor at +12, write cursor at +16, and mask at +20.
/// On success, its read cursor must be writable and each selected data byte
/// readable; `destination` must be writable for `length` bytes. Zero-length
/// reads do not access the data pointer or destination. Aliasing is permitted
/// only when every resulting pointer and selected index remains valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ring_read(ring: *mut u32, destination: *mut u8, length: u32) -> u32 {
    if length > ring_buffer_used_bytes(ring) {
        return 0;
    }
    for offset in 0..length {
        let data = ring.add(1).read_volatile() as usize as *const u8;
        let cursor = ring.add(3).read_volatile();
        destination.add(offset as usize).write_volatile(data.add(cursor as usize).read_volatile());
        let cursor = ring.add(3).read_volatile();
        let mask = ring.add(5).read_volatile();
        ring.add(3).write_volatile(cursor.wrapping_add(1) & mask);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::ring_read;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn matches_reference_for_all_small_ring_states_and_lengths() {
        let Some(slab) = (unsafe { try_map_u32_slab(hints::RING_READ, 0x1000) }) else {
            assert!(note_missing_u32_fixture("util::ring_read"));
            return;
        };
        unsafe {
            let data = slab.add(0x100);
            let source = [11u8, 23, 35, 47, 59, 71, 83, 95];
            core::ptr::copy_nonoverlapping(source.as_ptr(), data, source.len());
            for capacity in [0u32, 3, 8, u32::MAX] {
                for mask in [0u32, 5, 7] {
                    for read in 0..8u32 {
                        for write in 0..8u32 {
                            for length in 0..10u32 {
                                let mut ring = [0xa5a5_a5a5, data as usize as u32, capacity, read, write, mask];
                                let before = ring;
                                let mut output = [0xccu8; 12];
                                let mut expected = output;
                                let used = write.wrapping_sub(read).wrapping_add(capacity) & mask;
                                let mut cursor = read;
                                if length <= used {
                                    for offset in 0..length {
                                        expected[offset as usize + 1] = source[cursor as usize];
                                        cursor = cursor.wrapping_add(1) & mask;
                                    }
                                }
                                assert_eq!(ring_read(ring.as_mut_ptr(), output.as_mut_ptr().add(1), length),
                                    u32::from(length <= used));
                                assert_eq!(output, expected);
                                let mut expected_ring = before;
                                expected_ring[3] = cursor;
                                assert_eq!(ring, expected_ring);
                                assert_eq!(core::slice::from_raw_parts(data, 8), &source);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn empty_and_rejected_reads_do_not_touch_null_payload_or_destination() {
        let mut ring = [0x1234, 0, 8, 2, 2, 7];
        let before = ring;
        unsafe {
            assert_eq!(ring_read(ring.as_mut_ptr(), core::ptr::null_mut(), 0), 1);
            assert_eq!(ring_read(ring.as_mut_ptr(), core::ptr::null_mut(), 1), 0);
            assert_eq!(ring_read(ring.as_mut_ptr(), core::ptr::null_mut(), u32::MAX), 0);
        }
        assert_eq!(ring, before);
    }

    #[test]
    fn destination_aliasing_cursor_is_observed_before_advancing() {
        let Some(slab) = (unsafe { try_map_u32_slab(hints::RING_READ_ALIAS, 0x1000) }) else {
            assert!(note_missing_u32_fixture("util::ring_read::alias"));
            return;
        };
        unsafe {
            let data = slab.add(0x100);
            data.write(2);
            let mut ring = [0, data as usize as u32, 4, 0, 1, 3];
            let destination = ring.as_mut_ptr().add(3).cast::<u8>();
            assert_eq!(ring_read(ring.as_mut_ptr(), destination, 1), 1);
            assert_eq!(ring, [0, data as usize as u32, 4, 3, 1, 3]);
            assert_eq!(data.read(), 2);
        }
    }
}
