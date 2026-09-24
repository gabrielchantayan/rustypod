//! Masked-ring byte writer — retailOS `FUN_080fe954`.
//!
//! Load address: `0x080fe954`; true size: 152 bytes (`0x98`), from `push
//! {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}` at `0x080fe9e8`. The next real
//! function begins at `0x080fe9ec`. Raw A32 decoding finds three inbound `bl`
//! call sites, all plain and none predicated; the body has one plain outbound
//! `bl`, to [`ring_buffer_used_bytes`]. It optionally rejects a nonempty ring,
//! then rejects a write larger than `mask - used`, copies bytes at the write
//! cursor, and advances that cursor with `& mask`. No deliberate deviations.

use crate::util::ring_buffer_used_bytes::ring_buffer_used_bytes;

/// Writes `length` bytes into a masked retailOS ring.
///
/// # Safety
///
/// `ring` must point to six readable target-width words: data pointer at +4,
/// capacity at +8, read cursor at +12, write cursor at +16, and mask at +20.
/// The data pointer must address a writable ring allocation selected by `mask`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ring_write(
    ring: *mut u32,
    source: *const u8,
    length: u32,
    require_empty: u32,
) -> u32 {
    if require_empty != 0 && ring_buffer_used_bytes(ring) != 0 {
        return 0;
    }

    let write = ring.add(4).read_volatile();
    let read = ring.add(3).read_volatile();
    let capacity = ring.add(2).read_volatile();
    let mask = ring.add(5).read_volatile();
    let used = write.wrapping_sub(read).wrapping_add(capacity) & mask;
    if length > mask.wrapping_sub(used) {
        return 0;
    }

    let data = ring.add(1).read_volatile() as usize as *mut u8;
    let mut cursor = write;
    for offset in 0..length {
        data.add(cursor as usize).write_volatile(source.add(offset as usize).read_volatile());
        cursor = cursor.wrapping_add(1) & mask;
        ring.add(4).write_volatile(cursor);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::ring_write;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    unsafe fn fixture() -> Option<(*mut u32, *mut u8)> {
        let slab = try_map_u32_slab(hints::RING_WRITE, 0x1000)?;
        slab.write_bytes(0xa5, 0x1000);
        let ring = slab.cast::<u32>();
        let data = slab.add(0x100);
        ring.add(1).write(data as usize as u32);
        ring.add(2).write(8);
        ring.add(5).write(7);
        Some((ring, data))
    }

    #[test]
    fn writes_across_the_mask_and_advances_the_cursor() {
        let Some((ring, data)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util::ring_write"));
            return;
        };
        unsafe {
            ring.add(3).write(2);
            ring.add(4).write(6);
            assert_eq!(ring_write(ring, b"xyz".as_ptr(), 3, 0), 1);
            assert_eq!([data.add(6).read(), data.add(7).read(), data.read()], *b"xyz");
            assert_eq!(ring.add(4).read(), 1);
        }
    }

    #[test]
    fn rejects_nonempty_ring_when_empty_is_required() {
        let Some((ring, data)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util::ring_write"));
            return;
        };
        unsafe {
            ring.add(3).write(1);
            ring.add(4).write(2);
            assert_eq!(ring_write(ring, b"q".as_ptr(), 1, 1), 0);
            assert_eq!(data.add(2).read(), 0xa5);
            assert_eq!(ring.add(4).read(), 2);
        }
    }

    #[test]
    fn rejects_a_write_larger_than_remaining_capacity() {
        let Some((ring, data)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util::ring_write"));
            return;
        };
        unsafe {
            ring.add(3).write(2);
            ring.add(4).write(6);
            assert_eq!(ring_write(ring, b"wxyz".as_ptr(), 4, 0), 0);
            assert_eq!(data.add(6).read(), 0xa5);
            assert_eq!(ring.add(4).read(), 6);
        }
    }
}
