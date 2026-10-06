//! Byte-ring dequeue — retailOS `FUN_08165938` @ 0x08165938.
//!
//! True extent: 40 bytes, 0x08165938..0x08165960; the next function
//! begins with `mov r2,r1` and writes the ring. Raw A32 decoding finds
//! two plain incoming BLs (0x080cc2dc, 0x080cc300), zero predicated
//! incoming BLs, and zero outgoing plain or predicated BLs.
//! Increment the read cursor at +4, fetch the byte at +8 + old cursor,
//! then reset the cursor if the increment's low ten bits are zero.
//! The caller 0x080cc298 checks byte_ring_is_empty before dequeuing.
//! No deliberate behavioral deviations; volatile accesses preserve the
//! original store/load/reset ordering. No empty or range checks.

/// Consume one byte from the fixed-capacity retailOS byte ring.
///
/// # Safety
/// `ring` must address aligned, readable/writable u32 cursor words at
/// +0/+4 and a readable byte at +8 + the current read cursor. The caller
/// owns synchronization and must check availability if required.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_ring_read(ring: *mut u32) -> u32 {
    let cursor = ring.add(1);
    let read = cursor.read_volatile();
    let next = read.wrapping_add(1);
    cursor.write_volatile(next);
    let byte = ring.cast::<u8>().add(8 + read as usize).read_volatile();
    if next & 0x3ff == 0 {
        cursor.write_volatile(0);
    }
    byte as u32
}

#[cfg(test)]
mod tests {
    use super::byte_ring_read;
    use crate::app::byte_ring_is_empty;

    #[repr(C)]
    struct Ring {
        write: u32,
        read: u32,
        data: [u8; 3072],
    }

    fn fixture(read: u32, write: u32) -> Ring {
        let mut ring = Ring { write, read, data: [0; 3072] };
        for (i, byte) in ring.data.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(0x80);
        }
        ring
    }

    #[test]
    fn every_valid_cursor_returns_unsigned_byte_and_advances() {
        for read in 0..1024 {
            let mut ring = fixture(read, 731);
            let payload = ring.data;
            let expected = payload[read as usize] as u32;
            assert_eq!(unsafe { byte_ring_read(&mut ring.write) }, expected);
            assert_eq!(ring.read, (read + 1) % 1024);
            assert_eq!(ring.write, 731);
            assert_eq!(ring.data, payload);
        }
    }

    #[test]
    fn unchecked_empty_read_and_out_of_range_cursor_match_stock() {
        for read in [0, 1023, 1024, 2046, 2047] {
            let mut ring = fixture(read, read);
            let expected = ring.data[read as usize] as u32;
            assert_eq!(unsafe { byte_ring_read(&mut ring.write) }, expected);
            let next = read + 1;
            assert_eq!(ring.read, if next & 1023 == 0 { 0 } else { next });
            assert_eq!(ring.write, read);
        }
    }

    #[test]
    fn consumer_drains_across_wrap_then_observes_empty() {
        let mut ring = fixture(1023, 1);
        ring.data[1023] = 0xaa;
        ring.data[0] = 1;
        unsafe {
            assert_eq!(byte_ring_is_empty(&ring.write), 0);
            assert_eq!(byte_ring_read(&mut ring.write), 0xaa);
            assert_eq!(ring.read, 0);
            assert_eq!(byte_ring_is_empty(&ring.write), 0);
            assert_eq!(byte_ring_read(&mut ring.write), 1);
            assert_eq!(byte_ring_is_empty(&ring.write), 1);
        }
    }
}
