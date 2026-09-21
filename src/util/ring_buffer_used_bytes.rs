//! Ring-buffer occupied byte count — retailOS `FUN_08297608`.
//!
//! Load address: `0x08297608`; true size: 32 bytes (`0x20`), from the first
//! `ldr r1,[r0,#0x10]` through `bx lr` at `0x08297624`. The next independently
//! linked function starts at `0x08297638`; the intervening words are two
//! unreferenced `mov r0,#0; bx lr` stubs. Raw A32 branch decoding finds three
//! inbound plain `bl` call sites and zero predicated `bl` call sites; this leaf
//! has no outbound calls. It computes `(write - read + capacity) & mask` from
//! the ring's words at +0x10, +0x0c, +0x08, and +0x14 respectively. No
//! deliberate deviations.

/// Returns the number of occupied bytes in a masked ring buffer.
///
/// # Safety
///
/// `ring` must point to an aligned retailOS ring record readable through word
/// offset 5. The record uses 32-bit target words, independent of host pointer
/// width.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ring_buffer_used_bytes(ring: *const u32) -> u32 {
    let write = ring.add(4).read_volatile();
    let read = ring.add(3).read_volatile();
    let used_before_wrap = write.wrapping_sub(read);
    let capacity = ring.add(2).read_volatile();
    let mask = ring.add(5).read_volatile();

    used_before_wrap.wrapping_add(capacity) & mask
}

#[cfg(test)]
mod tests {
    use super::ring_buffer_used_bytes;

    fn used_bytes(capacity: u32, read: u32, write: u32, mask: u32) -> u32 {
        let mut ring = [0u32; 6];
        ring[2] = capacity;
        ring[3] = read;
        ring[4] = write;
        ring[5] = mask;
        unsafe { ring_buffer_used_bytes(ring.as_ptr()) }
    }

    #[test]
    fn reports_distance_when_write_is_ahead() {
        assert_eq!(used_bytes(0x100, 0x20, 0x70, 0xff), 0x50);
    }

    #[test]
    fn wraps_read_past_write_at_capacity() {
        assert_eq!(used_bytes(0x100, 0xe0, 0x20, 0xff), 0x40);
    }

    #[test]
    fn adds_capacity_before_applying_the_mask() {
        assert_eq!(used_bytes(0x100, 0x44, 0x44, u32::MAX), 0x100);
    }

    #[test]
    fn arithmetic_wraps_before_the_mask() {
        assert_eq!(used_bytes(0x8000_0000, 0xffff_fff0, 0x10, 0xffff_ffff), 0x8000_0020);
    }
}
