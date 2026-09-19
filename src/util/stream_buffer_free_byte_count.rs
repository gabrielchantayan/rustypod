//! Stream-buffer free capacity — `thunk_EXT_FUN_22006f10` @ 0x080380b8.
//!
//! The reported four-byte thunk is an eight-byte `ldr pc,[pc,#-4]` veneer whose
//! `0x22006f10` target is the IRAM mirror of the 48-byte osos body at
//! `0x08006f10`. The body compares the stream buffer's write and read offsets:
//! when write is ahead, free capacity is `capacity - (write - read)`; otherwise
//! it is `read - write`, with equal offsets denoting a completely free buffer.
//! It stores that byte count through `free_byte_count` and returns zero. There
//! are four verified direct callers: four unconditional `bl` instructions and
//! zero predicated `bl` instructions. No deliberate deviations.

/// stream_buffer_free_byte_count — original: `thunk_EXT_FUN_22006f10` @
/// `0x080380b8` (8-byte veneer) → body `FUN_08006f10` @ `0x08006f10` (48 bytes).
///
/// Stores the ring buffer's currently free byte capacity and returns zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_free_byte_count(
    stream_buffer: *const u8,
    free_byte_count: *mut u32,
) -> u32 {
    const READ_OFFSET: usize = 0x08;
    const WRITE_OFFSET: usize = 0x0c;
    const CAPACITY_OFFSET: usize = 0x24;

    let read_offset = stream_buffer.add(READ_OFFSET).cast::<u32>().read_volatile();
    let write_offset = stream_buffer.add(WRITE_OFFSET).cast::<u32>().read_volatile();
    let free_bytes = if write_offset > read_offset {
        stream_buffer
            .add(CAPACITY_OFFSET)
            .cast::<u32>()
            .read_volatile()
            .wrapping_sub(write_offset.wrapping_sub(read_offset))
    } else if write_offset < read_offset {
        read_offset.wrapping_sub(write_offset)
    } else {
        stream_buffer.add(CAPACITY_OFFSET).cast::<u32>().read_volatile()
    };

    free_byte_count.write_volatile(free_bytes);
    0
}

#[cfg(test)]
mod tests {
    use super::stream_buffer_free_byte_count;

    const READ_OFFSET: usize = 0x08;
    const WRITE_OFFSET: usize = 0x0c;
    const CAPACITY_OFFSET: usize = 0x24;

    #[repr(align(4))]
    struct StreamBuffer([u8; 0x28]);

    impl StreamBuffer {
        fn write_word(&mut self, offset: usize, value: u32) {
            unsafe { self.0.as_mut_ptr().add(offset).cast::<u32>().write(value) };
        }
    }

    fn free_bytes(read_offset: u32, write_offset: u32, capacity: u32) -> u32 {
        let mut stream_buffer = StreamBuffer([0xa5; 0x28]);
        stream_buffer.write_word(READ_OFFSET, read_offset);
        stream_buffer.write_word(WRITE_OFFSET, write_offset);
        stream_buffer.write_word(CAPACITY_OFFSET, capacity);
        let mut free_byte_count = 0;

        assert_eq!(
            unsafe {
                stream_buffer_free_byte_count(
                    stream_buffer.0.as_ptr(),
                    core::ptr::addr_of_mut!(free_byte_count),
                )
            },
            0
        );
        free_byte_count
    }

    #[test]
    fn equal_offsets_report_full_capacity() {
        assert_eq!(free_bytes(0x80, 0x80, 0x400), 0x400);
    }

    #[test]
    fn write_offset_ahead_subtracts_occupied_bytes_from_capacity() {
        assert_eq!(free_bytes(0x100, 0x280, 0x400), 0x280);
    }

    #[test]
    fn read_offset_ahead_reports_direct_distance() {
        assert_eq!(free_bytes(0x280, 0x100, 0x400), 0x180);
    }

    #[test]
    fn offset_subtraction_wraps_like_arm_register_arithmetic() {
        assert_eq!(free_bytes(0xffff_fff0, 0x10, 0x100), 0xffff_ffe0);
        assert_eq!(free_bytes(0x10, 0xffff_fff0, 0x100), 0x120);
    }
}
