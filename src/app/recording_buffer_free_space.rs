//! Sum unused bytes in the enabled recording buffer's slots.
//!
//! Port: [`recording_buffer_free_space`] — `FUN_08168164` @ `0x08168164`
//! (**64 bytes; zero plain or predicated BL instructions; two incoming plain
//! BL calls and no incoming predicated BL calls**). Raw ARM ends at `bx lr`
//! at `0x081681a0`; the next real prologue is at `0x081681a4`.
//!
//! Return zero if the byte at +0x1c is clear. Otherwise read the unsigned slot
//! count at +0x338 and sum `0x80000 - used` for slots whose used words start
//! at +0x38 with a twelve-byte stride. Subtraction and accumulation wrap at
//! 32 bits. The count is exclusive, even though other recording-buffer
//! routines use +0x338 as a pending marker or last slot index.
//!
//! Deliberate deviations: Rust uses a conventional loop instead of ARM's
//! predicated loop body. Volatile reads preserve the original read boundaries;
//! no validation, locking, saturation, or inclusive-count correction is added.

const ENABLED_OFFSET: usize = 0x1c;
const SLOT_COUNT_OFFSET: usize = 0x338;
const USED_OFFSET: usize = 0x38;
const SLOT_STRIDE: usize = 0xc;
const SLOT_CAPACITY: u32 = 0x80000;

/// `buffer` must be non-NULL. When enabled, it must be four-byte aligned and
/// contain the count word and every used word selected by that count.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.recording_buffer_free_space")]
pub unsafe extern "C" fn recording_buffer_free_space(buffer: *const u8) -> u32 {
    if core::ptr::read_volatile(buffer.add(ENABLED_OFFSET)) == 0 {
        return 0;
    }
    let count = core::ptr::read_volatile(buffer.add(SLOT_COUNT_OFFSET).cast::<u32>());
    let mut free = 0u32;
    for slot in 0..count {
        let offset = (slot as usize).wrapping_mul(SLOT_STRIDE).wrapping_add(USED_OFFSET);
        let used = core::ptr::read_volatile(buffer.wrapping_add(offset).cast::<u32>());
        free = free.wrapping_add(SLOT_CAPACITY.wrapping_sub(used));
    }
    free
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct Buffer([u32; 0x340 / 4]);

    fn check(enabled: u8, used: &[u32]) {
        let mut buffer = Buffer([0xa5a5_a5a5; 0x340 / 4]);
        let ptr = buffer.0.as_mut_ptr().cast::<u8>();
        unsafe { ptr.add(ENABLED_OFFSET).write(enabled) };
        buffer.0[SLOT_COUNT_OFFSET / 4] = used.len() as u32;
        for (slot, value) in used.iter().enumerate() {
            buffer.0[(USED_OFFSET + slot * SLOT_STRIDE) / 4] = *value;
        }
        let before = buffer.0;
        let expected = if enabled == 0 { 0 } else {
            ((used.len() as u64 * SLOT_CAPACITY as u64)
                .wrapping_sub(used.iter().map(|&v| v as u64).sum::<u64>())) as u32
        };
        assert_eq!(unsafe { recording_buffer_free_space(ptr) }, expected);
        assert_eq!(buffer.0, before);
    }

    #[test]
    fn disabled_reads_only_the_flag() {
        // No count word exists in this fixture: the disabled path must return first.
        let buffer = [0u8; ENABLED_OFFSET + 1];
        assert_eq!(unsafe { recording_buffer_free_space(buffer.as_ptr()) }, 0);
        check(0, &[0, SLOT_CAPACITY, u32::MAX]);
    }

    #[test]
    fn zero_count_and_non_boolean_enabled_flags() {
        for enabled in [1, 2, 0x80, 0xff] {
            check(enabled, &[]);
            check(enabled, &[0]);
        }
    }

    #[test]
    fn exclusive_count_stride_and_capacity_boundaries() {
        check(1, &[0, 1, SLOT_CAPACITY - 1, SLOT_CAPACITY]);
        check(1, &[SLOT_CAPACITY; 64]);
        check(1, &[0; 64]);
    }

    #[test]
    fn over_capacity_and_accumulation_wrap_like_arm() {
        check(1, &[SLOT_CAPACITY + 1]);
        check(1, &[u32::MAX, 0, 0x8000_0000, 0x8000_0000]);
        check(1, &[u32::MAX; 64]);
    }
}
