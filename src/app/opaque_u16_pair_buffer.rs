//! opaque_u16_pair_buffer_append — original: `FUN_0826c8b8` @ `0x0826c8b8`
//! (**40 bytes**, `0x0826c8b8..0x0826c8e0`; the separately linked next
//! function begins with `add r0, r0, #4` at `0x0826c8e0`). **8 direct `bl`
//! call sites, all unconditional; no predicated `bl` or direct tail-branch**,
//! binary-scanned by decoding every ARM B/BL word in
//! `work/firmware/osos.dec`.
//!
//! The opaque 0xfb0-byte buffer has a 12-byte header, 1000 four-byte entries,
//! and an entry count at `+0xfac`. This appends the two supplied 16-bit values
//! to entry `count`, then increments that count with ARM's wrapping arithmetic.
//! The eight callers are one contiguous sequence, appending alternating
//! `(540, 200)` and `(676, 400)` pairs four times. There is no NULL or capacity
//! guard. No deliberate deviations.

/// One four-byte entry in [`OpaqueU16PairBuffer`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct U16Pair {
    pub first: u16,
    pub second: u16,
}

/// The recovered layout used by `opaque_u16_pair_buffer_append`.
///
/// The header's concrete contents are not needed by this routine. Its named
/// field fixes the pair array at target offset `+0x0c`; `entry_count` is at
/// `+0xfac` on both 32-bit firmware and native test hosts.
#[repr(C)]
pub struct OpaqueU16PairBuffer {
    pub header: [u8; 0x0c],
    pub entries: [U16Pair; 1000],
    pub entry_count: u32,
}

const _: [u8; 0x0c] = [0; core::mem::offset_of!(OpaqueU16PairBuffer, entries)];
const _: [u8; 0xfac] = [0; core::mem::offset_of!(OpaqueU16PairBuffer, entry_count)];
const _: [u8; 0xfb0] = [0; core::mem::size_of::<OpaqueU16PairBuffer>()];

/// opaque_u16_pair_buffer_append — original: `FUN_0826c8b8` @ `0x0826c8b8`
/// (40 bytes; 8 unconditional direct `bl` call sites, binary-scanned).
///
/// Appends `first` and `second` at the current entry count before incrementing
/// it. As in retailOS, callers must provide a non-NULL buffer with a valid
/// writable entry at the current count; this routine does not enforce capacity.
///
/// # Safety
///
/// `buffer` must be non-NULL and valid for a mutable [`OpaqueU16PairBuffer`],
/// including its `entries[entry_count]` slot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_u16_pair_buffer_append(
    buffer: *mut OpaqueU16PairBuffer,
    first: u16,
    second: u16,
) {
    let entry_count = (*buffer).entry_count;
    let entry = (*buffer).entries.as_mut_ptr().add(entry_count as usize);
    (*entry).first = first;
    (*entry).second = second;
    (*buffer).entry_count = entry_count.wrapping_add(1);
}

#[cfg(test)]
mod tests {
    use super::{opaque_u16_pair_buffer_append, OpaqueU16PairBuffer, U16Pair};

    fn buffer_with_count(entry_count: u32) -> OpaqueU16PairBuffer {
        OpaqueU16PairBuffer {
            header: [0xa5; 0x0c],
            entries: [U16Pair { first: 0xcccc, second: 0xdddd }; 1000],
            entry_count,
        }
    }

    #[test]
    fn appends_pair_at_first_slot_without_touching_header_or_next_slot() {
        let mut buffer = buffer_with_count(0);

        unsafe { opaque_u16_pair_buffer_append(&mut buffer, 0x021c, 200) };

        assert_eq!(buffer.header, [0xa5; 0x0c]);
        assert_eq!(buffer.entries[0], U16Pair { first: 0x021c, second: 200 });
        assert_eq!(buffer.entries[1], U16Pair { first: 0xcccc, second: 0xdddd });
        assert_eq!(buffer.entry_count, 1);
    }

    #[test]
    fn appends_at_current_slot_and_preserves_u16_bit_patterns() {
        let mut buffer = buffer_with_count(999);

        unsafe { opaque_u16_pair_buffer_append(&mut buffer, u16::MAX, 0x8000) };

        assert_eq!(buffer.entries[998], U16Pair { first: 0xcccc, second: 0xdddd });
        assert_eq!(buffer.entries[999], U16Pair { first: u16::MAX, second: 0x8000 });
        assert_eq!(buffer.entry_count, 1000);
    }
}
