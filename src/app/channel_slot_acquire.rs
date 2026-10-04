//! Acquire a channel's selected two-slot record.
//!
//! `channel_slot_acquire` — `FUN_0820c3f0` @ 0x0820c3f0, 88 bytes:
//! 80 instruction bytes and two literal words; next function at 0x0820c448.
//! Raw A32 decoding verifies zero outgoing plain/predicated BLs and two
//! incoming plain BLs (0x081af964, 0x081af9ec), no predicated incoming BLs.
//! Read selector at base + channel*4 and record at base + channel*56 +
//! selector*28. When preserve is zero, install 0x08adc7a8 for selector zero
//! or 0x08ae07a8 otherwise at +12. Copy that word to the output, set byte
//! state at +8 to 2, and return zero without advancing the selector.
//! Deliberate deviations: none. Volatile accesses retain the otherwise
//! unused initial state-byte read and store order, including output aliasing.
//! Word indices preserve target layout; buffer addresses remain opaque u32s.

use core::ptr::{read_volatile, write_volatile};

/// # Safety
/// `base` must be word-aligned and cover the selector and selected record;
/// `output` must be writable and word-aligned. The selector must address a
/// valid record. Accesses require the owner's synchronization discipline.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn channel_slot_acquire(
    base: *mut u32, channel: u32, output: *mut u32, preserve: u32,
) -> u32 {
    let selected = read_volatile(base.add(channel as usize));
    let record = base.add(channel.wrapping_mul(14).wrapping_add(selected.wrapping_mul(7)) as usize);
    let _ = read_volatile(record.add(2).cast::<u8>());
    if preserve == 0 {
        write_volatile(record.add(3), if selected == 0 { 0x08adc7a8 } else { 0x08ae07a8 });
    }
    write_volatile(output, read_volatile(record.add(3)));
    write_volatile(record.add(2).cast::<u8>(), 2);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_slot_reset_or_preserve_without_advancing() {
        for channel in 0..3usize {
            for selected in 0..2usize {
                for preserve in [0, 1, u32::MAX] {
                    let mut actual = [0xa5b6c7d8u32; 48];
                    actual[channel] = selected as u32;
                    let mut expected = actual;
                    let record = channel * 14 + selected * 7;
                    let address = if preserve != 0 { expected[record + 3] }
                        else if selected == 0 { 0x08adc7a8 } else { 0x08ae07a8 };
                    expected[record + 3] = address;
                    expected[record + 2] = (expected[record + 2] & !0xff) | 2;
                    let mut output = 0;
                    let status = unsafe {
                        channel_slot_acquire(actual.as_mut_ptr(), channel as u32, &mut output, preserve)
                    };
                    assert_eq!(status, 0);
                    assert_eq!(output, address);
                    assert_eq!(actual, expected, "channel={channel}, selected={selected}, preserve={preserve}");
                }
            }
        }
    }

    #[test]
    fn output_aliases_state_word_before_byte_publication() {
        let mut words = [0xaabbccdd; 24];
        words[0] = 1;
        words[10] = 0x12345678;
        unsafe {
            let base = words.as_mut_ptr();
            assert_eq!(channel_slot_acquire(base, 0, base.add(9), 1), 0);
        }
        assert_eq!(words[9], 0x12345602);
        assert_eq!(words[10], 0x12345678);
        assert_eq!(words[0], 1);
    }

    #[test]
    fn aliased_selector_does_not_change_selected_record() {
        let mut words = [0u32; 24];
        words[0] = 1;
        words[10] = 0x10203040;
        unsafe {
            let base = words.as_mut_ptr();
            assert_eq!(channel_slot_acquire(base, 0, base, 1), 0);
        }
        assert_eq!(words[0], 0x10203040);
        assert_eq!(words[9], 2);
        assert_eq!(words[2], 0);
    }
}
