//! Publish a channel's selected two-slot record.
//!
//! `channel_slot_publish` — `FUN_0820c448` @ 0x0820c448, 96 bytes.
//! The next real function begins at 0x0820c4a8. Raw A32 words contain
//! zero plain or predicated outgoing BLs; whole-image decoding finds two
//! plain inbound BLs (0x081af9c4, 0x081afb14), zero predicated inbound BLs.
//! Read selector at base + channel*4, address the record at
//! base + channel*56 + selector*28, write four payload words, optionally
//! replace +12 when nonzero, publish byte state 3 at +8, then increment
//! the selector and reset it when its signed value is >= 2. Arguments
//! three and six are ignored by stock code. Payload word meanings and
//! concrete owner type remain unknown; no callee seam is needed.
//! Deliberate deviations: none. Word indices retain 32-bit target layout
//! on hosts; volatile accesses preserve stock store order and selector reread.

use core::ptr::{read_volatile, write_volatile};

/// # Safety
/// `base` must be word-aligned and cover the selector and selected record.
/// The selector must address a valid slot; accesses require the owner's
/// synchronization discipline. Payload words are opaque, not host pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn channel_slot_publish(
    base: *mut u32, channel: u32, _unused_third: u32, replacement: u32,
    payload_0: u32, _unused_sixth: u32, payload_1: u32,
    payload_2: u32, payload_3: u32,
) {
    let selector = base.add(channel as usize);
    let selected = read_volatile(selector);
    let record = base.add(channel.wrapping_mul(14).wrapping_add(selected.wrapping_mul(7)) as usize);
    write_volatile(record.add(4), payload_0);
    write_volatile(record.add(6), payload_1);
    write_volatile(record.add(7), payload_2);
    write_volatile(record.add(8), payload_3);
    if replacement != 0 {
        write_volatile(record.add(3), replacement);
    }
    write_volatile(record.add(2).cast::<u8>(), 3);
    write_volatile(selector, selected.wrapping_add(1));
    if (read_volatile(selector) as i32) >= 2 {
        write_volatile(selector, 0);
    }
}

/// Publish through the retailOS relocation veneer.
///
/// `FUN_08003858` @ 0x08003858, 8 bytes through the next veneer at
/// 0x08003860: raw words e51ff004 08201570 load PC from the literal.
/// Whole-image A32 decoding finds two plain inbound BLs (0x080060bc,
/// 0x08006558), zero predicated inbound BLs and zero outgoing BLs.
/// Startup's +0xaed8 relocation resolves runtime 0x08201570 to file
/// address 0x0820c448, the existing channel_slot_publish implementation.
/// Publish four payload words, optionally replace the record's +12 word,
/// set state 3, and advance the selected slot. Arguments three and six
/// are unused. Deliberate deviation: Rust forwards instead of loading PC;
/// the nine-argument C ABI preserves the veneer’s stack payload.
///
/// # Safety
/// The alignment, valid-slot and synchronization requirements of
/// `channel_slot_publish` apply unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn channel_slot_publish_veneer(
    base: *mut u32, channel: u32, unused_third: u32, replacement: u32,
    payload_0: u32, unused_sixth: u32, payload_1: u32,
    payload_2: u32, payload_3: u32,
) {
    channel_slot_publish(base, channel, unused_third, replacement,
        payload_0, unused_sixth, payload_1, payload_2, payload_3);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_record_fields_and_preserved_bytes() {
        for channel in 0..3usize {
            for selected in 0..2usize {
                for replacement in [0, 0x12345678] {
                    let mut actual = [0xa5b6c7d8u32; 48];
                    actual[channel] = selected as u32;
                    let mut expected = actual;
                    let record = channel * 14 + selected * 7;
                    expected[record + 4] = 0x10203040;
                    expected[record + 6] = 0x50607080;
                    expected[record + 7] = 0x90abcdef;
                    expected[record + 8] = 0xfedcba98;
                    if replacement != 0 { expected[record + 3] = replacement; }
                    expected[record + 2] = (expected[record + 2] & !0xff) | 3;
                    expected[channel] = (selected as u32 + 1) % 2;
                    unsafe {
                        channel_slot_publish(actual.as_mut_ptr(), channel as u32,
                            0xdeadbeef, replacement, 0x10203040, 0xbadf00d,
                            0x50607080, 0x90abcdef, 0xfedcba98);
                    }
                    assert_eq!(actual, expected, "channel={channel}, selected={selected}");
                }
            }
        }
    }

    #[test]
    fn repeated_publication_alternates_slots_and_retains_optional_word() {
        let mut words = [0u32; 24];
        unsafe {
            channel_slot_publish(words.as_mut_ptr(), 0, 0, 41, 11, 0, 12, 13, 14);
            assert_eq!(words[0], 1);
            channel_slot_publish(words.as_mut_ptr(), 0, 0, 42, 21, 0, 22, 23, 24);
            assert_eq!(words[0], 0);
            channel_slot_publish(words.as_mut_ptr(), 0, 0, 0, 31, 0, 32, 33, 34);
        }
        assert_eq!(words[0], 1);
        assert_eq!(words[3], 41);
        assert_eq!(words[10], 42);
        assert_eq!([words[4], words[6], words[7], words[8]], [31, 32, 33, 34]);
        assert_eq!([words[11], words[13], words[14], words[15]], [21, 22, 23, 24]);
        assert_eq!(words[2] as u8, 3);
        assert_eq!(words[9] as u8, 3);
    }

    #[test]
    fn veneer_preserves_record_on_zero_replacement_and_wraps_signed_selector() {
        // Selector 2 exercises the stock signed >= 2 reset, rather than
        // assuming only the usual alternating selectors zero and one.
        let mut words = [0xa5b6c7d8u32; 48];
        words[1] = 2;
        let record = 14 + 2 * 7;
        let mut expected = words;
        expected[record + 4] = 0x10203040;
        expected[record + 6] = 0x50607080;
        expected[record + 7] = 0x90abcdef;
        expected[record + 8] = 0xfedcba98;
        expected[record + 2] = (expected[record + 2] & !0xff) | 3;
        expected[1] = 0;
        unsafe {
            channel_slot_publish_veneer(words.as_mut_ptr(), 1, 0xdeadbeef, 0,
                0x10203040, 0xbadf00d, 0x50607080, 0x90abcdef, 0xfedcba98);
        }
        assert_eq!(words, expected);
    }
}
