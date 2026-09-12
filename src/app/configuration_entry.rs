//! Fixed configuration-entry initialization used by the eight-entry setup table.
//!
//! `configuration_entry_initialize` — retailOS `FUN_0824cac0` at
//! `0x0824cac0` (**164 bytes, `0x0824cac0..0x0824cb64`**). The raw
//! `osos.dec` extent is 41 ARM words ending in `pop {r4-r11,pc}` at
//! `0x0824cb60`; the next independently linked function begins at
//! `0x0824cb64`. Independently decoding every ARM B/BL immediate in the
//! firmware finds eight direct callers, all unconditional `bl` instructions
//! in `FUN_082ab6c0` (`0x082ab75c`, `0x082ab7f8`, `0x082ab88c`,
//! `0x082ab924`, `0x082ab9b0`, `0x082aba48`, `0x082abadc`, and
//! `0x082abb78`); this leaf contains no calls.
//!
//! # Algorithm
//!
//! Copies 25 caller-supplied 32-bit configuration fields into a 104-byte
//! entry at offsets `0x00..=0x60`, then writes the two selector bytes at
//! offsets `0x64` and `0x65`. Store order follows the ARM body, including its
//! delayed write of field 12 after fields 13 through 16. The remaining two
//! bytes of the entry are caller-owned padding. The destination is a raw byte
//! pointer so the host's 64-bit pointer width cannot alter the retail ARM
//! entry layout; it must still be four-byte aligned for the word stores.

/// Complete size of a retailOS configuration entry, including its two
/// caller-owned padding bytes.
pub const CONFIGURATION_ENTRY_SIZE: usize = 0x68;

/// Initialize one fixed-layout configuration entry.
///
/// # Safety
///
/// `entry` must be non-null, four-byte aligned, and point to at least
/// `CONFIGURATION_ENTRY_SIZE` writable bytes. The original performs no
/// validation and writes every specified field with volatile ARM stores.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn configuration_entry_initialize(
    entry: *mut u8,
    primary_selector: u8,
    secondary_selector: u8,
    field_00: u32,
    field_01: u32,
    field_02: u32,
    field_03: u32,
    field_04: u32,
    field_05: u32,
    field_06: u32,
    field_07: u32,
    field_08: u32,
    field_09: u32,
    field_10: u32,
    field_11: u32,
    field_12: u32,
    field_13: u32,
    field_14: u32,
    field_15: u32,
    field_16: u32,
    field_17: u32,
    field_18: u32,
    field_19: u32,
    field_20: u32,
    field_21: u32,
    field_22: u32,
    field_23: u32,
    field_24: u32,
) {
    unsafe {
        let words = entry.cast::<u32>();
        words.add(0).write_volatile(field_00);
        words.add(1).write_volatile(field_01);
        words.add(2).write_volatile(field_02);
        words.add(3).write_volatile(field_03);
        words.add(4).write_volatile(field_04);
        words.add(5).write_volatile(field_05);
        words.add(6).write_volatile(field_06);
        words.add(7).write_volatile(field_07);
        words.add(8).write_volatile(field_08);
        words.add(9).write_volatile(field_09);
        words.add(10).write_volatile(field_10);
        words.add(11).write_volatile(field_11);
        words.add(13).write_volatile(field_13);
        words.add(14).write_volatile(field_14);
        words.add(15).write_volatile(field_15);
        words.add(16).write_volatile(field_16);
        words.add(12).write_volatile(field_12);
        words.add(17).write_volatile(field_17);
        words.add(18).write_volatile(field_18);
        words.add(19).write_volatile(field_19);
        words.add(20).write_volatile(field_20);
        words.add(21).write_volatile(field_21);
        words.add(22).write_volatile(field_22);
        words.add(23).write_volatile(field_23);
        words.add(24).write_volatile(field_24);
        entry.add(0x64).write_volatile(primary_selector);
        entry.add(0x65).write_volatile(secondary_selector);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const GUARD: u8 = 0xa5;

    #[test]
    fn writes_all_configuration_fields_and_only_the_two_selector_bytes() {
        let mut storage = [GUARD; CONFIGURATION_ENTRY_SIZE + 8];
        let entry = unsafe { storage.as_mut_ptr().add(4) };
        let expected = [
            0x0000_0010, 0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444,
            0x5555_5555, 0x6666_6666, 0x7777_7777, 0x8888_8888, 0x9999_9999,
            0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc, 0xdddd_dddd, 0xeeee_eeee,
            0xffff_ffff, 0x1357_9bdf, 0x2468_ace0, 0x0102_0304, 0x1020_3040,
            0x5566_7788, 0x89ab_cdef, 0x0bad_c0de, 0xc001_d00d, 0xfeed_face,
        ];

        unsafe {
            configuration_entry_initialize(
                entry, 6, 1, expected[0], expected[1], expected[2], expected[3],
                expected[4], expected[5], expected[6], expected[7], expected[8],
                expected[9], expected[10], expected[11], expected[12], expected[13],
                expected[14], expected[15], expected[16], expected[17], expected[18],
                expected[19], expected[20], expected[21], expected[22], expected[23],
                expected[24],
            );

            for (index, value) in expected.into_iter().enumerate() {
                assert_eq!((entry.cast::<u32>().add(index)).read_volatile(), value);
            }
        }
        assert_eq!(storage[4 + 0x64], 6);
        assert_eq!(storage[4 + 0x65], 1);
        assert_eq!(&storage[..4], &[GUARD; 4]);
        assert_eq!(&storage[4 + 0x66..4 + CONFIGURATION_ENTRY_SIZE], &[GUARD; 2]);
        assert_eq!(&storage[4 + CONFIGURATION_ENTRY_SIZE..], &[GUARD; 4]);
    }
}
