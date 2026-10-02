//! Preset coefficient refresh at 0x0827cac8: 212 bytes to the next function
//! at 0x0827cb9c (200 bytes of code, 12 bytes of literals). Two incoming
//! plain BLs, zero predicated incoming BLs; zero outgoing BLs.
//! For nonzero presets and rates 44100/48000, select the corresponding
//! firmware table, load three coefficient indices, and either bypass a
//! record (-1) or copy five coefficient words in the original permutation.
//! Set the owner's active byte only after all three records are updated.
//! Unsupported rates/zero presets clear only that byte. No validation or
//! behavioral deviations; native-pointer table injection is private test
//! support, while the exported ABI retains the original fixed addresses.

use core::ptr::{read_volatile, write_volatile};

/// Owner must be word-aligned and writable through offset 0xb7; its preset
/// and the firmware tables must describe valid coefficient indices.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn filter_preset_refresh(owner: *mut u32) {
    refresh(owner, 0x088feb54 as *const u32, 0x088fef8c as *const u32,
            0x088ff3c4 as *const u32);
}

#[inline(always)]
unsafe fn refresh(owner: *mut u32, rate_44100: *const u32,
                  rate_48000: *const u32, presets: *const u32) {
    let active = owner.cast::<u8>().add(8);
    if read_volatile(owner.add(0xb4 / 4)) == 0 {
        write_volatile(active, 0);
        return;
    }
    let coefficients = match read_volatile(owner.add(1)) {
        44100 => rate_44100,
        48000 => rate_48000,
        _ => core::ptr::null(),
    };
    if coefficients.is_null() {
        write_volatile(active, 0);
        return;
    }
    for band in 0..3usize {
        let preset = read_volatile(owner.add(0xb4 / 4));
        let index = read_volatile(presets.wrapping_add(preset.wrapping_mul(3) as usize + band));
        let record = owner.add(band * 14);
        let bypass = record.cast::<u8>().add(0x40);
        if index == u32::MAX {
            write_volatile(bypass, 1);
        } else {
            let source = coefficients.wrapping_add(index.wrapping_mul(5) as usize);
            write_volatile(record.add(5), read_volatile(source));
            write_volatile(record.add(6), read_volatile(source.add(1)));
            write_volatile(record.add(7), read_volatile(source.add(2)));
            write_volatile(record.add(3), read_volatile(source.add(3)));
            write_volatile(record.add(4), read_volatile(source.add(4)));
            write_volatile(bypass, 0);
        }
    }
    write_volatile(active, 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coefficient_permutation_bypass_and_untouched_history() {
        let tables: [[u32; 10]; 2] = [[11, 12, 13, 14, 15, 21, 22, 23, 24, 25],
                                    [31, 32, 33, 34, 35, 41, 42, 43, 44, 45]];
        for (rate, table) in [(44100, &tables[0]), (48000, &tables[1])] {
            for disabled in 0..3 {
                let mut owner = [0xa5a5a5a5u32; 48];
                owner[1] = rate;
                owner[45] = 1;
                let mut indices = [0, 0, 0, 1, 0, 1];
                indices[3 + disabled] = u32::MAX;
                let mut expected = owner;
                let bytes = unsafe { core::slice::from_raw_parts_mut(expected.as_mut_ptr().cast::<u8>(), 192) };
                bytes[8] = 1;
                for band in 0..3 {
                    bytes[band * 56 + 64] = (band == disabled) as u8;
                    if band != disabled {
                        let start = indices[3 + band] as usize * 5;
                        for (word, offset) in [20, 24, 28, 12, 16].into_iter().enumerate() {
                            bytes[band * 56 + offset..band * 56 + offset + 4]
                                .copy_from_slice(&table[start + word].to_ne_bytes());
                        }
                    }
                }
                unsafe { refresh(owner.as_mut_ptr(), tables[0].as_ptr(), tables[1].as_ptr(), indices.as_ptr()); }
                assert_eq!(owner, expected);
            }
        }
    }

    #[test]
    fn inactive_paths_touch_only_active_byte_without_table_access() {
        for (preset, rate, missing) in [(0, 44100, false), (1, 0, false),
                                      (1, 44101, false), (1, 48000, true),
                                      (1, 44100, true)] {
            let mut owner = [0xffffffffu32; 48];
            owner[1] = rate;
            owner[45] = preset;
            let mut expected = owner;
            expected[2] &= !0xff;
            let table = if missing { core::ptr::null() } else { 4 as *const u32 };
            unsafe { refresh(owner.as_mut_ptr(), table, table, core::ptr::null()); }
            assert_eq!(owner, expected);
        }
    }
}
