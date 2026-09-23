//! `fat_entry_write` — retailOS `FUN_0818d69c` at `0x0818d69c` (216 bytes;
//! `0x0818d69c..0x0818d773`). The push at `0x0818d774` begins the next real
//! function. Whole-image A32 decoding finds three inbound direct calls: two
//! plain `bl` at `0x0818d0a4` and `0x0818d0b4`, and one predicated `bleq` at
//! `0x0818d0cc`; it makes no outbound calls.
//!
//! # Algorithm
//!
//! Writes a FAT entry selected by `volume + 0x42c`: format 16 writes a
//! little-endian 16-bit value, format 32 clears value bits 31..28 then writes
//! four little-endian bytes, and every other format uses packed FAT12 nibbles.
//! The raw body has no NULL, bounds, or format validity guards.
//!
//! # Deliberate deviations
//!
//! None.

use core::ptr::{read, write};

const FORMAT_OFFSET: usize = 0x42c;
const TABLE_POINTER_OFFSET: usize = 0x458;

/// Writes one raw FAT table entry and returns one.
///
/// # Safety
///
/// `volume` must point to a target-layout volume through +0x458. Its +0x458
/// word must be a valid writable 32-bit target address for the selected entry.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fat_entry_write")]
#[inline(never)]
pub unsafe extern "C" fn fat_entry_write(volume: *mut u8, entry: u32, value: u32) -> u32 {
    let format = read(volume.add(FORMAT_OFFSET).cast::<u32>());
    let table = read(volume.add(TABLE_POINTER_OFFSET).cast::<u32>()) as usize as *mut u8;

    if format == 0x10 {
        let dst = table.add((entry * 2) as usize);
        write(dst, value as u8);
        write(dst.add(1), (value >> 8) as u8);
    } else if format == 0x20 {
        let dst = table.add((entry * 4) as usize);
        let value = value & 0x0fff_ffff;
        write(dst, value as u8);
        write(dst.add(1), (value >> 8) as u8);
        write(dst.add(2), (value >> 16) as u8);
        write(dst.add(3), (value >> 24) as u8);
    } else {
        let value = value & 0x0fff;
        let offset = ((entry * 3) / 2) as usize;
        let dst = table.add(offset);
        if entry & 1 == 0 {
            write(dst, value as u8);
            write(dst.add(1), (read(dst.add(1)) & 0xf0) | (value >> 8) as u8);
        } else {
            write(dst, (read(dst) & 0x0f) | (value << 4) as u8);
            write(dst.add(1), (value >> 4) as u8);
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::fat_entry_write;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const VOLUME_LEN: usize = 0x500;
    const TABLE_OFFSET: usize = 0x800;

    unsafe fn fixture() -> Option<(*mut u8, *mut u8)> {
        let slab = try_map_u32_slab(hints::FAT_ENTRY_WRITE, 0x1000)?;
        let table = slab.add(TABLE_OFFSET);
        slab.add(0x458).cast::<u32>().write(table as usize as u32);
        Some((slab, table))
    }

    #[test]
    fn writes_each_fat_width_and_preserves_fat12_neighbor_nibbles() {
        let Some((volume, table)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("fs/fat_entry_write");
            return;
        };

        unsafe {
            volume.add(0x42c).cast::<u32>().write(0x10);
            table.add(2).write(0xa5);
            table.add(3).write(0xa5);
            assert_eq!(fat_entry_write(volume, 1, 0x89ab_4567), 1);
            assert_eq!([table.add(2).read(), table.add(3).read()], [0x67, 0x45]);

            volume.add(0x42c).cast::<u32>().write(0x20);
            table.add(8).write(0xa5);
            table.add(9).write(0xa5);
            table.add(10).write(0xa5);
            table.add(11).write(0xa5);
            assert_eq!(fat_entry_write(volume, 2, 0xfabc_def0), 1);
            assert_eq!(
                [table.add(8).read(), table.add(9).read(), table.add(10).read(), table.add(11).read()],
                [0xf0, 0xde, 0xbc, 0x0a]
            );

            volume.add(0x42c).cast::<u32>().write(0x0c);
            table.add(3).write(0xa5);
            table.add(4).write(0x5a);
            table.add(5).write(0xa5);
            assert_eq!(fat_entry_write(volume, 2, 0x0abc), 1);
            assert_eq!([table.add(3).read(), table.add(4).read(), table.add(5).read()], [0xbc, 0x5a, 0xa5]);
            assert_eq!(fat_entry_write(volume, 3, 0x0cde), 1);
            assert_eq!([table.add(3).read(), table.add(4).read(), table.add(5).read()], [0xbc, 0xea, 0xcd]);
        }
    }
}
