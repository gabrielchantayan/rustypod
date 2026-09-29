//! FAT directory-entry volume-information writer.
//!
//! `fat_dirent_write_volume_info` — retailOS `FUN_082e1390` at load address
//! **0x082e1390**, 184 bytes (46 ARM words; `pop {pc}` at 0x082e1444 ends the
//! body and the next separately entered function starts at 0x082e1448).
//! Decoding every ARM B/BL word in `osos.dec` finds two direct callers, both
//! plain `bl` (0x082e1a1c and 0x082e4704), with no predicated calls or tail
//! branches.
//!
//! The function copies selected FAT short-directory-entry metadata into the
//! 48-byte volume-information record. It derives mode bits from the entry
//! attributes, copies the file size and timestamps, reads the two sector counts
//! from the target-width volume pointer at entry +0x2c, and rounds file size up
//! to 512-byte sectors. Deliberate deviation: source and destination remain raw
//! byte pointers instead of claiming complete higher-level layouts; all observed
//! ARM offsets and the target-width pointer field are preserved.

const ENTRY_VOLUME_OFFSET: usize = 0x2c;
const VOLUME_DATA_SECTORS_OFFSET: usize = 0x64;
const VOLUME_TOTAL_SECTORS_OFFSET: usize = 0x78;

#[inline(always)]
unsafe fn read_u16(base: *const u8, offset: usize) -> u16 {
    base.add(offset).cast::<u16>().read()
}

#[inline(always)]
unsafe fn write_u16(base: *mut u8, offset: usize, value: u16) {
    base.add(offset).cast::<u16>().write(value);
}

/// Writes a FAT short directory entry's resident volume-information record.
///
/// `entry` must be readable through +0x2f and its +0x2c word must name a
/// readable volume through +0x79. `output` must name a writable 48-byte record.
/// The retail body has no NULL checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fat_dirent_write_volume_info(entry: *const u8, output: *mut u8) {
    let file_size = entry.add(0x1c).cast::<u32>().read();
    let attributes = entry.add(0x0b).read();
    let mut mode = if attributes & 1 == 0 { 0x180 } else { 0x80 };
    if attributes & 0x10 != 0 {
        mode |= 0x4000;
    }
    if attributes & 0x18 == 0 {
        mode |= 0x8000;
    }

    output.cast::<u32>().write(file_size);
    output.add(4).cast::<u32>().write(0);
    output.add(8).cast::<u32>().write(mode);
    output.add(0x2c).write(attributes);
    output.add(0x0c).cast::<u32>().write(1);
    output.add(0x10).cast::<u32>().write(file_size);
    output.add(0x14).cast::<u32>().write(entry.add(0x1c).cast::<u32>().read());
    write_u16(output, 0x20, read_u16(entry, 0x10));
    write_u16(output, 0x22, read_u16(entry, 0x0e));
    write_u16(output, 0x18, read_u16(entry, 0x12));
    write_u16(output, 0x1a, 0);
    write_u16(output, 0x1c, read_u16(entry, 0x18));
    write_u16(output, 0x1e, read_u16(entry, 0x16));

    let volume = entry.add(ENTRY_VOLUME_OFFSET).cast::<u32>().read() as usize as *const u8;
    output.add(0x24).cast::<u32>().write(read_u16(volume, VOLUME_DATA_SECTORS_OFFSET) as u32);
    output.add(0x28).cast::<u32>().write(file_size.wrapping_add(0x1ff) >> 9);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    const SLAB_LEN: usize = 0x1000;
    const ENTRY_OFFSET: usize = 0x100;
    const VOLUME_OFFSET: usize = 0x300;
    const OUTPUT_OFFSET: usize = 0x500;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SLAB: Option<usize> = None;

    unsafe fn slab() -> Option<*mut u8> {
        if SLAB.is_none() {
            SLAB = try_map_u32_slab(hints::FAT_DIRENT_VOLUME_INFO, SLAB_LEN).map(|base| base as usize);
        }
        SLAB.map(|base| base as *mut u8)
    }

    unsafe fn fixture() -> Option<(*mut u8, *mut u8)> {
        let slab = slab()?;
        slab.write_bytes(0, SLAB_LEN);
        let entry = slab.add(ENTRY_OFFSET);
        let volume = slab.add(VOLUME_OFFSET);
        entry.add(ENTRY_VOLUME_OFFSET).cast::<u32>().write(volume as usize as u32);
        Some((entry, slab.add(OUTPUT_OFFSET)))
    }

    fn reference(entry: &[u8; 48], volume: &[u8; 0x80], mut output: [u8; 48]) -> [u8; 48] {
        let read16 = |bytes: &[u8], offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let file_size = u32::from_le_bytes(entry[0x1c..0x20].try_into().unwrap());
        let attributes = entry[0x0b];
        let mut mode: u32 = if attributes & 1 == 0 { 0x180 } else { 0x80 };
        if attributes & 0x10 != 0 { mode |= 0x4000; }
        if attributes & 0x18 == 0 { mode |= 0x8000; }
        output[0..4].copy_from_slice(&file_size.to_le_bytes());
        output[4..8].fill(0);
        output[8..12].copy_from_slice(&mode.to_le_bytes());
        output[0x0c..0x10].copy_from_slice(&1u32.to_le_bytes());
        output[0x10..0x14].copy_from_slice(&file_size.to_le_bytes());
        output[0x14..0x18].copy_from_slice(&file_size.to_le_bytes());
        for (source, destination) in [(0x10, 0x20), (0x0e, 0x22), (0x12, 0x18), (0x18, 0x1c), (0x16, 0x1e)] {
            output[destination..destination + 2].copy_from_slice(&read16(entry, source).to_le_bytes());
        }
        output[0x1a..0x1c].fill(0);
        output[0x24..0x28].copy_from_slice(&(read16(volume, 0x64) as u32).to_le_bytes());
        output[0x28..0x2c].copy_from_slice(&file_size.wrapping_add(0x1ff).wrapping_shr(9).to_le_bytes());
        output[0x2c] = attributes;
        output
    }

    #[test]
    fn copies_metadata_and_sector_counts_for_a_directory_entry() {
        let _guard = TEST_LOCK.lock();
        let Some((entry, output)) = (unsafe { fixture() }) else { return };
        let mut entry_bytes = [0u8; 48];
        entry_bytes[0x0b] = 0x10;
        entry_bytes[0x0e..0x10].copy_from_slice(&0x1234u16.to_le_bytes());
        entry_bytes[0x10..0x12].copy_from_slice(&0x5678u16.to_le_bytes());
        entry_bytes[0x12..0x14].copy_from_slice(&0x9abcu16.to_le_bytes());
        entry_bytes[0x16..0x18].copy_from_slice(&0xdef0u16.to_le_bytes());
        entry_bytes[0x18..0x1a].copy_from_slice(&0x1357u16.to_le_bytes());
        entry_bytes[0x1c..0x20].copy_from_slice(&513u32.to_le_bytes());
        let mut volume_bytes = [0u8; 0x80];
        volume_bytes[0x64..0x66].copy_from_slice(&0x2468u16.to_le_bytes());
        unsafe {
            entry.copy_from_nonoverlapping(entry_bytes.as_ptr(), entry_bytes.len());
            entry.add(ENTRY_VOLUME_OFFSET).cast::<u32>().write(entry.add(0x200) as usize as u32);
            entry.add(0x200).copy_from_nonoverlapping(volume_bytes.as_ptr(), volume_bytes.len());
            output.write_bytes(0xa5, 48);
            let expected = reference(&entry_bytes, &volume_bytes, [0xa5; 48]);
            fat_dirent_write_volume_info(entry, output);
            assert_eq!(core::slice::from_raw_parts(output, 48), expected);
        }
    }

    #[test]
    fn mode_bits_and_sector_rounding_cover_attribute_and_overflow_edges() {
        let _guard = TEST_LOCK.lock();
        let Some((entry, output)) = (unsafe { fixture() }) else { return };
        for (attributes, file_size, expected_mode, expected_sectors) in [
            (0x00, 0u32, 0x8180, 0),
            (0x01, 512, 0x8080, 1),
            (0x18, 513, 0x4180, 2),
            (0x11, u32::MAX, 0x4080, 0),
        ] {
            unsafe {
                entry.write_bytes(0, 48);
                entry.add(0x0b).write(attributes);
                entry.add(0x1c).cast::<u32>().write(file_size);
                entry.add(ENTRY_VOLUME_OFFSET).cast::<u32>().write(entry.add(0x200) as usize as u32);
                entry.add(0x200).write_bytes(0, 0x80);
                output.write_bytes(0, 48);
                fat_dirent_write_volume_info(entry, output);
                assert_eq!(output.add(8).cast::<u32>().read(), expected_mode);
                assert_eq!(output.add(0x28).cast::<u32>().read(), expected_sectors);
            }
        }
    }
}
