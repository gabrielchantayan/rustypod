//! ATA command-block builders — the reset, the LBA packers/unpacker and
//! the hot setters of the family @ 0x0812120c..0x08121488.
//!
//! The storage layer builds every disk command in a 0x58-byte command
//! block. Twenty-three near-identical builders @ 0x082794xx..0x0827b1xx
//! (one per ATA command the firmware issues) reset a block and then poke
//! it field by field through a family of tiny out-of-line accessors.
//! Watching those builders recovers the layout:
//!
//! ```text
//! +0x0c u8   transfer protocol   1 in all 22 data-transfer builders,
//!                                5 in the two non-data ones
//! +0x10 u32  flag word           0x1000/0x1080/0x2000/0x2080/0x40000/
//!                                0x41000/0x42000/0x80000 ... — a bit set
//! +0x14 u8   feature register     (0xD5 for one SMART builder)
//! +0x15 u8   sector count
//! +0x16..+0x19  legacy taskfile: LBA low/mid/high, device+head
//! +0x1a u8   command register     (0xC8 = READ DMA in the read flow)
//! +0x1c u16, +0x1e u8            (opaque)
//! +0x20 i8   device index, -1 = none; the builders fill it from
//!            `ldrsb [dev, #8]` @ 0x08105a2c — a SIGNED byte
//! +0x24 u32  timeout, milliseconds (10000 for data, 30000 non-data)
//! +0x28 ptr  transfer buffer object
//! +0x2c u32  offset into that buffer
//! +0x30 u32  transfer length, bytes (sectors * bytes-per-sector)
//! +0x34 u32  block size, bytes — reset to 512
//! +0x38..+0x44                    (opaque words)
//! +0x48/+0x49/+0x4a u8            (opaque; +0x48/+0x49 set as a pair)
//! +0x4c..+0x56 u16  the extended (LBA48) taskfile register pairs
//! ```
//!
//! The two non-trivial members that address the medium:
//!
//! - `ata_cmd_set_lba28` — `FUN_0812141c` @ 0x0812141c (84 bytes;
//!   7 call sites, binary-scanned, callers @ 0x082799c8..0x0827a800).
//!   Validates lba < 2^28 and drive <= 1, then stores the legacy
//!   taskfile block: LBA bytes 0..2 at +0x16/+0x17/+0x18 and the
//!   device/head byte at +0x19 = 0x40 (LBA bit) | drive<<4 | lba[24:27].
//!   Returns 0, or 0xffffffff on a range violation.
//! - `ata_cmd_set_lba48` — `FUN_0812134c` @ 0x0812134c (96 bytes;
//!   8 call sites, binary-scanned, callers @ 0x0827a2f4..0x0827b09c).
//!   Stores the 48-bit extended taskfile as three (current | previous
//!   << 8) register pairs — +0x4c = lba[0] | lba[3]<<8, +0x4e = lba[1]
//!   | lba[4]<<8, +0x50 = lba[2] | lba[5]<<8, where the 48-bit LBA is
//!   passed split as `lba_hi` (bits 32..47) and `lba_lo` (bits 0..31) —
//!   plus the sector-count pair at +0x52, the command byte at +0x1a and
//!   the device byte at +0x56 = (0x40 | drive<<4) & 0xff (stored as a
//!   halfword, high byte 0). No validation, no return value.
//!
//! - `ata_cmd_get_lba48` — `FUN_081212e8` @ 0x081212e8 (76 bytes;
//!   1 call site). The exact inverse of the packer: reassembles the
//!   48-bit LBA out of the three register pairs and writes it to two
//!   out-parameters, high 16 bits first (r1), low 32 bits second (r2) —
//!   the same `(hi, lo)` split the packer takes.
//!
//! Deviations:
//!
//! - The original `ata_cmd_set_lba48` reaches its 16-bit fields with
//!   `strh` (which needs a 2-byte-aligned block); the port uses
//!   `write_unaligned`, identical for every pointer the original
//!   supported. `ata_cmd_reset` and `ata_cmd_get_lba48` instead take the
//!   aligned volatile path, because that is what reproduces their
//!   originals: an unaligned read lowers to two `ldrb`s, and a plain
//!   zero run lowers to `__aeabi_memclr`. The alignment they rely on is
//!   free — both functions also issue word `str`/`ldr`s, so every block
//!   the originals accepted was 4-byte aligned already. Field order of
//!   stores is preserved only where observable (it is not — all fields
//!   are distinct).
//! - Offsets are literal byte offsets into a `*mut u8`, the
//!   `drivers/surface.rs` precedent. The block does hold one pointer
//!   (+0x28, the transfer buffer), but no function ported here ever
//!   stores a pointer in it: `ata_cmd_reset` writes it as the same
//!   32-bit zero the original does, and the +0x28 setter @ 0x08121480 is
//!   deliberately left unported for exactly that reason.

/// +0x0c: the protocol every data-transfer builder selects.
pub const PROTOCOL_DATA: u8 = 1;
/// +0x0c: the protocol the two non-data builders select.
pub const PROTOCOL_NON_DATA: u8 = 5;

/// +0x20 after a reset: no device selected (stored as 0xff, read back
/// signed by the consumers).
pub const DEVICE_NONE: u8 = 0xff;

/// +0x34 after a reset: one ATA sector.
pub const DEFAULT_BLOCK_SIZE: u32 = 512;

const PROTOCOL: usize = 0x0c;
const FLAGS: usize = 0x10;
const FEATURE: usize = 0x14;
const SECTOR_COUNT: usize = 0x15;
const LBA_LOW: usize = 0x16;
const LBA_MID: usize = 0x17;
const LBA_HIGH: usize = 0x18;
const DEVICE_HEAD: usize = 0x19;
const COMMAND: usize = 0x1a;
const OPAQUE_HALF_1C: usize = 0x1c;
const OPAQUE_BYTE_1E: usize = 0x1e;
const DEVICE_INDEX: usize = 0x20;
const TIMEOUT_MS: usize = 0x24;
const BUFFER: usize = 0x28;
const BUFFER_OFFSET: usize = 0x2c;
const TRANSFER_LEN: usize = 0x30;
const BLOCK_SIZE: usize = 0x34;
const OPAQUE_WORD_38: usize = 0x38;
const OPAQUE_WORD_3C: usize = 0x3c;
const OPAQUE_WORD_40: usize = 0x40;
const OPAQUE_WORD_44: usize = 0x44;
const OPAQUE_BYTE_48: usize = 0x48;
const OPAQUE_BYTE_49: usize = 0x49;
const OPAQUE_BYTE_4A: usize = 0x4a;
const EXT_LBA_LOW: usize = 0x4c;
const EXT_LBA_MID: usize = 0x4e;
const EXT_LBA_HIGH: usize = 0x50;
const EXT_SECTOR_COUNT: usize = 0x52;
const EXT_OPAQUE_54: usize = 0x54;
const EXT_DEVICE: usize = 0x56;

#[inline(always)]
unsafe fn set_byte(cmd: *mut u8, offset: usize, value: u8) {
    cmd.add(offset).write_volatile(value);
}

#[inline(always)]
unsafe fn set_word(cmd: *mut u8, offset: usize, value: u32) {
    (cmd.add(offset) as *mut u32).write_volatile(value);
}

#[inline(always)]
unsafe fn set_half(cmd: *mut u8, offset: usize, value: u16) {
    (cmd.add(offset) as *mut u16).write_unaligned(value);
}

/// Volatile halfword zero for [`ata_cmd_reset`]. Its six trailing
/// `strh #0` stores are otherwise collapsed by LLVM's memset idiom
/// recognition into a call to `__aeabi_memclr`, a symbol that does not
/// exist here (the `drivers/surface.rs` trap — confirmed by reading the
/// ARM disassembly). Aligned like the original's `strh`, which is free:
/// reset's own `str` stores already require a 4-byte-aligned block.
#[inline(always)]
unsafe fn zero_half(cmd: *mut u8, offset: usize) {
    (cmd.add(offset) as *mut u16).write_volatile(0);
}

/// Aligned volatile halfword read for [`ata_cmd_get_lba48`]. An
/// unaligned read lowers to a pair of `ldrb`s on ARMv5 — same answer,
/// twice the instructions; the original's `ldrh` is what this
/// reproduces, and the alignment it needs is already guaranteed by the
/// `str` stores every block in this family receives.
#[inline(always)]
unsafe fn half(cmd: *const u8, offset: usize) -> u16 {
    (cmd.add(offset) as *const u16).read_volatile()
}

/// ata_cmd_reset — original: `FUN_0812120c` @ 0x0812120c (136 bytes;
/// 1 tail-`b` call site @ 0x08166078, and missing from
/// `decomp/functions.csv` entirely — recovered by decoding the branch).
///
/// Returns a command block to its empty state: everything zero except
/// the device index (+0x20 = [`DEVICE_NONE`]) and the block size
/// (+0x34 = [`DEFAULT_BLOCK_SIZE`]). Those two defaults are what make
/// the block usable before a builder has touched it — an unset device
/// reads back as -1 rather than "drive 0", and a command that never
/// states a block size transfers whole sectors.
///
/// The gaps are as deliberate as the stores: bytes +0x00..+0x0b,
/// +0x0d..+0x0f, +0x1b, +0x1f..+0x23, +0x4b and the extended device
/// halfword's neighbours are never written (the tests pin this).
///
/// The stores are `write_volatile` for the `drivers/surface.rs` reason:
/// plain writes let LLVM's memset idiom recognition collapse the zero
/// run into a call to `__aeabi_memclr`, a symbol that does not exist
/// here.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_reset(cmd: *mut u8) {
    set_byte(cmd, PROTOCOL, 0);
    set_word(cmd, FLAGS, 0);
    set_byte(cmd, DEVICE_INDEX, DEVICE_NONE);
    set_word(cmd, TIMEOUT_MS, 0);
    set_word(cmd, BUFFER, 0);
    set_word(cmd, BUFFER_OFFSET, 0);
    set_word(cmd, TRANSFER_LEN, 0);
    set_word(cmd, OPAQUE_WORD_38, 0);
    set_word(cmd, OPAQUE_WORD_3C, 0);
    set_word(cmd, OPAQUE_WORD_40, 0);
    set_word(cmd, OPAQUE_WORD_44, 0);
    set_byte(cmd, OPAQUE_BYTE_48, 0);
    set_byte(cmd, OPAQUE_BYTE_49, 0);
    set_word(cmd, BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
    set_byte(cmd, OPAQUE_BYTE_4A, 0);
    zero_half(cmd, OPAQUE_HALF_1C);
    set_byte(cmd, OPAQUE_BYTE_1E, 0);
    set_byte(cmd, FEATURE, 0);
    set_byte(cmd, SECTOR_COUNT, 0);
    set_byte(cmd, LBA_LOW, 0);
    set_byte(cmd, LBA_MID, 0);
    set_byte(cmd, LBA_HIGH, 0);
    set_byte(cmd, DEVICE_HEAD, 0);
    set_byte(cmd, COMMAND, 0);
    zero_half(cmd, EXT_LBA_LOW);
    zero_half(cmd, EXT_LBA_MID);
    zero_half(cmd, EXT_LBA_HIGH);
    zero_half(cmd, EXT_SECTOR_COUNT);
    zero_half(cmd, EXT_OPAQUE_54);
    zero_half(cmd, EXT_DEVICE);
}

/// ata_cmd_set_protocol — original: `FUN_08121488` @ 0x08121488
/// (8 bytes; **24 call sites**, binary-scanned — the busiest member of
/// the family).
///
/// Selects how the command moves its data: [`PROTOCOL_DATA`] in all 22
/// data-transfer builders, [`PROTOCOL_NON_DATA`] in the two that only
/// issue a command (both of which also skip the buffer, length and
/// count setters and ask for a 30-second timeout).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_protocol(cmd: *mut u8, protocol: u8) {
    set_byte(cmd, PROTOCOL, protocol);
}

/// ata_cmd_set_device — original: `FUN_081213ec` @ 0x081213ec (8 bytes;
/// 23 call sites, binary-scanned).
///
/// Stores which attached device the command is for. Every builder feeds
/// it the signed byte at device+8 (`ldrsb` @ 0x08105a2c), so the value
/// is an index whose "none" is -1 — the [`DEVICE_NONE`] byte
/// [`ata_cmd_reset`] leaves behind. The store itself is a plain `strb`,
/// so the port takes a `u8`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_device(cmd: *mut u8, device: u8) {
    set_byte(cmd, DEVICE_INDEX, device);
}

/// ata_cmd_set_timeout_ms — original: `FUN_081212c0` @ 0x081212c0
/// (8 bytes; 23 call sites, binary-scanned).
///
/// How long the command may take. Observed values: 10000 ms in every
/// data-transfer builder, 30000 ms in the non-data ones.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_timeout_ms(cmd: *mut u8, timeout_ms: u32) {
    set_word(cmd, TIMEOUT_MS, timeout_ms);
}

/// ata_cmd_set_flags — original: `FUN_08121414` @ 0x08121414 (8 bytes;
/// 19 call sites, binary-scanned).
///
/// The command's flag word. A bit set, not an enum: the builders load
/// 0x1000, 0x1080, 0x2000, 0x2080, 0x40000, 0x41000 and 0x42000 as
/// rotated immediates, and 0x08283474 ORs 0x80000 into a value it
/// already holds.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_flags(cmd: *mut u8, flags: u32) {
    set_word(cmd, FLAGS, flags);
}

/// ata_cmd_set_command — original: `FUN_081211bc` @ 0x081211bc (8
/// bytes; 16 call sites, binary-scanned).
///
/// The ATA command register (+0x1a). The read-DMA flow @ 0x082798bc
/// stores 0xC8 (READ DMA) here. [`ata_cmd_set_lba48`] writes the same
/// byte itself, which is why only the LBA28 flows need this setter.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_command(cmd: *mut u8, command: u8) {
    set_byte(cmd, COMMAND, command);
}

/// ata_cmd_get_lba48 — original: `FUN_081212e8` @ 0x081212e8 (76 bytes;
/// 1 call site).
///
/// Reads back the 48-bit LBA [`ata_cmd_set_lba48`] packed into the
/// extended taskfile, undoing the (current | previous << 8) interleave:
/// `*lba_hi` gets bits 32..47, `*lba_lo` bits 0..31. The two out-
/// parameters are in the original's register order (r1 = high, r2 =
/// low), matching the packer's argument order.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_get_lba48(cmd: *const u8, lba_hi: *mut u32, lba_lo: *mut u32) {
    let low_pair = half(cmd, EXT_LBA_LOW) as u32;
    let mid_pair = half(cmd, EXT_LBA_MID) as u32;
    let high_pair = half(cmd, EXT_LBA_HIGH) as u32;

    // Current registers are the low bytes, previous registers the high.
    lba_lo.write_volatile(
        (low_pair & 0xff)
            | (mid_pair & 0xff) << 8
            | (high_pair & 0xff) << 16
            | (low_pair & 0xff00) << 16,
    );
    lba_hi.write_volatile((high_pair & 0xff00) | (mid_pair & 0xff00) >> 8);
}

/// ata_cmd_set_lba28 — original: `FUN_0812141c` @ 0x0812141c (84 bytes).
///
/// Stores a 28-bit LBA + drive select into the command block's legacy
/// taskfile bytes (+0x16..+0x19). Fails with 0xffffffff if `lba` has
/// any of bits 28..31 set or `drive` is not 0/1.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_lba28(cmd: *mut u8, lba: u32, drive: u32) -> u32 {
    if lba & 0xf000_0000 != 0 || drive > 1 {
        return 0xffff_ffff;
    }
    set_byte(cmd, LBA_LOW, lba as u8);
    set_byte(cmd, LBA_MID, (lba >> 8) as u8);
    set_byte(cmd, LBA_HIGH, (lba >> 16) as u8);
    set_byte(cmd, DEVICE_HEAD, (0x40 | (drive as u8) << 4) | (lba >> 24) as u8 & 0xf);
    0
}

/// ata_cmd_set_lba48 — original: `FUN_0812134c` @ 0x0812134c (96 bytes).
///
/// Stores a 48-bit LBA (`lba_hi` = bits 32..47, `lba_lo` = bits 0..31),
/// sector count, command byte and device select into the command
/// block's extended taskfile pairs (+0x4c..+0x56, +0x1a). Each 16-bit
/// pair holds (current-register byte | previous-register byte << 8).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_lba48(
    cmd: *mut u8,
    lba_hi: u32,
    lba_lo: u32,
    drive: u32,
    count: u32,
    command: u8,
) {
    let pair = |cur: u32, prev: u32| -> u16 { (cur & 0xff | prev << 8) as u16 };
    set_half(cmd, EXT_LBA_LOW, pair(lba_lo, lba_lo >> 24));
    set_half(cmd, EXT_LBA_MID, pair(lba_lo >> 8, lba_hi));
    set_half(cmd, EXT_LBA_HIGH, (lba_lo >> 16 & 0xff | lba_hi & 0xff00) as u16);
    set_half(cmd, EXT_SECTOR_COUNT, count as u16);
    set_byte(cmd, COMMAND, command);
    set_half(cmd, EXT_DEVICE, ((0x40 | drive << 4) & 0xff) as u16);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lba28_packs_bytes_and_device_head() {
        let mut cmd = [0u8; 0x60];
        let r = unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0x0abc_def1, 1) };
        assert_eq!(r, 0);
        assert_eq!(cmd[0x16], 0xf1);
        assert_eq!(cmd[0x17], 0xde);
        assert_eq!(cmd[0x18], 0xbc);
        assert_eq!(cmd[0x19], 0x40 | 0x10 | 0x0a, "LBA bit | drive 1 | lba[24:27]");
    }

    #[test]
    fn lba28_rejects_out_of_range_lba_and_drive() {
        let mut cmd = [0xaau8; 0x60];
        assert_eq!(unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0x1000_0000, 0) }, 0xffff_ffff);
        assert_eq!(unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0xffff_ffff, 0) }, 0xffff_ffff);
        assert_eq!(unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0, 2) }, 0xffff_ffff);
        assert_eq!(cmd, [0xaau8; 0x60], "failed call must not touch the block");
    }

    #[test]
    fn lba28_boundary_values_pass() {
        let mut cmd = [0u8; 0x60];
        assert_eq!(unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0x0fff_ffff, 0) }, 0);
        assert_eq!(cmd[0x16..0x1a], [0xff, 0xff, 0xff, 0x4f]);
        assert_eq!(unsafe { ata_cmd_set_lba28(cmd.as_mut_ptr(), 0, 0) }, 0);
        assert_eq!(cmd[0x16..0x1a], [0, 0, 0, 0x40]);
    }

    #[test]
    fn lba48_packs_current_previous_register_pairs() {
        let mut cmd = [0u8; 0x60];
        // 48-bit LBA 0x1122_33445566, count 0xBEEF, drive 1, cmd 0x25.
        unsafe { ata_cmd_set_lba48(cmd.as_mut_ptr(), 0x1122, 0x3344_5566, 1, 0xbeef, 0x25) };
        let rd = |o: usize| u16::from_le_bytes([cmd[o], cmd[o + 1]]);
        assert_eq!(rd(0x4c), 0x3366, "lba_low: cur=lba[0] prev=lba[3]");
        assert_eq!(rd(0x4e), 0x2255, "lba_mid: cur=lba[1] prev=lba[4]");
        assert_eq!(rd(0x50), 0x1144, "lba_high: cur=lba[2] prev=lba[5]");
        assert_eq!(rd(0x52), 0xbeef, "sector count pair");
        assert_eq!(cmd[0x1a], 0x25, "command byte");
        assert_eq!(rd(0x56), 0x0050, "device: 0x40 | drive<<4, high byte 0");
    }

    #[test]
    fn lba48_masks_drive_into_one_byte() {
        let mut cmd = [0u8; 0x60];
        unsafe { ata_cmd_set_lba48(cmd.as_mut_ptr(), 0, 0, 0xffff_ffff, 0, 0) };
        let dev = u16::from_le_bytes([cmd[0x56], cmd[0x57]]);
        // (0x40 | 0xfffffff0) & 0xff = 0xf0.
        assert_eq!(dev, 0x00f0);
    }

    /// A poisoned, word-aligned command block (the original's `str`
    /// stores need 4-byte alignment; every caller passes one).
    #[repr(align(4))]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Block([u8; 0x58]);

    fn poisoned() -> Block {
        Block([0xa5; 0x58])
    }

    fn word_at(block: &Block, offset: usize) -> u32 {
        u32::from_le_bytes(block.0[offset..offset + 4].try_into().unwrap())
    }

    // ---- reset -----------------------------------------------------------

    #[test]
    fn reset_installs_the_two_nonzero_defaults() {
        let mut block = poisoned();
        unsafe { ata_cmd_reset(block.0.as_mut_ptr()) };
        assert_eq!(block.0[DEVICE_INDEX], DEVICE_NONE, "no device");
        assert_eq!(word_at(&block, BLOCK_SIZE), DEFAULT_BLOCK_SIZE);
    }

    #[test]
    fn reset_zeroes_every_other_field_it_owns() {
        let mut block = poisoned();
        unsafe { ata_cmd_reset(block.0.as_mut_ptr()) };
        for offset in [
            PROTOCOL,
            FEATURE,
            SECTOR_COUNT,
            LBA_LOW,
            LBA_MID,
            LBA_HIGH,
            DEVICE_HEAD,
            COMMAND,
            OPAQUE_BYTE_1E,
            OPAQUE_BYTE_48,
            OPAQUE_BYTE_49,
            OPAQUE_BYTE_4A,
        ] {
            assert_eq!(block.0[offset], 0, "byte +{offset:#x}");
        }
        for offset in [
            FLAGS,
            TIMEOUT_MS,
            BUFFER,
            BUFFER_OFFSET,
            TRANSFER_LEN,
            OPAQUE_WORD_38,
            OPAQUE_WORD_3C,
            OPAQUE_WORD_40,
            OPAQUE_WORD_44,
        ] {
            assert_eq!(word_at(&block, offset), 0, "word +{offset:#x}");
        }
        for offset in [
            OPAQUE_HALF_1C,
            EXT_LBA_LOW,
            EXT_LBA_MID,
            EXT_LBA_HIGH,
            EXT_SECTOR_COUNT,
            EXT_OPAQUE_54,
            EXT_DEVICE,
        ] {
            let half = u16::from_le_bytes(block.0[offset..offset + 2].try_into().unwrap());
            assert_eq!(half, 0, "half +{offset:#x}");
        }
    }

    #[test]
    fn reset_leaves_the_gaps_between_the_fields_untouched() {
        let mut block = poisoned();
        unsafe { ata_cmd_reset(block.0.as_mut_ptr()) };
        // Header (+0x00..+0x0b), the pad after the protocol byte, the
        // byte after the command register, the pad before the device
        // index, and the byte between +0x4a and the extended taskfile.
        for offset in (0x00..0x0c).chain([0x0d, 0x0e, 0x0f, 0x1b, 0x1f, 0x21, 0x22, 0x23, 0x4b]) {
            assert_eq!(block.0[offset], 0xa5, "byte +{offset:#x}");
        }
    }

    #[test]
    fn reset_is_idempotent() {
        let mut once = poisoned();
        unsafe { ata_cmd_reset(once.0.as_mut_ptr()) };
        let mut twice = once;
        unsafe { ata_cmd_reset(twice.0.as_mut_ptr()) };
        assert_eq!(once, twice);
    }

    // ---- the hot setters -------------------------------------------------

    #[test]
    fn each_setter_writes_exactly_its_own_field() {
        let cases: [(&str, &dyn Fn(*mut u8), usize, usize, u128); 4] = [
            (
                "protocol",
                &|cmd| unsafe { ata_cmd_set_protocol(cmd, PROTOCOL_NON_DATA) },
                PROTOCOL,
                1,
                PROTOCOL_NON_DATA as u128,
            ),
            ("device", &|cmd| unsafe { ata_cmd_set_device(cmd, 3) }, DEVICE_INDEX, 1, 3),
            (
                "timeout",
                &|cmd| unsafe { ata_cmd_set_timeout_ms(cmd, 30_000) },
                TIMEOUT_MS,
                4,
                30_000,
            ),
            ("flags", &|cmd| unsafe { ata_cmd_set_flags(cmd, 0x0004_2000) }, FLAGS, 4, 0x4_2000),
        ];

        for (name, apply, offset, width, expected) in cases {
            let mut block = poisoned();
            apply(block.0.as_mut_ptr());
            let mut stored = 0u128;
            for i in (0..width).rev() {
                stored = stored << 8 | block.0[offset + i] as u128;
            }
            assert_eq!(stored, expected, "{name}");
            for other in 0..block.0.len() {
                if (offset..offset + width).contains(&other) {
                    continue;
                }
                assert_eq!(block.0[other], 0xa5, "{name} spilled onto +{other:#x}");
            }
        }
    }

    #[test]
    fn the_device_setter_stores_the_unset_sentinel_verbatim() {
        // The producers read this byte back with `ldrsb`, so 0xff is -1.
        let mut block = poisoned();
        unsafe { ata_cmd_set_device(block.0.as_mut_ptr(), DEVICE_NONE) };
        assert_eq!(block.0[DEVICE_INDEX] as i8, -1);
    }

    #[test]
    fn the_command_setter_writes_only_the_command_byte() {
        let mut block = poisoned();
        unsafe { ata_cmd_set_command(block.0.as_mut_ptr(), 0xc8) };
        assert_eq!(block.0[COMMAND], 0xc8, "READ DMA");
        for other in 0..block.0.len() {
            if other != COMMAND {
                assert_eq!(block.0[other], 0xa5, "spilled onto +{other:#x}");
            }
        }
    }

    #[test]
    fn a_builder_sequence_reproduces_the_read_dma_command() {
        // The read flow @ 0x082798bc, instruction for instruction.
        let mut block = poisoned();
        let cmd = block.0.as_mut_ptr();
        unsafe {
            ata_cmd_reset(cmd);
            ata_cmd_set_protocol(cmd, PROTOCOL_DATA);
            ata_cmd_set_flags(cmd, 0x2080);
            ata_cmd_set_device(cmd, 0);
            ata_cmd_set_timeout_ms(cmd, 10_000);
            ata_cmd_set_lba28(cmd, 0x0012_3456, 0);
        }
        assert_eq!(block.0[PROTOCOL], PROTOCOL_DATA);
        assert_eq!(word_at(&block, FLAGS), 0x2080);
        assert_eq!(block.0[DEVICE_INDEX], 0);
        assert_eq!(word_at(&block, TIMEOUT_MS), 10_000);
        assert_eq!(block.0[LBA_LOW..DEVICE_HEAD], [0x56, 0x34, 0x12]);
        assert_eq!(block.0[DEVICE_HEAD], 0x40);
        // Reset's defaults survive everything the builder did not touch.
        assert_eq!(word_at(&block, BLOCK_SIZE), DEFAULT_BLOCK_SIZE);
    }

    // ---- LBA48 round trip ------------------------------------------------

    #[test]
    fn lba48_unpacks_exactly_what_the_packer_wrote() {
        for (hi, lo) in [
            (0u32, 0u32),
            (0x1122, 0x3344_5566),
            (0xffff, 0xffff_ffff),
            (0x0001, 0x0000_0000),
            (0x8000, 0x8000_0001),
            (0x00ff, 0xff00_ff00),
        ] {
            let mut block = poisoned();
            unsafe { ata_cmd_set_lba48(block.0.as_mut_ptr(), hi, lo, 1, 0x1234, 0x25) };
            let (mut out_hi, mut out_lo) = (0u32, 0u32);
            unsafe { ata_cmd_get_lba48(block.0.as_ptr(), &mut out_hi, &mut out_lo) };
            assert_eq!((out_hi, out_lo), (hi, lo), "lba {hi:#x}:{lo:#x}");
        }
    }

    #[test]
    fn lba48_read_back_ignores_the_neighbouring_registers() {
        // The count pair (+0x52) and device halfword (+0x56) sit right
        // next to the three LBA pairs and must not leak into the answer.
        let mut block = poisoned();
        unsafe { ata_cmd_set_lba48(block.0.as_mut_ptr(), 0, 0, 1, 0xffff, 0xff) };
        let (mut hi, mut lo) = (0xdead_beefu32, 0xdead_beefu32);
        unsafe { ata_cmd_get_lba48(block.0.as_ptr(), &mut hi, &mut lo) };
        assert_eq!((hi, lo), (0, 0));
    }

    #[test]
    fn lba48_read_back_decodes_a_hand_built_taskfile() {
        // LBA bytes 0..5 = 10 20 30 40 50 60, interleaved as the ATA
        // extended taskfile's (current | previous << 8) pairs.
        let mut block = poisoned();
        let put = |b: &mut Block, offset: usize, value: u16| {
            b.0[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        };
        put(&mut block, EXT_LBA_LOW, 0x4010);
        put(&mut block, EXT_LBA_MID, 0x5020);
        put(&mut block, EXT_LBA_HIGH, 0x6030);
        let (mut hi, mut lo) = (0u32, 0u32);
        unsafe { ata_cmd_get_lba48(block.0.as_ptr(), &mut hi, &mut lo) };
        assert_eq!(lo, 0x4030_2010);
        assert_eq!(hi, 0x0000_6050);
    }

    #[test]
    fn lba48_zero_everything() {
        let mut cmd = [0xffu8; 0x60];
        unsafe { ata_cmd_set_lba48(cmd.as_mut_ptr(), 0, 0, 0, 0, 0) };
        assert_eq!(&cmd[0x4c..0x54], &[0u8; 8]);
        assert_eq!(cmd[0x1a], 0);
        assert_eq!(u16::from_le_bytes([cmd[0x56], cmd[0x57]]), 0x40);
        // Bytes between the two written regions stay untouched.
        assert_eq!(cmd[0x54], 0xff);
        assert_eq!(cmd[0x55], 0xff);
        assert_eq!(cmd[0x1b], 0xff);
    }
}
