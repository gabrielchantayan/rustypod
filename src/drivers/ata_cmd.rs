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
//! Two neighbouring leaves from the ATA island @ 0x08369000..0x0836c000
//! live here too:
//!
//! - `ata_handle_first_word_or_minus1` — `FUN_08369780` @ 0x08369780
//!   (16 bytes; 106 `bl` + 2 tail-`b` call sites — the most-called leaf
//!   in the island). A NULL-guarded read of an ATA handle's first word:
//!   `handle[0]`, or 0xffffffff when the handle is NULL.
//! - `ata_handle_table_entry` — `FUN_08369864` @ 0x08369864 (20 bytes;
//!   99 `bl` + 7 tail-`b` call sites). A NULL-guarded word-indexed
//!   lookup into the table the handle's second word points at:
//!   `((const u32 *)handle[1])[index]`, or 0 when the handle is NULL.
//! - `ata_call_with_zero` — `FUN_08369778` @ 0x08369778 (8 bytes;
//!   24 `bl` + 1 tail-`b` call sites). The zero-argument entry point of
//!   the handle factory @ 0x083696f4 (`mov r0, #0; b 0x083696f4`) —
//!   allocates the 5-word handle both leaves above read. The factory
//!   itself is not ported yet (its allocator is the ported
//!   [`traced_alloc`]), so the veneer dispatches through
//!   [`ATA_HANDLE_HOOKS`].
//! - `traced_alloc` — `FUN_08043c18` @ 0x08043c18 (168 bytes; 88 `bl`
//!   call sites, binary-scanned — the ATA handle factory @ 0x083696f4
//!   among them). The firmware-wide traced allocator front-end: zeroes
//!   the descriptor's status word, brackets the real allocator call
//!   with an optional pre/post trace hook, and stamps the first byte
//!   of large blocks with a global tag. See its doc header.
//! - `traced_free` — `FUN_08043994` @ 0x08043994 (72 bytes; 126
//!   conditional/unconditional `bl` call sites in osos.asm). The free
//!   twin, over the same descriptor: an optional pre/post trace hook
//!   around an unconditional underlying free. See its doc header.
//!
//! The island's error reporting bottoms out in a per-task record pool,
//! allocated by:
//!
//! - `ata_error_record` — `FUN_082d0ae8` @ 0x082d0ae8 (136 bytes; 6 `bl`
//!   call sites in osos.asm, one of them `ata_report_error` @
//!   0x083690b0). Fetches the current owner id from the ROM thunk
//!   0x08037e60, returns the caller's 0x38-byte record from an 8-slot
//!   pool (stock table @ 0x08adb68c, pointer literal @ 0x082d0b74),
//!   claiming and zeroing a free slot on first use. See the function's
//!   doc header for the full algorithm.
//! - `ata_report_error` — `FUN_083690a8` @ 0x083690a8 (24 bytes; 25 `bl`
//!   call sites). The island's errno setter: stores its argument at
//!   record +0x04 of the caller's [`ata_error_record`] and returns
//!   0xffffffff for the caller to propagate.
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
//!   (+0x28, the transfer buffer): `ata_cmd_reset` writes it as the same
//!   32-bit zero the original does, and `ata_cmd_set_buffer` stores its
//!   argument narrowed to 32 bits — exact on the 32-bit target, a
//!   documented truncation on the 64-bit test host.

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

/// ata_cmd_set_block_size — original: `FUN_081213e4` @ 0x081213e4
/// (8 bytes; 12 call sites, binary-scanned).
///
/// Block size in bytes (+0x34). Every caller passes the device object's
/// bytes-per-sector (vtable slot +0x20) — the same value the transfer-
/// length computation multiplies by. [`ata_cmd_reset`] defaults the
/// field to [`DEFAULT_BLOCK_SIZE`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_block_size(cmd: *mut u8, block_size: u32) {
    set_word(cmd, BLOCK_SIZE, block_size);
}

/// ata_cmd_set_transfer_len — original: `FUN_081212a4` @ 0x081212a4
/// (8 bytes; 16 call sites, binary-scanned).
///
/// Transfer length in bytes (+0x30): the builders pass
/// `sectors * bytes-per-sector`, the product of the caller's count
/// argument and the device object's vtable slot +0x20.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_transfer_len(cmd: *mut u8, length: u32) {
    set_word(cmd, TRANSFER_LEN, length);
}

/// ata_cmd_set_buffer — original: `FUN_08121480` @ 0x08121480 (8 bytes;
/// 16 call sites, binary-scanned).
///
/// The transfer buffer object pointer (+0x28). Every builder sets it as
/// the head of the (buffer, offset, length) triple — buffer here, then
/// [`ata_cmd_set_buffer_offset`] (usually 0), then
/// [`ata_cmd_set_transfer_len`]. The two non-data builders skip the
/// whole triple.
///
/// Deviation: the field is a 32-bit word on the target, so the port
/// stores `buffer as u32` — exact where the firmware runs, a
/// truncation on the 64-bit test host (the tests pin the low 32 bits,
/// which is all the hardware ever sees).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_buffer(cmd: *mut u8, buffer: *mut u8) {
    set_word(cmd, BUFFER, buffer as u32);
}

/// ata_cmd_set_buffer_offset — original: `FUN_08121204` @ 0x08121204
/// (8 bytes; 16 call sites, binary-scanned).
///
/// Offset into the transfer buffer (+0x2c), always stored immediately
/// after the buffer pointer and immediately before the transfer length,
/// which is what makes the triple read as (buffer, offset, length).
/// Usually 0; 0x0827a2b0 passes a caller argument.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_buffer_offset(cmd: *mut u8, offset: u32) {
    set_word(cmd, BUFFER_OFFSET, offset);
}

/// ata_cmd_set_sector_count — original: `FUN_081213ac` @ 0x081213ac
/// (8 bytes; 10 call sites, binary-scanned).
///
/// The legacy-taskfile sector count (+0x15). Every caller passes the
/// caller's count masked to a byte (`and r1, r5, #0xff`), which is why
/// the LBA28 flows also cap the count at 0x100 (0x082798e4).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_sector_count(cmd: *mut u8, count: u8) {
    set_byte(cmd, SECTOR_COUNT, count);
}

/// ata_cmd_set_feature — original: `FUN_081211ec` @ 0x081211ec (8
/// bytes; 4 call sites, binary-scanned).
///
/// The ATA feature register (+0x14); one SMART builder passes 0xD5.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_cmd_set_feature(cmd: *mut u8, feature: u8) {
    set_byte(cmd, FEATURE, feature);
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

/// ata_handle_first_word_or_minus1 — original: `FUN_08369780` @
/// 0x08369780 (16 bytes; **106 `bl` + 2 tail-`b` call sites**,
/// binary-scanned — the most-called leaf in the ATA island
/// @ 0x08369000..0x0836c000).
///
/// A NULL-guarded read of an ATA handle's first word: `handle[0]`, or
/// 0xffffffff when the handle is NULL. The guard folds "no device" into
/// the same -1 the error paths report, and the callers rely on the
/// signedness — they `cmp` the result against a count and branch with
/// the signed `bgt`/`ble` (e.g. @ 0x0803b924, 0x0803b9f4, 0x080438f4),
/// so a missing handle sorts below every real count rather than reading
/// as a huge unsigned one.
///
/// The load is a plain `ldr` like the original's `ldrne r0, [r0]` —
/// this is an in-memory object field, not a hardware register.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_handle_first_word_or_minus1(handle: *const u32) -> u32 {
    if handle.is_null() {
        0xffff_ffff
    } else {
        handle.read()
    }
}
/// ata_handle_field4_is_positive — original:
/// `switchD_0807a000::caseD_7` @ 0x0806f1a0 (24 bytes).
///
/// The ATA candidate-selection path @ 0x08070c34 writes this leaf's result
/// to its optional status out-parameter after finding a matching table
/// entry. It returns 1 precisely when that entry is non-NULL and its signed
/// in-memory word at byte offset +0x04 is positive; a NULL entry, a negative
/// word, and zero each return 0. This is a plain aligned `ldr`, not an MMIO
/// access (`cmp r0,#0; ldrne r0,[r0,#4]; cmpne r0,#0; movle/movgt`).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_handle_field4_is_positive(handle: *const u8) -> i32 {
    if handle.is_null() {
        0
    } else {
        ((handle.add(4) as *const i32).read() > 0) as i32
    }
}

/// ata_handle_first_word_or_zero — original: `FUN_0806f1b8` @
/// 0x0806f1b8 (16 bytes).
///
/// The ATA candidate-selection helper's NULL-safe field-0 accessor:
/// returns the first in-memory word of `handle`, or zero when no handle
/// exists. The original is exactly `cmp r0,#0; ldrne r0,[r0];
/// moveq r0,#0; bx lr`; this is therefore a plain aligned object-field
/// load, not an MMIO read.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_handle_first_word_or_zero(handle: *const u32) -> u32 {
    if handle.is_null() {
        0
    } else {
        handle.read()
    }
}


/// ata_handle_table_entry — original: `FUN_08369864` @ 0x08369864
/// (20 bytes; 99 `bl` + 7 tail-`b` call sites, binary-scanned).
///
/// A NULL-guarded table lookup off the ATA handle's second word:
/// `((const u32 *)handle[1])[index]`, or 0 when the handle is NULL.
/// Where [`ata_handle_first_word_or_minus1`] reports "no device" as -1,
/// this one folds a missing handle into a zero entry — the two guards
/// exist because the callers read the results with different eyes (the
/// first word is compared signed, the table entry is a value or
/// pointer where 0 already means "none").
///
/// Both loads are plain `ldr`s like the original's
/// `ldrne r0, [r0, #4]; ldrne r0, [r0, r1, lsl #2]` — in-memory object
/// fields, not hardware registers. The `index` argument is used as a
/// word index, so on the 32-bit target it can reach any byte offset in
/// steps of four.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_handle_table_entry(handle: *const u32, index: u32) -> u32 {
    if handle.is_null() {
        0
    } else {
        (handle.add(1).read() as *const u32)
            .add(index as usize)
            .read()
    }
}

// ---------------------------------------------------------------------------
// The handle factory's zero-argument veneer.
// ---------------------------------------------------------------------------

/// ATA handle-factory services. The factory proper @ 0x083696f4 is not
/// ported yet — it allocates through the ported [`traced_alloc`]
/// (0x08043c18) and frees through the ported [`traced_free`]
/// (0x08043994) — so the
/// veneer below dispatches through this table (the [`ATA_ERROR_HOOKS`]
/// pattern) and the default stub reports allocation failure. Every
/// caller already handles that: each `bl 0x08369778` site compares the
/// result against NULL and takes its error path.
#[derive(Copy, Clone)]
pub struct AtaHandleHooks {
    /// The handle factory @ 0x083696f4: allocates a 5-word handle and a
    /// zeroed 4-entry table, then lays it out as `[0]=0, [1]=table,
    /// [2]=0, [3]=4, [4]=param`. Swap in the real port when 0x083696f4
    /// lands; host tests install a mock.
    pub create: unsafe extern "C" fn(param: u32) -> *mut u32,
}

/// Default stub: no factory wired in — behave as if the underlying
/// allocator failed and return NULL. Faithful to the original's own
/// failure path (0x083696f4 returns NULL when either allocation fails),
/// and the only behavior reachable until the factory is ported.
unsafe extern "C" fn missing_handle_factory(_param: u32) -> *mut u32 {
    core::ptr::null_mut()
}

/// Hook table for the unported factory. Replace before first use on
/// target; host tests install mocks via `core::ptr::addr_of_mut!`.
pub static mut ATA_HANDLE_HOOKS: AtaHandleHooks = AtaHandleHooks {
    create: missing_handle_factory,
};

/// Reads the hook table. Volatile so LLVM cannot constant-fold the load
/// to the default stub (the heap/wrappers.rs pattern).
#[inline(always)]
fn handle_hooks() -> AtaHandleHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ATA_HANDLE_HOOKS)) }
}

/// ata_call_with_zero — original: `FUN_08369778` @ 0x08369778 (8 bytes;
/// 24 `bl` + 1 tail-`b` call sites, binary-scanned).
///
/// A zero-argument veneer over the ATA handle factory @ 0x083696f4:
/// `mov r0, #0; b 0x083696f4`. The factory builds the 5-word handle
/// (`[0]=0, [1]=zeroed 4-entry table, [2]=0, [3]=4, [4]=param`) that
/// [`ata_handle_first_word_or_minus1`] and [`ata_handle_table_entry`]
/// read; this entry point is the common case where the factory's extra
/// word (+0x10) stays 0. Callers store the result into object fields
/// (e.g. @ 0x0803bbd8, 0x08070644/0x08070650) and treat NULL as
/// allocation failure.
///
/// Deviation: the original tail-branches into the factory; the port
/// calls it indirectly through [`ATA_HANDLE_HOOKS`] because the factory
/// itself is not ported yet — its allocator [`traced_alloc`] and the
/// free [`traced_free`] it pairs with now are. The default stub returns
/// NULL — the same value the original produces on an allocation
/// failure.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_call_with_zero() -> *mut u32 {
    (handle_hooks().create)(0)
}

// ---------------------------------------------------------------------------
// The traced allocator the handle factory (and 87 other call sites) use.
// ---------------------------------------------------------------------------

/// Allocator-descriptor services for [`traced_alloc`]. The stock
/// descriptor is a RAM table @ 0x08a0c2a4 (pointer literal @
/// 0x08043cc0) whose slots are function pointers the heap init
/// installs; the port keeps the two slots this function consults as a
/// hook table (the [`ATA_HANDLE_HOOKS`] pattern). The default stubs
/// report allocation failure — the original's own alloc-failure
/// result, which every caller's NULL check already handles.
#[derive(Copy, Clone)]
pub struct TracedAllocHooks {
    /// Descriptor slot +0x0c: the underlying allocator, called as
    /// `alloc(size, tag1, tag2)`; returns the block or NULL.
    pub alloc: unsafe extern "C" fn(size: i32, tag1: u32, tag2: u32) -> *mut u8,
    /// Descriptor slot +0x28: the optional trace hook (`None` = the
    /// stock image's NULL slot). Called before the allocation as
    /// `trace(NULL, size, tag1, tag2, 0)` and after it as
    /// `trace(block, size, tag1, tag2, 1)`; the fifth argument rides on
    /// the stack in the original (`str r3, [sp]` @ 0x08043c4c/0x08043c8c).
    pub trace: Option<
        unsafe extern "C" fn(block: *mut u8, size: i32, tag1: u32, tag2: u32, phase: u32),
    >,
}

/// Default stub: no heap wired in — fail the way the underlying
/// allocator does when it cannot serve the request.
unsafe extern "C" fn missing_allocator(_size: i32, _tag1: u32, _tag2: u32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Hook table for the descriptor's function-pointer slots. Replace
/// before first use on target; host tests install mocks via
/// `core::ptr::addr_of_mut!`.
pub static mut TRACED_ALLOC_HOOKS: TracedAllocHooks = TracedAllocHooks {
    alloc: missing_allocator,
    trace: None,
};

/// Reads the hook table. Volatile so LLVM cannot constant-fold the load
/// to the default stub (the heap/wrappers.rs pattern) — and so the
/// post-allocation read below really re-reads the slot, the way the
/// original reloads `[r6, #0x28]` after the allocator returns.
#[inline(always)]
fn alloc_hooks() -> TracedAllocHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRACED_ALLOC_HOOKS)) }
}

/// The descriptor's two status words, +0x00 and +0x04. [`traced_alloc`]
/// zeroes +0x00 on every in-range entry and +0x04 before the pre-trace
/// call; the rest of the descriptor is opaque to this function. The
/// stock words sit in the table @ 0x08a0c2a4; the port keeps them as a
/// crate static (the [`ERROR_RECORDS`] precedent). Only ever touched
/// through raw pointers, hence the module-level pattern of `static mut`
/// plus `addr_of_mut!`.
pub static mut TRACED_ALLOC_STATUS: [u32; 2] = [0; 2];

/// The large-allocation tag byte, read from 0x08a0ea04 in the stock
/// image (pointer literal @ 0x08043cc4) where it initializes to 0x61.
/// [`traced_alloc`] stamps it into the first byte of every served block
/// larger than 0x800 bytes; whatever installs it lives outside this
/// function. A crate static in the port so target setup (or a host
/// test) can substitute the live value.
pub static mut LARGE_ALLOC_TAG: u8 = 0x61;

/// traced_alloc — original: `FUN_08043c18` @ 0x08043c18 (168 bytes;
/// 88 `bl` call sites, binary-scanned — among them the ATA handle
/// factory @ 0x083696f4 and its zero-arg veneer [`ata_call_with_zero`]).
///
/// The firmware-wide traced allocator front-end. `size` is SIGNED (the
/// original guards with `subs`/`ble` and stamps with `cmp`/`strbgt`);
/// `tag1`/`tag2` are call-site tags the trace hook receives verbatim
/// (0,0 almost everywhere; the one caller @ 0x082d4474 passes a pair of
/// string literals). Algorithm:
///
/// 1. `size <= 0` (signed): return NULL without touching anything.
/// 2. Zero descriptor status word +0x00.
/// 3. If the trace hook (slot +0x28) is installed, zero status word
///    +0x04 and call `trace(NULL, size, tag1, tag2, 0)`.
/// 4. Allocate: `block = alloc(size, tag1, tag2)` (slot +0x0c).
/// 5. Re-read the trace slot — it is loaded again after the call, not
///    cached — and if still installed call
///    `trace(block, size, tag1, tag2, 1)`.
/// 6. If a block came back and `size > 0x800` (signed), stamp its
///    first byte with the global tag byte ([`LARGE_ALLOC_TAG`]) —
///    `*block = *(u8 *)0x08a0ea04` in the original. The stamp is a
///    large-allocation marker; blocks of exactly 0x800 bytes escape it
///    (the comparison is `bgt`, not `bge`).
/// 7. Return the block.
///
/// Deviations: the descriptor's function-pointer slots live in
/// [`TRACED_ALLOC_HOOKS`] (the [`ATA_HANDLE_HOOKS`] pattern) whose
/// default allocator fails every request — behaviorally the original's
/// own alloc-failure path, NULL with the post-trace still issued. The
/// status stores are `write_volatile` so LLVM cannot fold them away
/// (they are the descriptor's observable handshake with the trace
/// machinery); the tag-byte read is volatile to match the original's
/// `ldrb` off a literal-loaded pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn traced_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
    if size <= 0 {
        return core::ptr::null_mut();
    }
    let status = core::ptr::addr_of_mut!(TRACED_ALLOC_STATUS).cast::<u32>();
    status.write_volatile(0);
    if let Some(trace) = alloc_hooks().trace {
        status.add(1).write_volatile(0);
        trace(core::ptr::null_mut(), size, tag1, tag2, 0);
    }
    let block = (alloc_hooks().alloc)(size, tag1, tag2);
    if let Some(trace) = alloc_hooks().trace {
        trace(block, size, tag1, tag2, 1);
    }
    if !block.is_null() && size > 0x800 {
        block.write(core::ptr::read_volatile(core::ptr::addr_of!(LARGE_ALLOC_TAG)));
    }
    block
}

// ---------------------------------------------------------------------------
// The traced free — traced_alloc's twin over the same descriptor.
// ---------------------------------------------------------------------------

/// Allocator-descriptor services for [`traced_free`]. The stock
/// descriptor is the same RAM table [`traced_alloc`] consults @
/// 0x08a0c2a4 (this function's pointer literal @ 0x080439dc); the port
/// keeps the two slots this function consults as a hook table (the
/// [`TRACED_ALLOC_HOOKS`] pattern). The default free stub is a no-op:
/// the original calls slot +0x18 unconditionally, so with no heap wired
/// in the only safe stand-in is one that frees nothing.
#[derive(Copy, Clone)]
pub struct TracedFreeHooks {
    /// Descriptor slot +0x18: the underlying free, called as
    /// `free(block)`. Never NULL-checked by the original — not the
    /// slot, and not `block` (guarding is the callers' job; 44 of them
    /// reach this function through `blne`).
    pub free: unsafe extern "C" fn(block: *mut u8),
    /// Descriptor slot +0x30: the optional free-trace hook (`None` =
    /// the stock image's NULL slot). Called before the free as
    /// `trace(block, 0)` and after it as `trace(NULL, 1)`; the second
    /// argument is the phase, and the post-free block is NULL because
    /// the real one is already gone.
    pub trace: Option<unsafe extern "C" fn(block: *mut u8, phase: u32)>,
}

/// Default stub: no heap wired in — freeing is a no-op.
unsafe extern "C" fn missing_free(_block: *mut u8) {}

/// Hook table for the descriptor's function-pointer slots. Replace
/// before first use on target; host tests install mocks via
/// `core::ptr::addr_of_mut!`.
pub static mut TRACED_FREE_HOOKS: TracedFreeHooks = TracedFreeHooks {
    free: missing_free,
    trace: None,
};

/// Reads the hook table. Volatile so LLVM cannot constant-fold the load
/// to the default stub (the heap/wrappers.rs pattern) — and so the
/// post-free read below really re-reads the slot, the way the original
/// reloads `[r4, #0x30]` after the free returns.
#[inline(always)]
fn free_hooks() -> TracedFreeHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS)) }
}

/// traced_free — original: `FUN_08043994` @ 0x08043994 (72 bytes; 80
/// `bl` + 44 `blne` + 2 `bleq` call sites in osos.asm — among them the
/// keyid/serial formatter's hex-blob release @ 0x080aee4c and the ATA
/// handle factory's teardown).
///
/// The free twin of [`traced_alloc`] over the same descriptor @
/// 0x08a0c2a4. Algorithm:
///
/// 1. If the free-trace hook (slot +0x30) is installed, call
///    `trace(block, 0)` — the pre-free phase.
/// 2. Free: `free(block)` (slot +0x18), unconditionally — neither the
///    slot nor `block` is NULL-checked (the callers guard; that is what
///    the 44 `blne` sites are for).
/// 3. Re-read the trace slot — it is loaded again after the call, not
///    cached (`ldr r2, [r4, #0x30]` twice) — and if still installed,
///    tail-call `trace(NULL, 1)` — the post-free phase, reporting a
///    NULL block because the real one is already freed.
///
/// Deviations: the descriptor's function-pointer slots live in
/// [`TRACED_FREE_HOOKS`] (the [`TRACED_ALLOC_HOOKS`] pattern) whose
/// default free is a no-op; the post-free trace is an ordinary
/// returning call where the original tail-branches (`bxne r2`) — same
/// observable behavior.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn traced_free(block: *mut u8) {
    if let Some(trace) = free_hooks().trace {
        trace(block, 0);
    }
    (free_hooks().free)(block);
    if let Some(trace) = free_hooks().trace {
        trace(core::ptr::null_mut(), 1);
    }
}

// ---------------------------------------------------------------------------
// Per-task error records — the storage layer's errno.
// ---------------------------------------------------------------------------

use crate::libc::memzero::memzero;

/// Byte size of one error record (the original passes 0x38 to its zero
/// fill). Only three fields are known: the owner id at +0x00, the error
/// code at +0x04 (written by `ata_report_error`) and the 1-based slot
/// tag at +0x0c.
pub const ERROR_RECORD_SIZE: usize = 0x38;

/// Number of record slots; both of the original's scan loops bound at
/// `cmp r?, #0x8`.
pub const ERROR_RECORD_SLOTS: usize = 8;

const RECORD_OWNER: usize = 0x00;
const RECORD_ERROR: usize = 0x04;
const RECORD_SLOT_TAG: usize = 0x0c;

/// The record pool must be word-aligned: the original reaches every
/// field with word `ldr`/`str`s. The field is only ever touched through
/// raw pointers, hence the `allow`.
#[repr(align(4))]
#[allow(dead_code)]
struct ErrorRecords([u8; ERROR_RECORD_SLOTS * ERROR_RECORD_SIZE]);

/// The record pool. The stock table lives in RAM at 0x08adb68c (pointer
/// literal @ 0x082d0b74); the port keeps it as a crate static, the
/// kernel/task.rs pool precedent.
static mut ERROR_RECORDS: ErrorRecords =
    ErrorRecords([0; ERROR_RECORD_SLOTS * ERROR_RECORD_SIZE]);

/// ROM/kernel services the error-record allocator depends on. See
/// [`ATA_ERROR_HOOKS`] for the default-stub policy.
#[derive(Copy, Clone)]
pub struct AtaErrorHooks {
    /// Thunk 0x08037e60 -> ROM 0x22003eb0 (catalogued as the UNVERIFIED
    /// "size_to_class" in kernel/thunks.rs): the id that owns a record —
    /// the storage layer's per-task key. The stock call site sets no
    /// argument of its own (r0 is whatever the caller left in it), so
    /// this hook takes none.
    pub current_id: unsafe extern "C" fn() -> u32,
}

/// Default stub: no kernel — every caller reports under id 0, which the
/// first scan matches against a zeroed pool's slot 0. The
/// kernel/condvar.rs "kernel not present" policy.
unsafe extern "C" fn missing_current_id() -> u32 {
    0
}

/// Hook table for the ROM dependency. Replace before first use on
/// target; host tests install mocks via `core::ptr::addr_of_mut!`.
pub static mut ATA_ERROR_HOOKS: AtaErrorHooks = AtaErrorHooks {
    current_id: missing_current_id,
};

/// Reads the hook table. Volatile so LLVM cannot constant-fold the load
/// to the default stub (the heap/wrappers.rs pattern).
#[inline(always)]
fn error_hooks() -> AtaErrorHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ATA_ERROR_HOOKS)) }
}

/// Aligned volatile word read for the record scans — the original's
/// `ldr r1, [r8, r1, lsl #3]`.
#[inline(always)]
unsafe fn word(base: *const u8, offset: usize) -> u32 {
    (base.add(offset) as *const u32).read_volatile()
}

/// ata_error_record — original: `FUN_082d0ae8` @ 0x082d0ae8 (136 bytes;
/// 6 `bl` call sites in osos.asm — 0x082d0aa8, 0x082e1f7c, 0x082e1fa0,
/// 0x082e2258, 0x082e4074 and `ata_report_error` @ 0x083690b0).
///
/// The storage layer's per-task error-record allocator. Fetches the
/// current owner id (ROM thunk 0x08037e60, see [`AtaErrorHooks`]), then:
///
/// 1. Scans the 8 slots of 0x38 bytes for one whose owner word (+0x00)
///    equals the id and returns it — a caller always finds its own
///    record back.
/// 2. Otherwise claims the first slot whose owner word is 0: zeroes the
///    whole record, stamps the owner and a 1-based slot tag at +0x0c,
///    and returns it.
///
/// Faithful quirks, both preserved:
///
/// - A pool with no free slot falls through the second scan and reuses
///   slot 0 (`mov r4, #0; b found` @ 0x082d0b6c), zeroing whoever was
///   there.
/// - An id of 0 matches the zeroed pool on the FIRST scan, so it returns
///   slot 0 uninitialized — owner 0 reads back as "free" forever.
///
/// Deviations: the original zeroes with the island-local byte loop
/// 0x08394120 (returns dst+n, discarded by the caller); the port calls
/// the ported [`memzero`] — same memory effect. `#[inline(never)]`
/// keeps the body out of `ata_report_error`, whose original is a plain
/// `bl` here.
///
/// Codegen deviation: the original keeps two rolled 8-iteration scans;
/// LLVM fully unrolls the constant trip count into straight-line
/// compare/branch chains (the util/table_find.rs pattern). Behaviorally
/// identical — the slot order, the early return on the first owner
/// match and the full-pool fall-through to slot 0 are all preserved.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_error_record() -> *mut u8 {
    let id = (error_hooks().current_id)();
    let table = core::ptr::addr_of_mut!(ERROR_RECORDS) as *mut u8;
    for slot in 0..ERROR_RECORD_SLOTS {
        let record = table.add(slot * ERROR_RECORD_SIZE);
        if word(record, RECORD_OWNER) == id {
            return record;
        }
    }
    let mut slot = 0;
    for free in 0..ERROR_RECORD_SLOTS {
        if word(table, free * ERROR_RECORD_SIZE) == 0 {
            slot = free;
            break;
        }
    }
    let record = table.add(slot * ERROR_RECORD_SIZE);
    memzero(record, ERROR_RECORD_SIZE);
    set_word(record, RECORD_OWNER, id);
    set_word(record, RECORD_SLOT_TAG, slot as u32 + 1);
    record
}

/// ata_report_error — original: `FUN_083690a8` @ 0x083690a8 (24 bytes;
/// 25 `bl` call sites in osos.asm).
///
/// The storage layer's errno setter. Fetches the caller's per-task
/// error record ([`ata_error_record`]), stores `error` in its code
/// field (+0x04) and returns 0xffffffff. The ATA command flows end
/// their error paths with `return ata_report_error(code);` — the -1
/// propagates to the caller while the record keeps the code for whoever
/// inspects it later (the reader @ 0x082d0aa4 returns record+0x04).
///
/// The store is a volatile word store like the original's `str r4,
/// [r0, #4]` — an in-memory record field, not a hardware register.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_report_error(error: u32) -> u32 {
    let record = ata_error_record();
    set_word(record, RECORD_ERROR, error);
    0xffff_ffff
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
    fn the_block_size_setter_writes_only_its_word() {
        let mut block = poisoned();
        unsafe { ata_cmd_set_block_size(block.0.as_mut_ptr(), 4096) };
        assert_eq!(word_at(&block, BLOCK_SIZE), 4096);
        for other in 0..block.0.len() {
            if !(BLOCK_SIZE..BLOCK_SIZE + 4).contains(&other) {
                assert_eq!(block.0[other], 0xa5, "spilled onto +{other:#x}");
            }
        }
    }

    #[test]
    fn the_transfer_len_setter_writes_only_its_word() {
        let mut block = poisoned();
        unsafe { ata_cmd_set_transfer_len(block.0.as_mut_ptr(), 0x200 * 8) };
        assert_eq!(word_at(&block, TRANSFER_LEN), 0x1000);
        for other in 0..block.0.len() {
            if !(TRANSFER_LEN..TRANSFER_LEN + 4).contains(&other) {
                assert_eq!(block.0[other], 0xa5, "spilled onto +{other:#x}");
            }
        }
    }

    #[test]
    fn the_buffer_setter_writes_only_its_word() {
        let mut block = poisoned();
        let mut transfer_buffer = [0u8; 0x40];
        let buffer = transfer_buffer.as_mut_ptr();
        unsafe { ata_cmd_set_buffer(block.0.as_mut_ptr(), buffer) };
        // The field is 32 bits on the target; the test host keeps only
        // the low half of the pointer, which is all the firmware sees.
        assert_eq!(word_at(&block, BUFFER), buffer as u32);
        for other in 0..block.0.len() {
            if !(BUFFER..BUFFER + 4).contains(&other) {
                assert_eq!(block.0[other], 0xa5, "spilled onto +{other:#x}");
            }
        }
    }

    #[test]
    fn the_buffer_setter_stores_null_verbatim() {
        // ata_cmd_reset writes this same word as zero; the setter must
        // be able to put it back.
        let mut block = poisoned();
        unsafe { ata_cmd_set_buffer(block.0.as_mut_ptr(), core::ptr::null_mut()) };
        assert_eq!(word_at(&block, BUFFER), 0);
    }

    #[test]
    fn the_buffer_offset_setter_writes_only_its_word() {
        let mut block = poisoned();
        unsafe { ata_cmd_set_buffer_offset(block.0.as_mut_ptr(), 0x1000) };
        assert_eq!(word_at(&block, BUFFER_OFFSET), 0x1000);
        for other in 0..block.0.len() {
            if !(BUFFER_OFFSET..BUFFER_OFFSET + 4).contains(&other) {
                assert_eq!(block.0[other], 0xa5, "spilled onto +{other:#x}");
            }
        }
    }

    #[test]
    fn the_sector_count_setter_writes_only_the_count_byte() {
        let mut block = poisoned();
        unsafe { ata_cmd_set_sector_count(block.0.as_mut_ptr(), 0x80) };
        assert_eq!(block.0[SECTOR_COUNT], 0x80);
        for other in 0..block.0.len() {
            if other != SECTOR_COUNT {
                assert_eq!(block.0[other], 0xa5, "spilled onto +{other:#x}");
            }
        }
    }

    #[test]
    fn the_feature_setter_writes_only_the_feature_byte() {
        let mut block = poisoned();
        unsafe { ata_cmd_set_feature(block.0.as_mut_ptr(), 0xd5) };
        assert_eq!(block.0[FEATURE], 0xd5);
        for other in 0..block.0.len() {
            if other != FEATURE {
                assert_eq!(block.0[other], 0xa5, "spilled onto +{other:#x}");
            }
        }
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

    // ---- the handle's first word -------------------------------------

    #[test]
    fn null_handle_reads_back_as_minus1() {
        assert_eq!(
            unsafe { ata_handle_first_word_or_minus1(core::ptr::null()) },
            0xffff_ffff,
            "no device folds into the error paths' -1"
        );
    }

    #[test]
    fn the_first_word_is_returned_verbatim() {
        for first in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff] {
            let handle = [first, 0xdead_beef];
            assert_eq!(unsafe { ata_handle_first_word_or_minus1(handle.as_ptr()) }, first);
        }
    }

    // ---- ATA candidate field +0x04 -----------------------------------

    /// Independent expression of the leaf's observable contract.
    fn reference_field4_is_positive(field4: Option<i32>) -> i32 {
        match field4 {
            Some(value) if value > 0 => 1,
            _ => 0,
        }
    }

    #[repr(C)]
    struct AtaCandidate {
        ignored_word: u32,
        field4: i32,
    }

    #[test]
    fn candidate_field4_positive_matches_reference_for_all_branches() {
        let null = core::ptr::null();
        assert_eq!(
            unsafe { ata_handle_field4_is_positive(null) },
            reference_field4_is_positive(None),
            "NULL candidate"
        );

        for field4 in [-1, 0, 1] {
            let candidate = AtaCandidate {
                ignored_word: 0xdead_beef,
                field4,
            };
            assert_eq!(
                unsafe { ata_handle_field4_is_positive((&candidate as *const AtaCandidate).cast()) },
                reference_field4_is_positive(Some(field4)),
                "field +0x04 = {field4}"
            );
        }
    }

    // ---- ATA candidate field +0x00 -----------------------------------

    #[test]
    fn null_candidate_first_word_is_zero() {
        assert_eq!(
            unsafe { ata_handle_first_word_or_zero(core::ptr::null()) },
            0,
            "NULL candidate follows the original moveq-zero path"
        );
    }

    #[test]
    fn candidate_first_word_is_returned_verbatim() {
        for first in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xdead_beef, u32::MAX] {
            let candidate = [first, 0xa5a5_5a5a];
            assert_eq!(
                unsafe { ata_handle_first_word_or_zero(candidate.as_ptr()) },
                first,
                "field +0x00 = {first:#010x}"
            );
        }
    }


    // ---- the handle's table entries --------------------------------

    /// The handle's second word is a 32-bit table pointer the function
    /// dereferences — lossless on the 32-bit target, but an ASLR'd host
    /// stack/static address does not survive the `as u32` round-trip.
    /// Map a low arena instead, as on the device (the `heap/pool.rs`
    /// `arena_ptr` precedent), at a hint no other test module claims.
    fn try_low_arena() -> Option<*mut u32> {
        extern crate std;
        use std::sync::OnceLock;
        static ARENA: OnceLock<Option<usize>> = OnceLock::new();
        (*ARENA.get_or_init(|| {
            crate::testing::try_map_u32_slab(0x0a00_0000, 0x1000).map(|p| p as usize)
        }))
        .map(|p| p as *mut u32)
    }

    /// The arena base. Only reached after the caller's skip guard has
    /// confirmed the mapping exists.
    fn low_arena() -> *mut u32 {
        try_low_arena().expect("arena checked by the caller's skip guard")
    }

    /// Early-return marker: `if fixture_unavailable() { return; }`. arm64
    /// macOS cannot map below 4 GiB at all, so there these tests skip.
    fn fixture_unavailable() -> bool {
        try_low_arena().is_none() && crate::testing::note_missing_u32_fixture("ata_cmd")
    }

    /// Layout in the arena: [handle[0], handle[1] = table ptr, table...].
    unsafe fn handle_with_table(table: &[u32]) -> (*const u32, *const u32) {
        let arena = low_arena();
        arena.add(1).write(arena.add(2) as u32);
        for (i, &entry) in table.iter().enumerate() {
            arena.add(2 + i).write(entry);
        }
        (arena, arena.add(2))
    }

    #[test]
    fn null_handle_reads_back_as_zero() {
        assert_eq!(
            unsafe { ata_handle_table_entry(core::ptr::null(), 7) },
            0,
            "a missing handle folds into a zero entry, not the -1 the first-word reader reports"
        );
    }

    #[test]
    fn the_indexed_entry_is_returned_verbatim() {
        if fixture_unavailable() {
            return;
        }
        let table = [0x1111_1111u32, 0x2222_2222, 0xffff_ffff, 0x8000_0000];
        let (handle, _) = unsafe { handle_with_table(&table) };
        for (index, &expected) in table.iter().enumerate() {
            assert_eq!(
                unsafe { ata_handle_table_entry(handle, index as u32) },
                expected,
                "entry {index}"
            );
        }
    }

    #[test]
    fn the_guard_is_on_the_handle_not_the_contents() {
        if fixture_unavailable() {
            return;
        }
        // A zero entry reads back as 0 — the same 0 the NULL guard
        // returns, but reached by dereferencing, not by the guard.
        let table = [0u32, 0x1234_5678];
        let (handle, _) = unsafe { handle_with_table(&table) };
        assert_eq!(unsafe { ata_handle_table_entry(handle, 0) }, 0);
        assert_eq!(unsafe { ata_handle_table_entry(handle, 1) }, 0x1234_5678);
    }

    #[test]
    fn the_index_scales_by_words() {
        if fixture_unavailable() {
            return;
        }
        // r1 is shifted left by 2 — an index, never a byte offset.
        let table: [u32; 16] = core::array::from_fn(|i| i as u32 * 0x0101_0101);
        let (handle, _) = unsafe { handle_with_table(&table) };
        for index in 0..16u32 {
            assert_eq!(
                unsafe { ata_handle_table_entry(handle, index) },
                index * 0x0101_0101
            );
        }
    }

    #[test]
    fn the_first_word_of_the_handle_is_never_read() {
        if fixture_unavailable() {
            return;
        }
        // Poison handle[0]; only handle[1] leads to the table.
        let table = [0xabcd_1234u32];
        let (handle, _) = unsafe { handle_with_table(&table) };
        unsafe { (handle as *mut u32).write(0xffff_ffff) };
        assert_eq!(unsafe { ata_handle_table_entry(handle, 0) }, 0xabcd_1234);
    }

    #[test]
    fn only_the_first_word_is_read() {
        // A zero first word is 0, not the -1 the NULL guard returns —
        // the guard is on the pointer, never on the contents.
        let handle = [0u32, 0xffff_ffff];
        assert_eq!(unsafe { ata_handle_first_word_or_minus1(handle.as_ptr()) }, 0);
    }

    // ---- the per-task error records ----------------------------------

    extern crate std;
    use std::sync::{Mutex, MutexGuard};

    static ERROR_TEST_LOCK: Mutex<()> = Mutex::new(());

    static mut MOCK_ID: u32 = 0;
    unsafe extern "C" fn mock_current_id() -> u32 {
        MOCK_ID
    }

    fn set_id(id: u32) {
        unsafe { MOCK_ID = id };
    }

    /// Restores the default hook when a test ends (drop order: declared
    /// after the guard, so it runs before the lock is released).
    struct ErrorHookReset;
    impl Drop for ErrorHookReset {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(ATA_ERROR_HOOKS)).current_id = missing_current_id;
            }
        }
    }

    /// Serializes the error-record tests, zeroes the pool and installs
    /// the mock id hook.
    fn fresh_records() -> MutexGuard<'static, ()> {
        let guard = ERROR_TEST_LOCK.lock().unwrap();
        unsafe {
            core::ptr::addr_of_mut!(ERROR_RECORDS)
                .write(ErrorRecords([0; ERROR_RECORD_SLOTS * ERROR_RECORD_SIZE]));
            MOCK_ID = 0;
            (*core::ptr::addr_of_mut!(ATA_ERROR_HOOKS)).current_id = mock_current_id;
        }
        guard
    }

    fn record_word(record: *const u8, offset: usize) -> u32 {
        unsafe { word(record, offset) }
    }

    fn slot_of(record: *const u8) -> usize {
        let base = core::ptr::addr_of!(ERROR_RECORDS) as *const u8;
        (record as usize - base as usize) / ERROR_RECORD_SIZE
    }

    #[test]
    fn first_call_claims_slot_zero_and_stamps_it() {
        let _guard = fresh_records();
        let _reset = ErrorHookReset;
        set_id(7);
        let record = unsafe { ata_error_record() };
        assert_eq!(slot_of(record), 0);
        assert_eq!(record_word(record, RECORD_OWNER), 7, "owner id");
        assert_eq!(record_word(record, RECORD_SLOT_TAG), 1, "1-based slot tag");
        // Everything outside owner and tag is zeroed.
        for offset in (0..ERROR_RECORD_SIZE).step_by(4) {
            if offset != RECORD_OWNER && offset != RECORD_SLOT_TAG {
                assert_eq!(record_word(record, offset), 0, "word +{offset:#x}");
            }
        }
    }

    #[test]
    fn the_same_id_finds_its_record_back_without_zeroing_it() {
        let _guard = fresh_records();
        let _reset = ErrorHookReset;
        set_id(7);
        let first = unsafe { ata_error_record() };
        // A payload the allocator must not disturb on the second call.
        unsafe { set_word(first, 0x10, 0xdead_beef) };
        let second = unsafe { ata_error_record() };
        assert_eq!(first, second);
        assert_eq!(record_word(second, 0x10), 0xdead_beef, "no re-zero on the hit path");
    }

    #[test]
    fn distinct_ids_claim_consecutive_slots_with_1_based_tags() {
        let _guard = fresh_records();
        let _reset = ErrorHookReset;
        let mut records = [core::ptr::null_mut::<u8>(); ERROR_RECORD_SLOTS];
        for (i, slot) in records.iter_mut().enumerate() {
            set_id(100 + i as u32);
            *slot = unsafe { ata_error_record() };
            assert_eq!(slot_of(*slot), i);
            assert_eq!(record_word(*slot, RECORD_OWNER), 100 + i as u32);
            assert_eq!(record_word(*slot, RECORD_SLOT_TAG), i as u32 + 1);
        }
    }

    #[test]
    fn id_zero_matches_the_zeroed_pool_on_the_first_scan() {
        // Faithful quirk: owner 0 reads back as "free", so id 0 returns
        // slot 0 uninitialized — owner and tag stay 0.
        let _guard = fresh_records();
        let _reset = ErrorHookReset;
        set_id(0);
        let record = unsafe { ata_error_record() };
        assert_eq!(slot_of(record), 0);
        assert_eq!(record_word(record, RECORD_OWNER), 0);
        assert_eq!(record_word(record, RECORD_SLOT_TAG), 0);
    }

    #[test]
    fn a_full_pool_reuses_slot_zero() {
        let _guard = fresh_records();
        let _reset = ErrorHookReset;
        for i in 0..ERROR_RECORD_SLOTS {
            set_id(100 + i as u32);
            unsafe { ata_error_record() };
        }
        set_id(999);
        let record = unsafe { ata_error_record() };
        assert_eq!(slot_of(record), 0, "full pool falls through to slot 0");
        assert_eq!(record_word(record, RECORD_OWNER), 999, "previous owner evicted");
        assert_eq!(record_word(record, RECORD_SLOT_TAG), 1);
        // Every other slot survived the eviction.
        for i in 1..ERROR_RECORD_SLOTS {
            let base = core::ptr::addr_of!(ERROR_RECORDS) as *const u8;
            let other = unsafe { base.add(i * ERROR_RECORD_SIZE) };
            assert_eq!(record_word(other, RECORD_OWNER), 100 + i as u32, "slot {i}");
        }
    }

    #[test]
    fn the_default_stub_reports_every_caller_under_id_zero() {
        let _guard = fresh_records();
        unsafe {
            (*core::ptr::addr_of_mut!(ATA_ERROR_HOOKS)).current_id = missing_current_id;
        }
        let record = unsafe { ata_error_record() };
        assert_eq!(slot_of(record), 0, "no kernel: the shared slot 0");
    }

    // ---- ata_report_error ---------------------------------------------

    #[test]
    fn report_error_returns_minus1_and_stores_the_code_at_plus4() {
        let _guard = fresh_records();
        let _reset = ErrorHookReset;
        set_id(7);
        assert_eq!(unsafe { ata_report_error(0x1c) }, 0xffff_ffff);
        let record = unsafe { ata_error_record() };
        assert_eq!(record_word(record, RECORD_ERROR), 0x1c);
    }

    #[test]
    fn report_error_lands_in_the_callers_own_slot() {
        let _guard = fresh_records();
        let _reset = ErrorHookReset;
        set_id(7);
        unsafe { ata_report_error(0x1111_1111) };
        set_id(8);
        unsafe { ata_report_error(0x2222_2222) };
        let base = core::ptr::addr_of!(ERROR_RECORDS) as *const u8;
        let slot0 = unsafe { base.add(0) };
        let slot1 = unsafe { base.add(ERROR_RECORD_SIZE) };
        assert_eq!(record_word(slot0, RECORD_ERROR), 0x1111_1111, "id 7's record");
        assert_eq!(record_word(slot1, RECORD_ERROR), 0x2222_2222, "id 8's record");
    }

    #[test]
    fn report_error_overwrites_only_the_code_field() {
        let _guard = fresh_records();
        let _reset = ErrorHookReset;
        set_id(7);
        let record = unsafe { ata_error_record() };
        unsafe { ata_report_error(1) };
        let before: std::vec::Vec<u8> = (0..ERROR_RECORD_SIZE)
            .map(|i| unsafe { record.add(i).read_volatile() })
            .collect();
        unsafe { ata_report_error(2) };
        for i in 0..ERROR_RECORD_SIZE {
            let after = unsafe { record.add(i).read_volatile() };
            if (RECORD_ERROR..RECORD_ERROR + 4).contains(&i) {
                continue;
            }
            assert_eq!(after, before[i], "byte +{i:#x} disturbed");
        }
        assert_eq!(record_word(record, RECORD_ERROR), 2, "second report wins");
    }

    // ---- the zero-argument factory veneer ---------------------------

    static VENEER_TEST_LOCK: Mutex<()> = Mutex::new(());

    static mut VENEER_SEEN_PARAM: u32 = u32::MAX;
    const SENTINEL_HANDLE: usize = 0x0836_0004;

    unsafe extern "C" fn mock_handle_factory(param: u32) -> *mut u32 {
        VENEER_SEEN_PARAM = param;
        SENTINEL_HANDLE as *mut u32
    }

    /// Restores the default hook when a test ends (declared after the
    /// guard, so it runs before the lock is released).
    struct HandleHookReset;
    impl Drop for HandleHookReset {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(ATA_HANDLE_HOOKS)).create = missing_handle_factory;
            }
        }
    }

    #[test]
    fn the_veneer_passes_zero_and_returns_the_factory_result_verbatim() {
        let _guard = VENEER_TEST_LOCK.lock().unwrap();
        let _reset = HandleHookReset;
        unsafe {
            VENEER_SEEN_PARAM = u32::MAX;
            (*core::ptr::addr_of_mut!(ATA_HANDLE_HOOKS)).create = mock_handle_factory;
        }
        let handle = unsafe { ata_call_with_zero() };
        assert_eq!(handle as usize, SENTINEL_HANDLE, "the factory's result, untouched");
        assert_eq!(unsafe { VENEER_SEEN_PARAM }, 0, "the original's mov r0, #0");
    }

    #[test]
    fn the_default_stub_reports_allocation_failure() {
        let _guard = VENEER_TEST_LOCK.lock().unwrap();
        let _reset = HandleHookReset;
        assert!(
            unsafe { ata_call_with_zero() }.is_null(),
            "no factory wired in: NULL, like the original's alloc-failure path"
        );
    }

    // ---- the traced allocator -----------------------------------------

    static ALLOC_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// One observable call into the descriptor, in order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum AllocEvent {
        Trace { null_block: bool, size: i32, tag1: u32, tag2: u32, phase: u32 },
        Alloc { size: i32, tag1: u32, tag2: u32 },
    }

    /// Everything a call lets the world observe.
    #[derive(Debug, PartialEq, Eq)]
    struct AllocOutcome {
        returned_null: bool,
        first_byte: Option<u8>,
        second_byte: Option<u8>,
        status: [u32; 2],
        events: std::vec::Vec<AllocEvent>,
    }

    static ALLOC_EVENTS: Mutex<std::vec::Vec<AllocEvent>> = Mutex::new(std::vec::Vec::new());

    const ALLOC_POISON: u8 = 0xa5;
    static mut ALLOC_BUFFER: [u8; 8] = [ALLOC_POISON; 8];
    static mut ALLOC_FAIL: bool = false;

    unsafe extern "C" fn mock_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        ALLOC_EVENTS.lock().unwrap().push(AllocEvent::Alloc { size, tag1, tag2 });
        if ALLOC_FAIL {
            core::ptr::null_mut()
        } else {
            core::ptr::addr_of_mut!(ALLOC_BUFFER) as *mut u8
        }
    }

    unsafe extern "C" fn mock_trace(block: *mut u8, size: i32, tag1: u32, tag2: u32, phase: u32) {
        ALLOC_EVENTS.lock().unwrap().push(AllocEvent::Trace {
            null_block: block.is_null(),
            size,
            tag1,
            tag2,
            phase,
        });
    }

    /// Restores the default hooks, tag and status when a test ends
    /// (declared after the guard, so it runs before the lock drops).
    struct AllocHookReset;
    impl Drop for AllocHookReset {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS)).alloc = missing_allocator;
                (*core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS)).trace = None;
                TRACED_ALLOC_STATUS = [0; 2];
                LARGE_ALLOC_TAG = 0x61;
            }
        }
    }

    /// Runs the port under the mocks and collects every observable.
    fn run_port(size: i32, tag1: u32, tag2: u32, with_trace: bool, fail: bool, tag: u8) -> AllocOutcome {
        ALLOC_EVENTS.lock().unwrap().clear();
        unsafe {
            ALLOC_BUFFER = [ALLOC_POISON; 8];
            ALLOC_FAIL = fail;
            TRACED_ALLOC_STATUS = [0xdead_beef; 2];
            LARGE_ALLOC_TAG = tag;
            (*core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS)).alloc = mock_alloc;
            (*core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS)).trace =
                if with_trace { Some(mock_trace) } else { None };
        }
        let result = unsafe { traced_alloc(size, tag1, tag2) };
        let (first_byte, second_byte) = if result.is_null() {
            (None, None)
        } else {
            (Some(unsafe { ALLOC_BUFFER[0] }), Some(unsafe { ALLOC_BUFFER[1] }))
        };
        AllocOutcome {
            returned_null: result.is_null(),
            first_byte,
            second_byte,
            status: unsafe { TRACED_ALLOC_STATUS },
            events: ALLOC_EVENTS.lock().unwrap().clone(),
        }
    }

    /// The reference implementation: the C of
    /// `decomp/c/002/08043c18_FUN_08043c18.c` (checked against the
    /// disassembly — Ghidra's convoluted last condition is just
    /// `block != NULL && size > 0x800`, both signed) with plain data in
    /// place of the descriptor.
    fn reference(size: i32, tag1: u32, tag2: u32, with_trace: bool, fail: bool, tag: u8) -> AllocOutcome {
        let mut status = [0xdead_beef; 2];
        let mut events = std::vec::Vec::new();
        let mut block = [ALLOC_POISON; 8];
        if size <= 0 {
            return AllocOutcome {
                returned_null: true,
                first_byte: None,
                second_byte: None,
                status,
                events,
            };
        }
        status[0] = 0;
        if with_trace {
            status[1] = 0;
            events.push(AllocEvent::Trace { null_block: true, size, tag1, tag2, phase: 0 });
        }
        events.push(AllocEvent::Alloc { size, tag1, tag2 });
        if with_trace {
            events.push(AllocEvent::Trace { null_block: fail, size, tag1, tag2, phase: 1 });
        }
        if !fail && size > 0x800 {
            block[0] = tag;
        }
        AllocOutcome {
            returned_null: fail,
            first_byte: (!fail).then_some(block[0]),
            second_byte: (!fail).then_some(block[1]),
            status,
            events,
        }
    }

    #[test]
    fn matches_the_reference_across_sizes_hooks_and_failures() {
        let _guard = ALLOC_TEST_LOCK.lock().unwrap();
        let _reset = AllocHookReset;
        for size in [i32::MIN, -1, 0, 1, 0x14, 0x7ff, 0x800, 0x801, 0x1000, i32::MAX] {
            for with_trace in [false, true] {
                for fail in [false, true] {
                    for tag in [0x61, 0x42] {
                        let got = run_port(size, 0x1111_2222, 0x3333_4444, with_trace, fail, tag);
                        let want = reference(size, 0x1111_2222, 0x3333_4444, with_trace, fail, tag);
                        assert_eq!(
                            got, want,
                            "size {size:#x}, trace {with_trace}, fail {fail}, tag {tag:#x}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn nonpositive_sizes_return_null_without_touching_anything() {
        let _guard = ALLOC_TEST_LOCK.lock().unwrap();
        let _reset = AllocHookReset;
        for size in [0, -1, i32::MIN] {
            let got = run_port(size, 0, 0, true, false, 0x61);
            assert!(got.returned_null, "size {size}");
            assert!(got.events.is_empty(), "size {size}: no trace, no alloc");
            assert_eq!(got.status, [0xdead_beef; 2], "size {size}: status words untouched");
        }
    }

    #[test]
    fn the_stamp_is_strictly_above_0x800() {
        let _guard = ALLOC_TEST_LOCK.lock().unwrap();
        let _reset = AllocHookReset;
        let at = run_port(0x800, 0, 0, false, false, 0x61);
        assert_eq!(at.first_byte, Some(ALLOC_POISON), "0x800 exactly: bgt, not bge");
        let above = run_port(0x801, 0, 0, false, false, 0x61);
        assert_eq!(above.first_byte, Some(0x61));
        assert_eq!(above.second_byte, Some(ALLOC_POISON), "only the first byte is stamped");
    }

    #[test]
    fn the_default_allocator_stub_fails_every_request() {
        let _guard = ALLOC_TEST_LOCK.lock().unwrap();
        let _reset = AllocHookReset;
        unsafe { TRACED_ALLOC_STATUS = [0xdead_beef; 2] };
        assert!(unsafe { traced_alloc(0x14, 0, 0) }.is_null());
        assert_eq!(unsafe { TRACED_ALLOC_STATUS }[0], 0, "status +0x00 still zeroed");
        assert_eq!(
            unsafe { TRACED_ALLOC_STATUS }[1],
            0xdead_beef,
            "no trace hook installed: +0x04 untouched"
        );
    }

    // ---- the traced free --------------------------------------------

    static FREE_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// One observable call into the descriptor, in order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FreeEvent {
        Trace { null_block: bool, phase: u32 },
        Free { null_block: bool },
    }

    static FREE_EVENTS: Mutex<std::vec::Vec<FreeEvent>> = Mutex::new(std::vec::Vec::new());

    static mut FREE_BUFFER: [u8; 8] = [0; 8];

    unsafe extern "C" fn mock_free(block: *mut u8) {
        FREE_EVENTS.lock().unwrap().push(FreeEvent::Free { null_block: block.is_null() });
    }

    unsafe extern "C" fn mock_free_trace(block: *mut u8, phase: u32) {
        FREE_EVENTS
            .lock()
            .unwrap()
            .push(FreeEvent::Trace { null_block: block.is_null(), phase });
    }

    /// The trace slot is re-read after the free: a free that uninstalls
    /// the hook suppresses the post-trace, one that installs it adds it.
    unsafe extern "C" fn free_that_uninstalls_trace(_block: *mut u8) {
        (*core::ptr::addr_of_mut!(TRACED_FREE_HOOKS)).trace = None;
    }

    unsafe extern "C" fn free_that_installs_trace(_block: *mut u8) {
        (*core::ptr::addr_of_mut!(TRACED_FREE_HOOKS)).trace = Some(mock_free_trace);
    }

    /// Restores the default hooks when a test ends (declared after the
    /// guard, so it runs before the lock drops).
    struct FreeHookReset;
    impl Drop for FreeHookReset {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(TRACED_FREE_HOOKS)).free = missing_free;
                (*core::ptr::addr_of_mut!(TRACED_FREE_HOOKS)).trace = None;
            }
        }
    }

    /// Runs the port under the given hooks and collects the events.
    fn run_free(
        block: *mut u8,
        free: unsafe extern "C" fn(*mut u8),
        trace: Option<unsafe extern "C" fn(*mut u8, u32)>,
    ) -> std::vec::Vec<FreeEvent> {
        FREE_EVENTS.lock().unwrap().clear();
        unsafe {
            (*core::ptr::addr_of_mut!(TRACED_FREE_HOOKS)).free = free;
            (*core::ptr::addr_of_mut!(TRACED_FREE_HOOKS)).trace = trace;
            traced_free(block);
        }
        FREE_EVENTS.lock().unwrap().clone()
    }

    /// The reference implementation: the C of
    /// `decomp/c/002/08043994_FUN_08043994.c` (checked against the
    /// disassembly — the "unrecovered jumptable" is just the tail-call
    /// `bxne r2` of the post-free trace) with plain data in place of
    /// the descriptor.
    fn reference_free(null_block: bool, with_trace: bool) -> std::vec::Vec<FreeEvent> {
        let mut events = std::vec::Vec::new();
        if with_trace {
            events.push(FreeEvent::Trace { null_block, phase: 0 });
        }
        events.push(FreeEvent::Free { null_block });
        if with_trace {
            events.push(FreeEvent::Trace { null_block: true, phase: 1 });
        }
        events
    }

    #[test]
    fn brackets_the_free_with_the_two_trace_phases() {
        let _guard = FREE_TEST_LOCK.lock().unwrap();
        let _reset = FreeHookReset;
        let block = unsafe { core::ptr::addr_of_mut!(FREE_BUFFER) as *mut u8 };
        for with_trace in [false, true] {
            let got = run_free(block, mock_free, if with_trace { Some(mock_free_trace) } else { None });
            assert_eq!(got, reference_free(false, with_trace), "with_trace {with_trace}");
        }
    }

    #[test]
    fn passes_a_null_block_verbatim_like_the_original() {
        // No NULL guard anywhere in the original — the 44 `blne` call
        // sites do the guarding, and a NULL that does arrive reaches
        // both the pre-trace and the free untouched.
        let _guard = FREE_TEST_LOCK.lock().unwrap();
        let _reset = FreeHookReset;
        let got = run_free(core::ptr::null_mut(), mock_free, Some(mock_free_trace));
        assert_eq!(got, reference_free(true, true));
    }

    #[test]
    fn rereads_the_trace_slot_after_the_free() {
        let _guard = FREE_TEST_LOCK.lock().unwrap();
        let _reset = FreeHookReset;
        let block = unsafe { core::ptr::addr_of_mut!(FREE_BUFFER) as *mut u8 };
        // Installed before, gone after: only the pre-trace fires.
        let got = run_free(block, free_that_uninstalls_trace, Some(mock_free_trace));
        assert_eq!(got, [FreeEvent::Trace { null_block: false, phase: 0 }]);
        // Absent before, installed after: only the post-trace fires.
        let got = run_free(block, free_that_installs_trace, None);
        assert_eq!(got, [FreeEvent::Trace { null_block: true, phase: 1 }]);
    }

    #[test]
    fn the_default_free_stub_is_a_noop() {
        let _guard = FREE_TEST_LOCK.lock().unwrap();
        let _reset = FreeHookReset;
        FREE_EVENTS.lock().unwrap().clear();
        let block = unsafe { core::ptr::addr_of_mut!(FREE_BUFFER) as *mut u8 };
        unsafe {
            traced_free(block);
            traced_free(core::ptr::null_mut());
        }
        assert!(FREE_EVENTS.lock().unwrap().is_empty(), "no hooks, no calls");
    }
}
