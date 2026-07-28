//! `surface_config_init` — original: `FUN_08120604` @ 0x08120604
//! (80 bytes; 15 `bl` call sites + 1 tail `b`, binary-scanned).
//!
//! Default constructor for the **display-layer configuration
//! descriptor**: the 0x40-byte stack block every caller fills in and
//! hands to the layer applier `FUN_08120978`, which copies it into the
//! live layer object obtained from `FUN_081d9064(display, layer)`.
//!
//! (Provenance correction: the earlier scouting note filed this under
//! "the ATA command-block cluster" purely on address adjacency to the
//! taskfile setters in drivers/ata_cmd.rs. It is not storage. Every
//! caller is display code — e.g. the boot-screen setup @ 0x0816e500 and
//! @ 0x0829635c both init this block and then store width 0x140 = 320
//! and height 0xf0 = 240, the Classic 6G panel size, before applying it
//! to layer 1.)
//!
//! Recovered field map, with the applier's destination in the layer
//! object in brackets:
//!
//! ```text
//! +0x00 u8   pixel format          [layer +0x0a; the value 3 also
//!                                   forces layer +0x49 = 2]
//! +0x01 u8   format variant        [layer +0x0b]
//! +0x04 i32  origin x              [layer +0x0c, clamped >= 0]
//! +0x08 i32  origin y              [layer +0x10, clamped >= 0]
//! +0x0c i32  width                 [layer +0x1c, clamped >= 0]
//! +0x10 i32  height                [layer +0x20, clamped >= 0]
//! +0x14 i32  buffer width          [layer +0x30, clamped >= width]
//! +0x18 i32  buffer height         [layer +0x2c, clamped >= height]
//! +0x1c i32  display width         -1 = auto (see below)
//! +0x20 i32  display height        -1 = auto
//! +0x24 i32  source offset y       [layer +0x18]   (inferred pairing)
//! +0x28 i32  source offset x       [layer +0x14]   (inferred pairing)
//! +0x2c u8   flag                  [layer +0x34]
//! +0x2d u8   flag                  [layer +0x46]
//! +0x30 u32  (opaque)              [layer +0x3c]
//! +0x34..+0x3f                     [layer +0x1be/+0x1c0/+0x1c4] —
//!                                   left uninitialized by this ctor
//! ```
//!
//! The two -1s are the reason this is a constructor and not a `memset`:
//! the applier treats `display width == -1` as *auto* and writes the
//! resolved buffer width / height back into the caller's block before
//! forwarding them to layer +0x24/+0x28. Any other value is taken
//! literally. Bytes +0x02/+0x03, +0x2e/+0x2f and everything from +0x34
//! up are deliberately left untouched (proven by the tests).
//!
//! Offsets are literal byte offsets into a `*mut u8`, as in
//! drivers/ata_cmd.rs: the block holds no pointer fields, so nothing
//! shifts on a 64-bit test host. Store order matches the original
//! (not observable — all fields are distinct — but free to keep).
//!
//! The stores are `write_volatile`. Plain writes let LLVM's memset
//! idiom recognition collapse the +0x04..+0x18 zero run into a call to
//! `__aeabi_memclr` (a symbol that does not exist here — the same trap
//! `strcat.rs` / `strlen_safe.rs` document) and then lower the rest to
//! byte stores; volatile reproduces the original's aligned word `str`
//! sequence exactly. Like the original's `str`, this requires a
//! 4-byte-aligned block — every caller passes an aligned stack local.

/// Default pixel-format byte (+0x00).
pub const DEFAULT_PIXEL_FORMAT: u8 = 2;

/// Default format-variant byte (+0x01).
pub const DEFAULT_FORMAT_VARIANT: u8 = 3;

/// Value the applier reads as "auto": resolve from the buffer size.
pub const SIZE_AUTO: u32 = 0xffff_ffff;

/// surface_config_init — original: `FUN_08120604` @ 0x08120604
/// (80 bytes).
///
/// Resets a display-layer configuration block to its defaults: format
/// 2 / variant 3, all geometry zero, and the display size pair armed
/// with the -1 "auto" sentinel.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn surface_config_init(config: *mut u8) {
    let byte = |offset: usize, value: u8| config.add(offset).write_volatile(value);
    let word = |offset: usize, value: u32| (config.add(offset) as *mut u32).write_volatile(value);

    byte(0x00, DEFAULT_PIXEL_FORMAT);
    byte(0x01, DEFAULT_FORMAT_VARIANT);
    word(0x04, 0); // origin x
    word(0x08, 0); // origin y
    word(0x0c, 0); // width
    word(0x10, 0); // height
    word(0x14, 0); // buffer width
    word(0x18, 0); // buffer height
    word(0x1c, SIZE_AUTO); // display width
    word(0x24, 0); // source offset y
    word(0x20, SIZE_AUTO); // display height
    word(0x28, 0); // source offset x
    byte(0x2c, 0);
    byte(0x2d, 0);
    word(0x30, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 0x40-byte block, word-aligned like every caller's stack
    /// local (the original stores with `str`).
    #[repr(align(4))]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Block([u8; 0x40]);

    fn poisoned() -> Block {
        Block([0xa5; 0x40])
    }

    fn word_at(block: &Block, offset: usize) -> u32 {
        u32::from_le_bytes(block.0[offset..offset + 4].try_into().unwrap())
    }

    fn init(block: &mut Block) {
        unsafe { surface_config_init(block.0.as_mut_ptr()) };
    }

    #[test]
    fn the_two_format_bytes_get_their_defaults() {
        let mut block = poisoned();
        init(&mut block);
        assert_eq!(block.0[0x00], 2);
        assert_eq!(block.0[0x01], 3);
    }

    #[test]
    fn every_geometry_word_is_zeroed() {
        let mut block = poisoned();
        init(&mut block);
        for offset in [0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x24, 0x28, 0x30] {
            assert_eq!(word_at(&block, offset), 0, "word +{offset:#x}");
        }
    }

    #[test]
    fn the_display_size_pair_is_armed_with_the_auto_sentinel() {
        let mut block = poisoned();
        init(&mut block);
        assert_eq!(word_at(&block, 0x1c), 0xffff_ffff);
        assert_eq!(word_at(&block, 0x20), 0xffff_ffff);
    }

    #[test]
    fn the_two_flag_bytes_are_cleared() {
        let mut block = poisoned();
        init(&mut block);
        assert_eq!(block.0[0x2c], 0);
        assert_eq!(block.0[0x2d], 0);
    }

    #[test]
    fn the_gaps_and_the_tail_are_left_untouched() {
        let mut block = poisoned();
        init(&mut block);
        // +0x02/+0x03 sit between the format bytes and the first word;
        // +0x2e/+0x2f between the flag bytes and +0x30; +0x34.. is the
        // applier's opaque tail. The original writes none of them.
        for offset in [0x02, 0x03, 0x2e, 0x2f] {
            assert_eq!(block.0[offset], 0xa5, "byte +{offset:#x}");
        }
        assert!(block.0[0x34..0x40].iter().all(|&b| b == 0xa5), "tail +0x34..+0x40");
    }

    #[test]
    fn the_whole_block_matches_a_byte_for_byte_reference() {
        let mut expected = poisoned();
        expected.0[0x00] = 2;
        expected.0[0x01] = 3;
        for offset in [0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x24, 0x28, 0x30] {
            expected.0[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        }
        for offset in [0x1c, 0x20] {
            expected.0[offset..offset + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        }
        expected.0[0x2c] = 0;
        expected.0[0x2d] = 0;

        let mut block = poisoned();
        init(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn init_is_idempotent() {
        let mut once = poisoned();
        init(&mut once);
        let mut twice = once;
        init(&mut twice);
        assert_eq!(once, twice);
    }
}
