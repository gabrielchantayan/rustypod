//! Checked byte-block reader — `FUN_0802b6a8` @ 0x0802b6a8 (132 bytes).
//!
//! Raw ARM spans 0x0802b6a8..0x0802b72c; decoding every ARM B/BL word in
//! `osos.dec` finds 30 plain unconditional `bl` call sites, with no predicated
//! `bl` or direct `B` entries. It copies a signed `row_count * bytes_per_row`
//! byte block, accumulates its wrapping byte sum, and compares that sum with
//! the following mode-transformed u32 checksum. A match advances both input
//! cursor aliases past the checksum and both output aliases past the copied
//! bytes; a mismatch returns 4 without advancing aliases, after the copy.
//!
//! Deliberate deviation: the sole `bl 0x0802b538` mode transform is inlined;
//! exactly mode 1 byte-reverses the checksum word and all other modes preserve
//! it. This matches the sibling checked-word block ports.

/// The checksum-mismatch status returned by the retail reader.
pub const BYTE_BLOCK_CHECKSUM_MISMATCH: u32 = 4;

#[inline(always)]
const fn transform_checksum_for_mode(mode: u32, checksum: u32) -> u32 {
    if mode == 1 { checksum.swap_bytes() } else { checksum }
}

/// checked_byte_block_reader — original: `FUN_0802b6a8` @ 0x0802b6a8
/// (132 bytes, 30 plain unconditional `bl` call sites).
///
/// Copies `row_count * bytes_per_row` bytes from the cursor held by
/// `input_cursor_mirror` to the cursor held by `output_cursor_mirror`, adding
/// each byte into a wrapping u32 sum. The aligned u32 immediately following
/// the source block is mode-transformed and compared with that sum. On a
/// match, stores the advanced input cursor then input mirror, followed by the
/// advanced output cursor then output mirror, and returns zero. On mismatch,
/// returns [`BYTE_BLOCK_CHECKSUM_MISMATCH`] without changing any alias.
///
/// The raw `blt` loop bounds are signed: a zero or negative bound leaves the
/// corresponding loop empty, so the checksum must transform to zero.
///
/// # Safety
///
/// Cursor slots must be readable/writable. Their initial cursors must cover
/// the signed-positive byte count; the checksum word at the resulting input
/// cursor must be aligned and readable. The destination must cover the copied
/// byte count.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn checked_byte_block_reader(
    mode: u32,
    input_cursor: *mut *mut u8,
    input_cursor_mirror: *mut *mut u8,
    output_cursor: *mut *mut u8,
    output_cursor_mirror: *mut *mut u8,
    row_count: i32,
    bytes_per_row: i32,
) -> u32 {
    let mut source = unsafe { core::ptr::read_volatile(input_cursor_mirror) };
    let mut target = unsafe { core::ptr::read_volatile(output_cursor_mirror) };
    let mut sum = 0u32;
    let mut row = 0;

    while row < row_count {
        let mut column = 0;
        while column < bytes_per_row {
            let byte = unsafe { core::ptr::read_volatile(source) };
            sum = sum.wrapping_add(byte as u32);
            unsafe { core::ptr::write_volatile(target, byte) };
            source = unsafe { source.add(1) };
            target = unsafe { target.add(1) };
            column = column.wrapping_add(1);
        }
        row = row.wrapping_add(1);
    }

    let checksum = transform_checksum_for_mode(mode, unsafe {
        core::ptr::read_volatile(source.cast::<u32>())
    });
    if checksum != sum {
        return BYTE_BLOCK_CHECKSUM_MISMATCH;
    }

    let advanced_source = unsafe { source.add(core::mem::size_of::<u32>()) };
    unsafe {
        core::ptr::write_volatile(input_cursor, advanced_source);
        core::ptr::write_volatile(input_cursor_mirror, advanced_source);
        core::ptr::write_volatile(output_cursor, target);
        core::ptr::write_volatile(output_cursor_mirror, target);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    struct Block {
        source: std::vec::Vec<u32>,
        target: std::vec::Vec<u8>,
        input: *mut u8,
        input_mirror: *mut u8,
        output: *mut u8,
        output_mirror: *mut u8,
    }

    impl Block {
        fn new(words: &[u32], target_len: usize) -> Self {
            let mut source = words.to_vec();
            let source_ptr = source.as_mut_ptr().cast::<u8>();
            let mut target = std::vec![0xad_u8; target_len];
            let target_ptr = target.as_mut_ptr();
            Self {
                source,
                target,
                input: source_ptr,
                input_mirror: source_ptr,
                output: target_ptr,
                output_mirror: target_ptr,
            }
        }

        fn run(&mut self, mode: u32, row_count: i32, bytes_per_row: i32) -> u32 {
            unsafe {
                checked_byte_block_reader(
                    mode,
                    &mut self.input,
                    &mut self.input_mirror,
                    &mut self.output,
                    &mut self.output_mirror,
                    row_count,
                    bytes_per_row,
                )
            }
        }

        fn input_offset(&self, cursor: *mut u8) -> usize {
            cursor as usize - self.source.as_ptr() as usize
        }

        fn output_offset(&self, cursor: *mut u8) -> usize {
            cursor as usize - self.target.as_ptr() as usize
        }
    }

    #[test]
    fn copies_rows_checks_sum_and_advances_every_alias() {
        let mut block = Block::new(&[0x0403_0201, 10, 0xcccc_cccc], 12);
        let status = block.run(0, 2, 2);

        assert_eq!(status, 0, "matching checksum succeeds");
        assert_eq!(&block.target[..4], &[1, 2, 3, 4], "bytes copy in source order");
        assert_eq!(block.input_offset(block.input), 8, "input advances past checksum");
        assert_eq!(block.input_offset(block.input_mirror), 8, "input mirror advances too");
        assert_eq!(block.output_offset(block.output), 4, "output advances past copied bytes");
        assert_eq!(block.output_offset(block.output_mirror), 4, "output mirror advances too");
    }

    #[test]
    fn mode_one_transforms_the_checksum_before_comparing() {
        let mut block = Block::new(&[0x4030_2010, 0xa000_0000], 12);
        let status = block.run(1, 1, 4);

        assert_eq!(status, 0, "byte-reversed checksum 0xa0 matches 16+32+48+64");
        assert_eq!(&block.target[..4], &[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(block.input_offset(block.input), 8);
    }

    #[test]
    fn mismatch_keeps_aliases_but_leaves_the_copy_written() {
        let mut block = Block::new(&[0x0403_0201, 9, 0xcccc_cccc], 12);
        let status = block.run(0, 1, 4);

        assert_eq!(status, BYTE_BLOCK_CHECKSUM_MISMATCH);
        assert_eq!(block.input_offset(block.input), 0, "input remains unchanged");
        assert_eq!(block.input_offset(block.input_mirror), 0, "input mirror remains unchanged");
        assert_eq!(block.output_offset(block.output), 0, "output remains unchanged");
        assert_eq!(block.output_offset(block.output_mirror), 0, "output mirror remains unchanged");
        assert_eq!(&block.target[..4], &[1, 2, 3, 4], "copy happens before comparison");
    }

    #[test]
    fn negative_bound_reads_only_a_zero_checksum() {
        let mut block = Block::new(&[0, 0xaaaa_aaaa], 4);
        let status = block.run(0, 3, -1);

        assert_eq!(status, 0, "signed blt makes a negative inner bound empty");
        assert_eq!(block.input_offset(block.input), 4);
        assert_eq!(block.output_offset(block.output), 0);
        assert_eq!(block.target, [0xad; 4]);
    }
}
