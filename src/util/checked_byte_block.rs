//! Checked byte-block reader family.
//!
//! `checked_byte_block_convert_core` — `FUN_0802b56c` @ 0x0802b56c (104
//! bytes, 0x0802b56c..0x0802b5d4). Decoding every ARM B/BL word in `osos.dec`
//! finds 17 plain unconditional `bl` call sites, zero predicated `bl` forms,
//! and zero direct `B` entries.
//! `checked_byte_block_reader` — `FUN_0802b6a8` @ 0x0802b6a8 (132 bytes).
//! It copies a signed two-dimensional byte block, accumulates its wrapping
//! byte sum, and compares that sum with the following mode-transformed u32
//! checksum. A match advances both input aliases past the checksum and both
//! output aliases past the copied bytes; a mismatch returns 4 without advancing
//! aliases, after the copy. The flat core reads its initial cursors from
//! `input_cursor` and `output_cursor`; the two-dimensional reader uses its
//! mirror slots.
//! `checked_byte_block_reader_3d` — `FUN_0802b7c4` @ 0x0802b7c4 (164 bytes).
//! This distinct three-dimensional reader starts from the primary cursor slots.
//! Deliberate deviation: the mode transform is inlined. Exactly mode 1
//! byte-reverses the checksum; all other modes preserve it.


/// The checksum-mismatch status returned by the retail reader.
pub const BYTE_BLOCK_CHECKSUM_MISMATCH: u32 = 4;

#[inline(always)]
const fn transform_checksum_for_mode(mode: u32, checksum: u32) -> u32 {
    if mode == 1 { checksum.swap_bytes() } else { checksum }
}

/// checked_byte_block_convert_core — original: `FUN_0802b56c` @ 0x0802b56c
/// (104 bytes; 17 plain unconditional `bl` call sites, zero predicated forms).
///
/// Copies `byte_count` bytes from the cursor held by `input_cursor` to the
/// cursor held by `output_cursor`, accumulating their unsigned wrapping sum.
/// The aligned u32 immediately following the source bytes is mode-transformed
/// and compared with that sum. On a match it stores the advanced input cursor,
/// input mirror, output cursor, then output mirror; on mismatch it returns
/// [`BYTE_BLOCK_CHECKSUM_MISMATCH`] without changing aliases, after copying.
///
/// The raw `blt` loop treats `byte_count` as signed: a zero or negative value
/// skips copying and accepts only a transformed zero checksum.
///
/// # Safety
///
/// Cursor slots must be readable/writable. `input_cursor` must initially cover
/// the signed-positive byte count plus an aligned readable checksum word, and
/// `output_cursor` must cover the copied bytes. On success all cursor slots are
/// written.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn checked_byte_block_convert_core(
    mode: u32,
    input_cursor: *mut *mut u8,
    input_cursor_mirror: *mut *mut u8,
    output_cursor: *mut *mut u8,
    output_cursor_mirror: *mut *mut u8,
    byte_count: i32,
) -> u32 {
    let mut source = unsafe { core::ptr::read_volatile(input_cursor) };
    let mut target = unsafe { core::ptr::read_volatile(output_cursor) };
    let mut sum = 0u32;
    let mut index = 0i32;

    while index < byte_count {
        let byte = unsafe { core::ptr::read_volatile(source) };
        sum = sum.wrapping_add(byte as u32);
        unsafe { core::ptr::write_volatile(target, byte) };
        source = unsafe { source.add(1) };
        target = unsafe { target.add(1) };
        index = index.wrapping_add(1);
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
/// checked_byte_block_reader_3d — original: `FUN_0802b7c4` @ 0x0802b7c4
/// (164 bytes, 0x0802b7c4..0x0802b868; 14 plain unconditional `bl` call
/// sites, zero predicated `bl` forms, verified by decoding every ARM B/BL
/// word in `osos.dec`).
///
/// Copies `dim0 * dim1 * dim2` bytes from the cursor in `input_cursor` to
/// `output_cursor` through three signed `blt`-equivalent loops. It accumulates
/// the unsigned wrapping byte sum, transforms the aligned u32 immediately
/// afterward for exact mode 1, then compares it with the sum. A matching
/// checksum advances input cursor, input mirror, output cursor, then output
/// mirror; mismatch returns [`BYTE_BLOCK_CHECKSUM_MISMATCH`] without updating
/// aliases, after the output bytes were written.
///
/// Zero or negative dimensions skip the appropriate loop and therefore require
/// a transformed zero checksum. The 14 stock callers are all unconditional;
/// none guards this reader with a conditional `bl`.
///
/// Deliberate deviation: the byte-identical `FUN_0802b538` mode transform is
/// inlined, as it is in the neighboring byte-block readers.
///
/// # Safety
///
/// Cursor slots must be readable/writable. `input_cursor` must initially cover
/// the signed-positive product of dimensions plus an aligned readable checksum
/// word, and `output_cursor` must cover the copied bytes. On success all four
/// cursor slots are updated.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn checked_byte_block_reader_3d(
    mode: u32,
    input_cursor: *mut *mut u8,
    input_cursor_mirror: *mut *mut u8,
    output_cursor: *mut *mut u8,
    output_cursor_mirror: *mut *mut u8,
    dim0: i32,
    dim1: i32,
    dim2: i32,
) -> u32 {
    let mut source = unsafe { core::ptr::read_volatile(input_cursor) };
    let mut target = unsafe { core::ptr::read_volatile(output_cursor) };
    let mut sum = 0u32;
    let mut i = 0;
    while i < dim0 {
        let mut j = 0;
        while j < dim1 {
            let mut k = 0;
            while k < dim2 {
                let byte = unsafe { core::ptr::read_volatile(source) };
                sum = sum.wrapping_add(byte as u32);
                unsafe { core::ptr::write_volatile(target, byte) };
                source = unsafe { source.add(1) };
                target = unsafe { target.add(1) };
                k = k.wrapping_add(1);
            }
            j = j.wrapping_add(1);
        }
        i = i.wrapping_add(1);
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

        fn run_3d(&mut self, mode: u32, dim0: i32, dim1: i32, dim2: i32) -> u32 {
            unsafe {
                checked_byte_block_reader_3d(
                    mode,
                    &mut self.input,
                    &mut self.input_mirror,
                    &mut self.output,
                    &mut self.output_mirror,
                    dim0,
                    dim1,
                    dim2,
                )
            }
        }

        fn run_flat(&mut self, mode: u32, byte_count: i32) -> u32 {
            unsafe {
                checked_byte_block_convert_core(
                    mode,
                    &mut self.input,
                    &mut self.input_mirror,
                    &mut self.output,
                    &mut self.output_mirror,
                    byte_count,
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
    fn flat_core_copies_bytes_sums_and_advances_all_aliases() {
        let mut block = Block::new(&[0x0403_0201, 10, 0xcccc_cccc], 12);

        assert_eq!(block.run_flat(0, 4), 0, "matching byte sum succeeds");
        assert_eq!(&block.target[..4], &[1, 2, 3, 4]);
        assert_eq!(block.input_offset(block.input), 8, "input advances past checksum");
        assert_eq!(block.input_offset(block.input_mirror), 8, "input mirror is updated");
        assert_eq!(block.output_offset(block.output), 4, "output advances past copied bytes");
        assert_eq!(block.output_offset(block.output_mirror), 4, "output mirror is updated");
    }

    #[test]
    fn flat_core_mode_one_transforms_only_the_checksum() {
        let mut block = Block::new(&[0x4030_2010, 0xa000_0000], 8);

        assert_eq!(block.run_flat(1, 4), 0);
        assert_eq!(&block.target[..4], &[0x10, 0x20, 0x30, 0x40], "data bytes are copied verbatim");
        assert_eq!(block.input_offset(block.input), 8);
    }

    #[test]
    fn flat_core_mismatch_keeps_aliases_after_writing_output() {
        let mut block = Block::new(&[0x0403_0201, 9], 8);

        assert_eq!(block.run_flat(0, 4), BYTE_BLOCK_CHECKSUM_MISMATCH);
        assert_eq!(block.input_offset(block.input), 0);
        assert_eq!(block.input_offset(block.input_mirror), 0);
        assert_eq!(block.output_offset(block.output), 0);
        assert_eq!(block.output_offset(block.output_mirror), 0);
        assert_eq!(&block.target[..4], &[1, 2, 3, 4], "copy precedes comparison");
    }

    #[test]
    fn flat_core_negative_count_checks_zero_without_copying() {
        let mut block = Block::new(&[0u32, 0xaaaa_aaaa], 4);

        assert_eq!(block.run_flat(0, -1), 0, "signed blt leaves a negative count empty");
        assert_eq!(block.input_offset(block.input), 4);
        assert_eq!(block.output_offset(block.output), 0);
        assert_eq!(block.target, [0xad; 4]);
    }

    #[test]
    fn flat_core_reads_primary_cursors_then_updates_mirrors() {
        let mut source = [0x0403_0201u32, 10, 0xcccc_cccc];
        let mut source_mirror = [0xfeed_faceu32; 3];
        let mut target = [0xad_u8; 12];
        let mut target_mirror = [0xbc_u8; 12];
        let mut input = source.as_mut_ptr().cast::<u8>();
        let mut input_mirror = source_mirror.as_mut_ptr().cast::<u8>();
        let mut output = target.as_mut_ptr();
        let mut output_mirror = target_mirror.as_mut_ptr();

        let status = unsafe {
            checked_byte_block_convert_core(0, &mut input, &mut input_mirror, &mut output, &mut output_mirror, 4)
        };

        assert_eq!(status, 0);
        assert_eq!(&target[..4], &[1, 2, 3, 4], "source comes from input_cursor");
        assert_eq!(target_mirror, [0xbc; 12], "target comes from output_cursor");
        assert_eq!(input, unsafe { source.as_mut_ptr().cast::<u8>().add(8) });
        assert_eq!(input_mirror, input);
        assert_eq!(output, unsafe { target.as_mut_ptr().add(4) });
        assert_eq!(output_mirror, output);
    }

    #[test]
    fn byte_wrapper_decodes_leading_word_then_uses_flat_core() {
        let mut source = [0x1020_3040u32, 2, 0xa200_0000, 0xcccc_cccc];
        let mut target = [0xad_u8; 16];
        let mut input = source.as_mut_ptr().cast::<u8>();
        let mut input_mirror = source.as_mut_ptr().cast::<u8>();
        let mut output = target.as_mut_ptr();
        let mut output_mirror = target.as_mut_ptr();
        let mut leading = 0;

        let status = unsafe {
            crate::util::checked_word_block::checked_byte_block_convert(
                1,
                &mut input,
                &mut input_mirror,
                &mut output,
                &mut output_mirror,
                8,
                &mut leading,
            )
        };

        assert_eq!(status, 0);
        assert_eq!(leading, 0x4030_2010, "leading word is mode-transformed");
        assert_eq!(&target[..8], &[0x40, 0x30, 0x20, 0x10, 2, 0, 0, 0]);
        assert_eq!(input, unsafe { source.as_mut_ptr().cast::<u8>().add(12) });
        assert_eq!(output, unsafe { target.as_mut_ptr().add(8) });
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

    #[test]
    fn three_dimensional_reader_copies_sums_and_advances_aliases() {
        let mut block = Block::new(&[0x0403_0201, 10, 0xcccc_cccc], 12);

        assert_eq!(block.run_3d(0, 1, 2, 2), 0);
        assert_eq!(&block.target[..4], &[1, 2, 3, 4]);
        assert_eq!(block.input_offset(block.input), 8);
        assert_eq!(block.input_offset(block.input_mirror), 8);
        assert_eq!(block.output_offset(block.output), 4);
        assert_eq!(block.output_offset(block.output_mirror), 4);
    }

    #[test]
    fn three_dimensional_reader_reverses_only_mode_one_checksum() {
        let mut block = Block::new(&[0x4030_2010, 0xa000_0000], 8);

        assert_eq!(block.run_3d(1, 1, 1, 4), 0);
        assert_eq!(&block.target[..4], &[0x10, 0x20, 0x30, 0x40]);
    }

    #[test]
    fn three_dimensional_reader_mismatch_writes_without_advancing_aliases() {
        let mut block = Block::new(&[0x0403_0201, 9], 8);

        assert_eq!(block.run_3d(0, 2, 1, 2), BYTE_BLOCK_CHECKSUM_MISMATCH);
        assert_eq!(&block.target[..4], &[1, 2, 3, 4]);
        assert_eq!(block.input_offset(block.input), 0);
        assert_eq!(block.input_offset(block.input_mirror), 0);
        assert_eq!(block.output_offset(block.output), 0);
        assert_eq!(block.output_offset(block.output_mirror), 0);
    }

    #[test]
    fn three_dimensional_reader_uses_primary_cursors_and_empty_negative_dimension() {
        let mut source = [0x0403_0201u32, 10, 0xcccc_cccc];
        let mut source_mirror = [0xfeed_faceu32; 3];
        let mut target = [0xad_u8; 12];
        let mut target_mirror = [0xbc_u8; 12];
        let mut input = source.as_mut_ptr().cast::<u8>();
        let mut input_mirror = source_mirror.as_mut_ptr().cast::<u8>();
        let mut output = target.as_mut_ptr();
        let mut output_mirror = target_mirror.as_mut_ptr();

        let status = unsafe {
            checked_byte_block_reader_3d(
                0,
                &mut input,
                &mut input_mirror,
                &mut output,
                &mut output_mirror,
                1,
                1,
                4,
            )
        };

        assert_eq!(status, 0);
        assert_eq!(&target[..4], &[1, 2, 3, 4]);
        assert_eq!(target_mirror, [0xbc; 12]);
        assert_eq!(input, unsafe { source.as_mut_ptr().cast::<u8>().add(8) });
        assert_eq!(input_mirror, input);
        assert_eq!(output, unsafe { target.as_mut_ptr().add(4) });
        assert_eq!(output_mirror, output);

        let mut empty = Block::new(&[0, 0xaaaa_aaaa], 4);
        assert_eq!(empty.run_3d(0, 1, -1, 4), 0);
        assert_eq!(empty.input_offset(empty.input), 4);
        assert_eq!(empty.output_offset(empty.output), 0);
        assert_eq!(empty.target, [0xad; 4]);
    }
}
