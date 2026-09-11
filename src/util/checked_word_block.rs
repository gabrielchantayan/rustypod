//! Checked binary word-block reader family.
//!
//! `checked_byte_block_convert` — `FUN_0802b654` @ 0x0802b654 (84 bytes,
//! 0x0802b654..0x0802b6a8; 54 `bl` call sites, no tail branches).
//! `checked_word_block_convert_3d` — `FUN_0802b868` @ 0x0802b868 (188
//! bytes, 0x0802b868..0x0802b924; 31 `bl` call sites, all unconditional,
//! binary-scanned).
//!
//! The byte wrapper decodes one leading mode-transformed word through
//! `input_cursor_mirror`, then invokes the flat byte-block checksum core at
//! 0x0802b56c. The word core below is the distinct three-dimensional variant.
//! Every word and its checksum call `transform_checked_word_for_mode`
//! (0x0802b538): only exact mode 1 reverses four byte lanes.



use crate::util::bswap::transform_checked_word_for_mode;

/// The core's checksum-mismatch result.
pub const CHECKSUM_MISMATCH: u32 = 4;




/// checked_byte_block_convert — original: `FUN_0802b654` @ 0x0802b654
/// (84 bytes; 54 `bl` call sites).
///
/// Decodes and stores the current leading input word, then passes all cursor
/// slots and the signed byte count to [`crate::util::checked_byte_block::
/// checked_byte_block_convert_core`].
///
/// # Safety
/// `input_cursor_mirror` and its current aligned word must be readable,
/// `out_leading_word` writable, and all cursor aliases valid for the byte core.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn checked_byte_block_convert(
    mode: u32,
    input_cursor: *mut *mut u8,
    input_cursor_mirror: *mut *mut u8,
    output_cursor: *mut *mut u8,
    output_cursor_mirror: *mut *mut u8,
    byte_count: i32,
    out_leading_word: *mut u32,
) -> u32 {
    let source = unsafe { core::ptr::read_volatile(input_cursor_mirror) };
    let leading = transform_checked_word_for_mode(mode, unsafe {
        core::ptr::read_volatile(source.cast::<u32>())
    });
    unsafe { core::ptr::write_volatile(out_leading_word, leading) };
    unsafe {
        crate::util::checked_byte_block::checked_byte_block_convert_core(
            mode,
            input_cursor,
            input_cursor_mirror,
            output_cursor,
            output_cursor_mirror,
            byte_count,
        )
    }
}
/// checked_word_block_convert_core — original: `FUN_0802b5d4` @ 0x0802b5d4
/// (128 bytes; 9 plain unconditional `bl` call sites, zero predicated forms).
///
/// Converts `word_count` aligned words from the cursor held by
/// `input_cursor_mirror`, storing each mode-transformed word through the cursor
/// held by `output_cursor_mirror` while accumulating their wrapping sum. It
/// compares that sum with the transformed following word. A match advances
/// input cursor, input mirror, output cursor, then output mirror; a mismatch
/// returns [`CHECKSUM_MISMATCH`] without advancing aliases after its output
/// writes.
///
/// The original's `blt` loop makes `word_count` signed: zero or negative
/// counts convert no words and require a transformed zero checksum. Exactly
/// mode 1 reverses each word through
/// [`transform_checked_word_for_mode`]; all other modes preserve it. No
/// deliberate deviations.
///
/// # Safety
/// `input_cursor_mirror` and `output_cursor_mirror` must be readable and hold
/// cursors valid for the signed-positive word count plus one aligned checksum
/// word of input. All four cursor slots must be writable on success.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn checked_word_block_convert_core(
    mode: u32,
    input_cursor: *mut *mut u32,
    input_cursor_mirror: *mut *mut u32,
    output_cursor: *mut *mut u32,
    output_cursor_mirror: *mut *mut u32,
    word_count: i32,
) -> u32 {
    let mut source = unsafe { core::ptr::read_volatile(input_cursor_mirror) };
    let mut target = unsafe { core::ptr::read_volatile(output_cursor_mirror) };
    let mut sum = 0u32;
    let mut index = 0i32;
    while index < word_count {
        let word = transform_checked_word_for_mode(mode, unsafe { core::ptr::read_volatile(source) });
        sum = sum.wrapping_add(word);
        source = unsafe { source.add(1) };
        unsafe { core::ptr::write_volatile(target, word) };
        target = unsafe { target.add(1) };
        index = index.wrapping_add(1);
    }
    let checksum = transform_checked_word_for_mode(mode, unsafe { core::ptr::read_volatile(source) });
    if checksum != sum {
        return CHECKSUM_MISMATCH;
    }
    let advanced_source = unsafe { source.add(1) };
    unsafe {
        core::ptr::write_volatile(input_cursor, advanced_source);
        core::ptr::write_volatile(input_cursor_mirror, advanced_source);
        core::ptr::write_volatile(output_cursor, target);
        core::ptr::write_volatile(output_cursor_mirror, target);
    }
    0
}


/// checked_word_block_convert_3d — original: `FUN_0802b868` @ 0x0802b868
/// (188 bytes, 0x0802b868..0x0802b924; 31 `bl` call sites, every one a
/// plain unconditional `bl`, verified by decoding every B/BL word in
/// osos.dec).
///
/// Three-dimensional word-block decoder: converts `dim0 * dim1 * dim2` words
/// with the mode-controlled transform, stores them through the output cursor in
/// row-major order while accumulating their wrapping 32-bit sum, then
/// transforms the next input word and compares it against that sum. On a
/// match it advances BOTH input aliases to one word past the checksum word
/// and BOTH output aliases past the last written word (input cursor, input
/// mirror, output cursor, output mirror — in that store order) and returns
/// 0; on a mismatch it returns [`CHECKSUM_MISMATCH`] with all four aliases
/// untouched, although the transformed words are already in the output
/// buffer. The initial input position is read from `input_cursor_mirror`
/// and the initial output position from `output_cursor_mirror`, each
/// exactly once.
///
/// Loop bounds are signed (`blt` in the original): a zero or negative
/// dimension skips its whole nest, so e.g. `dim1 == 0` converts no words
/// and the leading input word must transform to 0 for the block to be
/// accepted. All 31 callers pass positive compile-time-constant dimensions
/// (typically 8/2/256), so the degenerate paths are binary-verified but
/// not exercised by stock firmware.
///
/// Every mode transform calls the separately ported
/// [`crate::util::bswap::transform_checked_word_for_mode`], retaining the
/// original's distinct `bl` target.
///
/// # Safety
/// `input_cursor_mirror` and `output_cursor_mirror` must be readable and
/// hold cursors valid for `dim0 * dim1 * dim2` aligned words plus one
/// checksum word of input; on success all four alias pointers are written.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn checked_word_block_convert_3d(
    mode: u32,
    input_cursor: *mut *mut u32,
    input_cursor_mirror: *mut *mut u32,
    output_cursor: *mut *mut u32,
    output_cursor_mirror: *mut *mut u32,
    dim0: i32,
    dim1: i32,
    dim2: i32,
) -> u32 {
    let mut source = unsafe { core::ptr::read_volatile(input_cursor_mirror) };
    let mut target = unsafe { core::ptr::read_volatile(output_cursor_mirror) };
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < dim0 {
        let mut j = 0;
        while j < dim1 {
            let mut k = 0;
            while k < dim2 {
                let word = transform_checked_word_for_mode(mode, unsafe { core::ptr::read_volatile(source) });
                sum = sum.wrapping_add(word);
                source = unsafe { source.add(1) };
                unsafe { core::ptr::write_volatile(target, word) };
                target = unsafe { target.add(1) };
                k += 1;
            }
            j += 1;
        }
        i += 1;
    }
    let checksum = transform_checked_word_for_mode(mode, unsafe { core::ptr::read_volatile(source) });
    if checksum != sum {
        return CHECKSUM_MISMATCH;
    }
    let advanced_source = unsafe { source.add(1) };
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
        target: std::vec::Vec<u32>,
        input: *mut u32,
        input_mirror: *mut u32,
        output: *mut u32,
        output_mirror: *mut u32,
    }

    impl Block {
        fn new(words: &[u32]) -> Block {
            let source = words.to_vec();
            let target = std::vec![0xdead_beefu32; words.len()];
            let mut block = Block { source, target, input: core::ptr::null_mut(), input_mirror: core::ptr::null_mut(), output: core::ptr::null_mut(), output_mirror: core::ptr::null_mut() };
            block.input = block.source.as_mut_ptr();
            block.input_mirror = block.source.as_mut_ptr();
            block.output = block.target.as_mut_ptr();
            block.output_mirror = block.target.as_mut_ptr();
            block
        }

        fn run(&mut self, mode: u32, dim0: i32, dim1: i32, dim2: i32) -> u32 {
            unsafe {
                checked_word_block_convert_3d(
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


        fn source_offset(&self, cursor: *mut u32) -> usize {
            (cursor as usize - self.source.as_ptr() as usize) / core::mem::size_of::<u32>()
        }

        fn target_offset(&self, cursor: *mut u32) -> usize {
            (cursor as usize - self.target.as_ptr() as usize) / core::mem::size_of::<u32>()
        }
    }

    #[test]
    fn core_uses_mirror_cursors_and_advances_all_aliases_after_mode_one_success() {
        let data = [0x1020_3040u32, 0xa0b0_c0d0, 0x0000_00ff];
        let sum = data.iter().fold(0u32, |acc, word| acc.wrapping_add(word.swap_bytes()));
        let mut words = data.to_vec();
        words.push(sum.swap_bytes());
        let mut block = Block::new(&words);
        block.input = unsafe { block.source.as_mut_ptr().add(2) };
        block.output = unsafe { block.target.as_mut_ptr().add(2) };

        let status = unsafe {
            checked_word_block_convert_core(
                1,
                &mut block.input,
                &mut block.input_mirror,
                &mut block.output,
                &mut block.output_mirror,
                3,
            )
        };

        assert_eq!(status, 0);
        assert_eq!(&block.target[..3], &[0x4030_2010, 0xd0c0_b0a0, 0xff00_0000]);
        assert_eq!(block.source_offset(block.input), 4);
        assert_eq!(block.source_offset(block.input_mirror), 4);
        assert_eq!(block.target_offset(block.output), 3);
        assert_eq!(block.target_offset(block.output_mirror), 3);
    }

    #[test]
    fn core_mismatch_writes_words_but_leaves_distinct_aliases_unchanged() {
        let mut block = Block::new(&[10u32, 20, 0]);
        block.input = unsafe { block.source.as_mut_ptr().add(2) };
        block.output = unsafe { block.target.as_mut_ptr().add(2) };

        let status = unsafe {
            checked_word_block_convert_core(
                0,
                &mut block.input,
                &mut block.input_mirror,
                &mut block.output,
                &mut block.output_mirror,
                2,
            )
        };

        assert_eq!(status, CHECKSUM_MISMATCH);
        assert_eq!(&block.target[..2], &[10, 20]);
        assert_eq!(block.source_offset(block.input), 2);
        assert_eq!(block.source_offset(block.input_mirror), 0);
        assert_eq!(block.target_offset(block.output), 2);
        assert_eq!(block.target_offset(block.output_mirror), 0);
    }

    #[test]
    fn core_negative_count_checks_only_zero_checksum() {
        let mut block = Block::new(&[0u32, 0xaaaa_aaaa]);
        let status = unsafe {
            checked_word_block_convert_core(
                9,
                &mut block.input,
                &mut block.input_mirror,
                &mut block.output,
                &mut block.output_mirror,
                -7,
            )
        };

        assert_eq!(status, 0);
        assert_eq!(block.source_offset(block.input), 1);
        assert_eq!(block.source_offset(block.input_mirror), 1);
        assert_eq!(block.target_offset(block.output), 0);
        assert_eq!(block.target_offset(block.output_mirror), 0);
        assert_eq!(block.target[0], 0xdead_beef);
    }

    #[test]
    fn convert_3d_mode_zero_copies_sums_and_advances_all_four_aliases() {
        // 2*3*2 = 12 data words followed by their plain sum as checksum.
        let data = [1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let sum: u32 = data.iter().sum();
        let mut words = data.to_vec();
        words.push(sum);
        words.push(0xcccc_cccc); // unread sentinel past the checksum word
        let mut block = Block::new(&words);
        let status = block.run(0, 2, 3, 2);
        assert_eq!(status, 0, "matching checksum returns success");
        assert_eq!(&block.target[..12], &data, "mode 0 copies words unchanged in row-major order");
        assert_eq!(block.source_offset(block.input), 13, "input alias lands one word past the checksum");
        assert_eq!(block.source_offset(block.input_mirror), 13, "input mirror receives the same advance");
        assert_eq!(block.target_offset(block.output), 12, "output alias lands past the last written word");
        assert_eq!(block.target_offset(block.output_mirror), 12, "output mirror receives the same advance");
    }

    #[test]
    fn convert_3d_mode_one_byte_reverses_and_checks_the_transformed_sum() {
        let data = [0x1020_3040u32, 0xa0b0_c0d0, 0x0000_00ff, 0x8000_0001, 5, 6];
        let sum = data.iter().fold(0u32, |acc, w| acc.wrapping_add(w.swap_bytes()));
        let mut words = data.to_vec();
        words.push(sum.swap_bytes()); // checksum word transforms to the sum
        let mut block = Block::new(&words);
        let status = block.run(1, 1, 2, 3);
        assert_eq!(status, 0, "mode 1 compares the transformed checksum against the transformed sum");
        let expected: std::vec::Vec<u32> = data.iter().map(|w| w.swap_bytes()).collect();
        assert_eq!(&block.target[..6], &expected[..], "mode 1 stores byte-reversed words");
        assert_eq!(block.source_offset(block.input), 7);
        assert_eq!(block.target_offset(block.output), 6);
    }

    #[test]
    fn convert_3d_mismatch_returns_4_without_advancing_but_output_stays_written() {
        let words = [10u32, 20, 30, 40, 0x1234_5678]; // checksum does not match the sum
        let mut block = Block::new(&words);
        let status = block.run(0, 2, 1, 2);
        assert_eq!(status, CHECKSUM_MISMATCH, "mismatched checksum returns 4");
        assert_eq!(block.source_offset(block.input), 0, "input alias not advanced on mismatch");
        assert_eq!(block.source_offset(block.input_mirror), 0, "input mirror not advanced on mismatch");
        assert_eq!(block.target_offset(block.output), 0, "output alias not advanced on mismatch");
        assert_eq!(block.target_offset(block.output_mirror), 0, "output mirror not advanced on mismatch");
        assert_eq!(&block.target[..4], &[10, 20, 30, 40], "transformed words are already in the output buffer");
    }

    #[test]
    fn convert_3d_zero_outer_dim_consumes_only_the_checksum_word() {
        let words = [0u32, 0xaaaa_aaaa]; // empty block: checksum word 0 matches sum 0
        let mut block = Block::new(&words);
        let status = block.run(0, 0, 5, 9);
        assert_eq!(status, 0, "dim0 == 0 leaves an empty block whose checksum must be 0");
        assert_eq!(block.source_offset(block.input), 1, "input advances past the checksum word alone");
        assert_eq!(block.source_offset(block.input_mirror), 1);
        assert_eq!(block.target_offset(block.output), 0, "no words written, output cursor unmoved but stored");
        assert_eq!(block.target[0], 0xdead_beef, "output buffer untouched");
    }

    #[test]
    fn convert_3d_negative_middle_dim_skips_the_nest_under_mode_one() {
        let words = [0u32, 7, 8];
        let mut block = Block::new(&words);
        let status = block.run(1, 3, -1, 7);
        assert_eq!(status, 0, "signed blt skips the whole nest; bswap(0) == 0 matches the empty sum");
        assert_eq!(block.source_offset(block.input), 1);
        assert_eq!(block.target_offset(block.output), 0);
    }

    #[test]
    fn convert_3d_empty_block_rejects_a_nonzero_checksum() {
        let words = [0x2au32, 0];
        let mut block = Block::new(&words);
        let status = block.run(0, 4, 2, -3);
        assert_eq!(status, CHECKSUM_MISMATCH, "negative inner dim empties the block; 42 != 0");
        assert_eq!(block.source_offset(block.input), 0, "aliases stay put on mismatch");
    }

    #[test]
    fn convert_3d_sum_wraps_mod_2_to_the_32() {
        let data = [0xffff_ffffu32, 2];
        let mut words = data.to_vec();
        words.push(1); // wrapping sum of the two data words
        let mut block = Block::new(&words);
        let status = block.run(0, 1, 1, 2);
        assert_eq!(status, 0, "the accumulated sum wraps like ARM's 32-bit add");
        assert_eq!(&block.target[..2], &data);
        assert_eq!(block.source_offset(block.input), 3);
    }
}
