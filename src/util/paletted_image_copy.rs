//! Port of the `0x1888` paletted-image copy helper `FUN_08144730` @
//! `0x08144730`.
//!
//! `paletted_image_copy` — original: `FUN_08144730` @ **0x08144730**
//! (220 bytes; `0x08144730..0x0814480b`, followed by a literal pool word;
//! the next function begins at `0x08144810`). A complete aligned ARM
//! B/BL-immediate decode of `osos.dec` finds five direct inbound `bl` call
//! sites, all unconditional plain `bl`, and no predicated `bl` forms.
//!
//! Copies columns `6..154` of each source row (160 words wide), forcing every
//! output word's alpha byte to `0xff`. Modes 2 and 3 write the rotated layout
//! `destination[(column + 10) * 180 + 169 - row]`; all other modes write the
//! linear layout `destination[450 + row * 180 + column + 10]`. The signed ARM
//! row comparison makes an empty or descending range a no-op.
//!
//! # Deliberate deviations
//!
//! None. Volatile word accesses preserve the retailOS per-pixel load/store
//! order and prevent LLVM from replacing either loop with a bulk copy.

const SOURCE_ROW_WORDS: u32 = 160;
const DESTINATION_ROW_WORDS: u32 = 180;
const FIRST_COLUMN: u32 = 6;
const COLUMN_END: u32 = 154;
const LINEAR_DESTINATION_BASE: u32 = 450;

/// Copies a row range from a `0x1888` paletted image into its display layout.
///
/// # Safety
///
/// `source` and `destination` must identify readable and writable aligned
/// word storage for every address selected by `first_row..end_row`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn paletted_image_copy(
    _unused: u32,
    mode: u32,
    source: *const u32,
    destination: *mut u32,
    first_row: u32,
    end_row: u32,
) {
    let mut row = first_row;
    while (row as i32) < (end_row as i32) {
        let mut column = FIRST_COLUMN;
        while column < COLUMN_END {
            let pixel = core::ptr::read_volatile(source.add(
                row.wrapping_mul(SOURCE_ROW_WORDS).wrapping_add(column) as usize,
            )) | 0xff00_0000;
            let destination_index = if mode == 2 || mode == 3 {
                column
                    .wrapping_add(10)
                    .wrapping_mul(DESTINATION_ROW_WORDS)
                    .wrapping_add(169)
                    .wrapping_sub(row)
            } else {
                LINEAR_DESTINATION_BASE
                    .wrapping_add(row.wrapping_mul(DESTINATION_ROW_WORDS))
                    .wrapping_add(column)
                    .wrapping_add(10)
            };
            core::ptr::write_volatile(destination.add(destination_index as usize), pixel);
            column = column.wrapping_add(1);
        }
        row = row.wrapping_add(1);
    }
}


#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec;
    use std::vec::Vec;
    use super::*;

    fn source_words(rows: usize) -> Vec<u32> {
        (0..rows * SOURCE_ROW_WORDS as usize)
            .map(|index| 0x0012_0000 | index as u32)
            .collect()
    }

    #[test]
    fn linear_layout_copies_only_the_interior_columns_and_forces_alpha() {
        let source = source_words(3);
        let mut destination = vec![0xdead_beef; 1_000];
        unsafe { paletted_image_copy(0, 1, source.as_ptr(), destination.as_mut_ptr(), 1, 3) };

        for row in 1..3u32 {
            for column in FIRST_COLUMN..COLUMN_END {
                let index = (LINEAR_DESTINATION_BASE + row * DESTINATION_ROW_WORDS + column + 10) as usize;
                assert_eq!(destination[index], source[(row * SOURCE_ROW_WORDS + column) as usize] | 0xff00_0000);
            }
        }
        assert_eq!(destination[LINEAR_DESTINATION_BASE as usize + 1 * 180 + 15], 0xdead_beef);
        assert_eq!(destination[999], 0xdead_beef);
    }

    #[test]
    fn modes_two_and_three_select_the_same_rotated_layout() {
        let source = source_words(2);
        let mut mode_two = vec![0xdead_beef; 30_000];
        let mut mode_three = mode_two.clone();
        unsafe {
            paletted_image_copy(0, 2, source.as_ptr(), mode_two.as_mut_ptr(), 0, 2);
            paletted_image_copy(0, 3, source.as_ptr(), mode_three.as_mut_ptr(), 0, 2);
        }

        assert_eq!(mode_two, mode_three);
        for row in 0..2u32 {
            for column in FIRST_COLUMN..COLUMN_END {
                let index = ((column + 10) * DESTINATION_ROW_WORDS + 169 - row) as usize;
                assert_eq!(mode_two[index], source[(row * SOURCE_ROW_WORDS + column) as usize] | 0xff00_0000);
            }
        }
    }

    #[test]
    fn empty_and_descending_signed_ranges_do_not_touch_destination() {
        let source = source_words(1);
        let mut destination = vec![0xdead_beef; 1_000];
        unsafe {
            paletted_image_copy(0, 0, source.as_ptr(), destination.as_mut_ptr(), 1, 1);
            paletted_image_copy(0, 0, source.as_ptr(), destination.as_mut_ptr(), 1, 0);
            paletted_image_copy(0, 0, source.as_ptr(), destination.as_mut_ptr(), 0, 0x8000_0000);
        }
        assert!(destination.iter().all(|&word| word == 0xdead_beef));
    }
}
