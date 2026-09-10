//! Normalization of opaque tagged descriptor fields used by command layouts.
//!
//! `descriptor_field_map` — original `FUN_08270f84` @ `0x08270f84`
//! (**160 bytes, `0x08270f84..0x08271040`**). The body occupies 39 ARM
//! instructions through `bx lr` at `0x08271020`, followed by seven
//! function-local literal-pool words; the next separately linked function
//! starts at `0x08271040`. Decoding every ARM B/BL word in `osos.dec` finds
//! **10 direct `bl` call sites**, all unconditional, plus one unconditional
//! plain-`b` tail call; there are no predicated call sites.
//!
//! # Algorithm
//!
//! Reads the low byte at source word two as an opaque field tag. Tags 0, 5,
//! and 6 select a two-word literal prefix and retain source word zero as the
//! destination's third word. Tags 1 through 4 move source words one and zero
//! into destination words zero and two, with `0x8000_0010 + (tag << 8)` in
//! between. Tags 7 through 10 replace all three words with their respective
//! literal triples. Every other tag enters `heap_panic`, exactly as the
//! retailOS default switch path does. The tag and any source words needed by
//! a path are read before the first destination write, preserving the
//! original's source == destination behavior.
//!
//! Deliberate code-generation deviation: the fatal default calls the existing
//! Rust `heap_panic` port rather than encoding its fixed firmware address.

/// Number of words in each opaque tagged field.
pub const DESCRIPTOR_FIELD_WORDS: usize = 3;

const TAGGED_PREFIX_BASE: u32 = 0x8000_0010;

const TAG_0_PREFIX: [u32; 2] = [0x2077_6152, 0xe7a7_85e7];
const TAG_5_PREFIX: [u32; 2] = [0x20a0_bce5, 0x2077_6152];
const TAG_6_PREFIX: [u32; 2] = [0x0000_8789, 0xe5a8_83e9];
const TAG_7_FIELD: [u32; DESCRIPTOR_FIELD_WORDS] = [0x0000_0087, 0xe5a8_83e9, 0x89e7_b1bd];
const TAG_8_FIELD: [u32; DESCRIPTOR_FIELD_WORDS] = [0x0000_0087, 0x20ac_ace7, 0x2064_2523];
const TAG_9_FIELD: [u32; DESCRIPTOR_FIELD_WORDS] = [0x00b7_8de5, 0x20ac_ace7, 0x2064_2523];
const TAG_10_FIELD: [u32; DESCRIPTOR_FIELD_WORDS] = [0xefb7_8de5, 0x85e5_88bc, 0x6425_20b1];

#[inline(always)]
unsafe fn write_field(destination: *mut u32, field: &[u32; DESCRIPTOR_FIELD_WORDS]) {
    unsafe {
        destination.write_volatile(field[0]);
        destination.add(1).write_volatile(field[1]);
        destination.add(2).write_volatile(field[2]);
    }
}

/// Maps an opaque three-word tagged descriptor field into its layout form.
///
/// # Safety
///
/// `source` must point to three readable aligned words and `destination` to
/// three writable aligned words. The retail function neither checks NULL nor
/// validates either buffer extent. `source` and `destination` may be equal.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn descriptor_field_map(source: *const u32, destination: *mut u32) {
    let tag = unsafe { source.add(2).cast::<u8>().read_volatile() };

    unsafe {
        match tag {
            0 => {
                let source_zero = source.read_volatile();
                destination.write_volatile(TAG_0_PREFIX[0]);
                destination.add(1).write_volatile(TAG_0_PREFIX[1]);
                destination.add(2).write_volatile(source_zero);
            }
            1..=4 => {
                let source_one = source.add(1).read_volatile();
                let source_zero = source.read_volatile();
                destination.write_volatile(source_one);
                destination.add(1).write_volatile(TAGGED_PREFIX_BASE + ((tag as u32) << 8));
                destination.add(2).write_volatile(source_zero);
            }
            5 => {
                let source_zero = source.read_volatile();
                destination.write_volatile(TAG_5_PREFIX[0]);
                destination.add(1).write_volatile(TAG_5_PREFIX[1]);
                destination.add(2).write_volatile(source_zero);
            }
            6 => {
                let source_zero = source.read_volatile();
                destination.write_volatile(TAG_6_PREFIX[0]);
                destination.add(1).write_volatile(TAG_6_PREFIX[1]);
                destination.add(2).write_volatile(source_zero);
            }
            7 => write_field(destination, &TAG_7_FIELD),
            8 => write_field(destination, &TAG_8_FIELD),
            9 => write_field(destination, &TAG_9_FIELD),
            10 => write_field(destination, &TAG_10_FIELD),
            _ => crate::heap::veneers::heap_panic(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_supported_tag_to_its_retail_triple() {
        let cases = [
            ([0x1122_3344, 0x5566_7788, 0xaa00_0000], [0x2077_6152, 0xe7a7_85e7, 0x1122_3344]),
            ([0x1122_3344, 0x5566_7788, 0xaa00_0001], [0x5566_7788, 0x8000_0110, 0x1122_3344]),
            ([0x1122_3344, 0x5566_7788, 0xaa00_0002], [0x5566_7788, 0x8000_0210, 0x1122_3344]),
            ([0x1122_3344, 0x5566_7788, 0xaa00_0003], [0x5566_7788, 0x8000_0310, 0x1122_3344]),
            ([0x1122_3344, 0x5566_7788, 0xaa00_0004], [0x5566_7788, 0x8000_0410, 0x1122_3344]),
            ([0x1122_3344, 0x5566_7788, 0xaa00_0005], [0x20a0_bce5, 0x2077_6152, 0x1122_3344]),
            ([0x1122_3344, 0x5566_7788, 0xaa00_0006], [0x0000_8789, 0xe5a8_83e9, 0x1122_3344]),
            ([0x1122_3344, 0x5566_7788, 0xaa00_0007], [0x0000_0087, 0xe5a8_83e9, 0x89e7_b1bd]),
            ([0x1122_3344, 0x5566_7788, 0xaa00_0008], [0x0000_0087, 0x20ac_ace7, 0x2064_2523]),
            ([0x1122_3344, 0x5566_7788, 0xaa00_0009], [0x00b7_8de5, 0x20ac_ace7, 0x2064_2523]),
            ([0x1122_3344, 0x5566_7788, 0xaa00_000a], [0xefb7_8de5, 0x85e5_88bc, 0x6425_20b1]),
        ];

        for (source_words, expected) in cases {
            let source_before = source_words;
            let mut destination = [0xdead_beef; DESCRIPTOR_FIELD_WORDS];
            unsafe { descriptor_field_map(source_words.as_ptr(), destination.as_mut_ptr()) };
            assert_eq!(destination, expected, "tag {}", source_words[2] as u8);
            assert_eq!(source_words, source_before, "tag {} must not write source", source_words[2] as u8);
        }
    }

    #[test]
    fn reads_dynamic_source_words_before_overwriting_an_aliased_field() {
        let mut field = [0x1122_3344, 0x5566_7788, 0xaabb_cc04];
        unsafe { descriptor_field_map(field.as_ptr(), field.as_mut_ptr()) };
        assert_eq!(field, [0x5566_7788, 0x8000_0410, 0x1122_3344]);
    }
}
