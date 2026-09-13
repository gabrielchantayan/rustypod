//! Store variable-length record trailer header — `record_store_trailer_header`
//! @ 0x0814d74c.
//!
//! Raw ARM is seven instructions at `0x0814d74c..0x0814d768`; the next
//! separately linked function begins at `0x0814d76c`, so the true extent is
//! 28 bytes rather than Ghidra's reported 32. It calls
//! [`super::record_body_size::record_body_size`] with `align = 4`, adds that
//! byte count and 12 to the record base, then writes the caller's header word
//! to the resulting trailer slot. Full-image ARM decoding finds six direct
//! `bl` callers, all unconditional (`0x0814d5c8`, `0x0814d69c`,
//! `0x0814d740`, `0x0814d890`, `0x0814d8c4`, and `0x081a8618`), plus one
//! unconditional tail `b` at `0x0814d788`; there are no aligned data-word
//! references to the entry.
//!
//! Deliberate deviations: none.

use super::record_body_size::record_body_size;

/// Byte offset from the end of a record body to the copied header word.
const TRAILER_HEADER_OFFSET: usize = 12;

/// Copies `header` into the variable-length record's trailer header slot.
///
/// # Safety
///
/// `record` must point to a writable variable-length record whose body size
/// word and trailer header slot are valid. As in retailOS, the low 24 bits of
/// `record[0]` determine the body length; no validation or NULL guard occurs.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_store_trailer_header(record: *mut u32, header: u32) {
    let body_size = unsafe { record_body_size(record, 4) } as usize;
    let trailer_header = unsafe {
        record
            .cast::<u8>()
            .add(body_size)
            .add(TRAILER_HEADER_OFFSET)
            .cast::<u32>()
    };
    unsafe { trailer_header.write(header) };
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD_WORDS: usize = 16;
    const TRAILER_HEADER_WORDS: usize = TRAILER_HEADER_OFFSET / core::mem::size_of::<u32>();

    #[test]
    fn stores_full_flagged_header_after_each_body_length() {
        for (body_words, flags) in [(0usize, 0x0000_0000), (1, 0x0100_0000), (5, 0x2300_0000), (11, 0xff00_0000)] {
            let body_size = (body_words * core::mem::size_of::<u32>()) as u32;
            let header = flags | body_size;
            let mut record = [0xa5a5_a5a5; RECORD_WORDS];
            record[0] = header;
            let before = record;

            unsafe { record_store_trailer_header(record.as_mut_ptr(), header) };

            let trailer_header_word = body_words + TRAILER_HEADER_WORDS;
            for (index, word) in record.iter().copied().enumerate() {
                let expected = if index == trailer_header_word { header } else { before[index] };
                assert_eq!(word, expected, "body_words={body_words} word={index}");
            }
        }
    }

    #[test]
    fn copies_argument_not_the_record_header() {
        let mut record = [0x5a5a_5a5a; RECORD_WORDS];
        record[0] = 0x7e00_0008;
        let supplied_header = 0x8100_000c;
        let before = record;

        unsafe { record_store_trailer_header(record.as_mut_ptr(), supplied_header) };

        assert_eq!(record[5], supplied_header, "body size 8 places trailer at word +5");
        for (index, word) in record.iter().copied().enumerate() {
            if index != 5 {
                assert_eq!(word, before[index], "word={index}");
            }
        }
    }
}
