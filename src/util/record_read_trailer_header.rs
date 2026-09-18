//! Variable-length record trailer header reader — `record_read_trailer_header` @ 0x0814d6c8.
//!
//! Raw ARM is seven instructions at `0x0814d6c8..0x0814d6e0`; the `ldr r2,
//! [r0, #4]` at `0x0814d6e4` begins the next function, so the true size is
//! 28 bytes. It makes one unconditional `bl` to
//! [`super::record_body_size::record_body_size`] with `align = 4`, adds the
//! resulting body-size byte offset to `record`, and loads the word 12 bytes
//! into the record trailer. Full raw-image decoding finds four direct callers
//! (`0x0814d578`, `0x0814d624`, `0x081a8268`, and `0x081a89c8`), all plain
//! unconditional `bl`; there are no predicated `bl` callers. No deliberate
//! deviations.

use super::record_body_size::record_body_size;

/// Reads the header word stored 12 bytes after a variable-length record body.
///
/// # Safety
///
/// `record` must point to a readable record whose low-24-bit header size and
/// corresponding trailer header are valid. As in retailOS, this has no NULL
/// guard or bounds validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_read_trailer_header(record: *const u32) -> u32 {
    let body_size = unsafe { record_body_size(record, 4) } as usize;
    let trailer_header = unsafe { record.cast::<u8>().add(body_size).add(12).cast::<u32>() };
    unsafe { trailer_header.read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_trailer_header_after_multiple_body_sizes_and_preserves_flags() {
        for (body_words, flags) in [(0usize, 0x0000_0000), (1, 0xab00_0000), (5, 0xff00_0000)] {
            let mut record = [0xa5a5_a5a5u32; 16];
            record[0] = flags | (body_words as u32 * 4);
            let trailer_word = body_words + 3;
            record[trailer_word] = 0xfeed_0000 | body_words as u32;

            assert_eq!(
                unsafe { record_read_trailer_header(record.as_ptr()) },
                record[trailer_word],
                "body_words={body_words} flags={flags:#x}"
            );
        }
    }

    #[test]
    fn reads_exact_trailer_word_without_modifying_record() {
        let mut record = [0x5a5a_5a5au32; 12];
        record[0] = 8;
        record[5] = 0x1234_5678;
        let before = record;

        assert_eq!(unsafe { record_read_trailer_header(record.as_ptr()) }, 0x1234_5678);
        assert_eq!(record, before);
    }
}
