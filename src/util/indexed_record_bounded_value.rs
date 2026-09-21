//! Indexed record lookup with mode-specific bounds — retailOS `FUN_0829db34` @
//! 0x0829db34 (100 bytes).
//!
//! Raw osos.dec words establish the exact extent 0x0829db34..0x0829db97; the
//! literal `0x0000ffff` follows at 0x0829db98 and the independently entered
//! next function begins at 0x0829db9c. Whole-image branch decoding finds three
//! inbound plain `bl` calls at 0x080f532c, 0x080f5358, and 0x080f53c0, with no
//! predicated `bl` calls; this leaf has no outbound calls. It returns the
//! selected word unless mode 0 finds its high halfword no greater than the
//! header limit, or mode 2 finds the complete word no greater than that limit;
//! either match returns zero. Mode 1 and every other mode return the word
//! unchanged. An out-of-range index returns `0xffff0000 | (index << 16)`.
//!
//! Deliberate deviations: the target header is exposed as three target-width
//! words rather than a host-pointer-containing Rust struct, and volatile reads
//! preserve the retail load order while preventing LLVM from inventing a
//! libc-style access.

/// Looks up an indexed record and applies the mode-specific header limit.
///
/// # Safety
/// `header` must point to three aligned target-width words: record base,
/// record count, and a low-halfword limit. When `index < count`, the base word
/// must name an aligned readable `u32` record at `index`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.indexed_record_bounded_value")]
#[inline(never)]
pub unsafe extern "C" fn indexed_record_bounded_value(
    header: *const u32,
    index: u32,
    mode: u32,
) -> u32 {
    let count = header.add(1).read_volatile();
    if index >= count {
        return 0xffff_0000 | (index << 16);
    }

    let records = header.read_volatile() as *const u32;
    let value = records.add(index as usize).read_volatile();
    match mode {
        0 => {
            let limit = header.add(2).read_volatile() & 0xffff;
            if (value >> 16) <= limit { 0 } else { value }
        }
        2 => {
            let limit = header.add(2).read_volatile() & 0xffff;
            if value <= limit { 0 } else { value }
        }
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::indexed_record_bounded_value;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn applies_each_mode_and_preserves_out_of_range_encoding() {
        let Some(records) = try_map_u32_slab(hints::INDEXED_RECORD_BOUNDED_VALUE, 0x1000) else {
            assert!(note_missing_u32_fixture("util/indexed_record_bounded_value"));
            return;
        };
        let records = records.cast::<u32>();
        unsafe {
            records.write(0x0012_3456);
            records.add(1).write(0x0013_0001);
            records.add(2).write(0x0000_0012);
        }
        let header = [records as u32, 3, 0x0012];

        for (index, mode, expected) in [
            (0, 0, 0),                 // high halfword equals the limit.
            (1, 0, 0x0013_0001),       // high halfword exceeds the limit.
            (2, 2, 0),                 // complete word equals the limit.
            (0, 2, 0x0012_3456),       // complete word exceeds the limit.
            (0, 1, 0x0012_3456),       // mode 1 is unfiltered.
            (1, 3, 0x0013_0001),       // unknown modes are unfiltered.
            (3, 0, 0xffff_0000),       // first invalid index.
            (0x1234, 2, 0xffff_0000),  // shifted index is deliberately lost.
        ] {
            assert_eq!(
                unsafe { indexed_record_bounded_value(header.as_ptr(), index, mode) },
                expected,
                "index={index} mode={mode}"
            );
        }
    }
}
