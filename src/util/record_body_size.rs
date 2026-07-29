//! Record body size reader — `record_body_size` @ 0x0814d51c.
//!
//! Reads the header word of a variable-length record and returns the size
//! of its body: the low 24 bits of the header (the top byte is a flags
//! byte, cleared by `bic r2, r2, #0xff000000`). When `align` is greater
//! than 4 the record body is padded so that `record + 12` rounded up to
//! `align` stays aligned, and that padding
//! (`(align - ((record + 12) & (align - 1))) & (align - 1)`) is subtracted
//! from the size. With `align <= 4` the padding term is skipped entirely.
//!
//! 11 `bl` call sites from 9 distinct callers in osos.asm, and every one
//! of them passes `align = 4`, so in this image the function is always
//! just the 24-bit size field; the alignment path is dead but ported
//! anyway for structural parity. Callers use the result as a byte offset
//! from the record base (e.g. 0x0814d6c8 reads `record + size + 0x0c`,
//! 0x0814d7a4 forms `record + size + 0x10`); the record class itself is
//! not identified. Pure leaf function, no globals.

/// record_body_size — original: `FUN_0814d51c` @ 0x0814d51c (44 bytes).
///
/// Returns the record body size: `record[0] & 0x00ff_ffff`, minus the
/// alignment padding of `record + 12` up to `align` when `align > 4`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_body_size(record: *const u32, align: u32) -> u32 {
    let mut size = record.read();
    let mut padding = 0u32;
    if align > 4 {
        let addr = record as usize as u32;
        let mask = align.wrapping_sub(1);
        padding = align.wrapping_sub(addr.wrapping_add(12) & mask) & mask;
    }
    size &= 0x00ff_ffff;
    if align > 4 {
        size = size.wrapping_sub(padding);
    }
    size
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent reference, straight from the Ghidra decompile.
    fn reference(record: *const u32, align: u32) -> u32 {
        let mut size = unsafe { record.read() };
        let mut padding = 0u32;
        if 4 < align {
            padding =
                (align.wrapping_sub(((record as usize as u32).wrapping_add(12)) & align.wrapping_sub(1)))
                    & align.wrapping_sub(1);
        }
        size &= 0xff_ffff;
        if 4 < align {
            size = size.wrapping_sub(padding);
        }
        size
    }

    /// Buffer with one record header at each word offset, so the record
    /// address takes a spread of low bits for the alignment path.
    fn spread() -> [u32; 64] {
        core::array::from_fn(|i| (i as u32) << 24 | 0x00a5_5a00 | (i as u32) * 7)
    }

    #[test]
    fn align_4_returns_low_24_bits_of_header() {
        let buf = spread();
        for (i, header) in buf.iter().enumerate() {
            let rec = unsafe { buf.as_ptr().add(i) };
            assert_eq!(unsafe { record_body_size(rec, 4) }, header & 0x00ff_ffff);
        }
    }

    #[test]
    fn align_at_or_below_4_never_pads() {
        let buf = spread();
        for align in 0..=4u32 {
            for (i, header) in buf.iter().enumerate() {
                let rec = unsafe { buf.as_ptr().add(i) };
                assert_eq!(
                    unsafe { record_body_size(rec, align) },
                    header & 0x00ff_ffff,
                    "align={align}"
                );
            }
        }
    }

    #[test]
    fn matches_reference_across_aligns_and_addresses() {
        let buf = spread();
        // Power-of-two and non-power-of-two aligns; the original does raw
        // arithmetic with `align - 1`, so odd values are fair game.
        for align in [5u32, 6, 7, 8, 12, 16, 24, 32, 64, 256, 4096] {
            for i in 0..buf.len() {
                let rec = unsafe { buf.as_ptr().add(i) };
                assert_eq!(
                    unsafe { record_body_size(rec, align) },
                    reference(rec, align),
                    "align={align} offset={i}"
                );
            }
        }
    }

    #[test]
    fn padding_is_distance_from_record_plus_12_up_to_align() {
        // Craft a header whose size is large enough to see the subtraction.
        let mut buf = [0u32; 40];
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = 0xff00_1000 | i as u32; // flags byte set, size 0x1000 + i
        }
        for i in 0..buf.len() {
            let rec = unsafe { buf.as_ptr().add(i) };
            let addr = rec as usize as u32;
            let pad = (16 - (addr.wrapping_add(12) & 15)) & 15;
            assert_eq!(
                unsafe { record_body_size(rec, 16) },
                (0x1000 + i as u32).wrapping_sub(pad),
                "offset={i}"
            );
        }
    }
}
