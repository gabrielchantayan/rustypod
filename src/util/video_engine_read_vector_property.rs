//! video_engine_read_vector_property — FUN_082502bc @ 0x082502bc.
//! True extent: 160 bytes, 0x082502bc..0x0825035c (156 instruction bytes
//! plus the 0x1202 literal; next independent push prologue at 0x0825035c).
//! Raw whole-image ARM scan: two inbound plain BL sites (0x08250270,
//! 0x08250298), zero predicated BLs; two outbound plain BLs, zero predicated.
//!
//! Accepts selectors 0x404 and 0x405. Properties 0x1200, 0x1201, 0x1202,
//! and 0x1600 copy four ordered words from engine offsets 0x838, 0x848,
//! 0x858, and 0x868. Property 0x1601 copies only the word at 0x878.
//! Success returns 1; rejection preserves output, latches first error 0x500,
//! and returns 0. The caller at 0x08250228 converts one or four output words.
//! Deliberate deviations: none; existing copy and error-latch seams are reused.

use crate::util::copy_four_words::copy_four_words_forward_property;
use crate::util::error_latch::latch_first_error;

/// # Safety
/// `engine` must point to aligned writable error state, and for accepted
/// requests be readable through the selected property's last word. `output`
/// must be aligned and writable for one or four words on success; it is not
/// accessed on rejection. Source and output may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_read_vector_property(
    engine: *mut u32,
    selector: u32,
    property_id: u32,
    output: *mut u32,
) -> u32 {
    if selector == 0x404 || selector == 0x405 {
        let offset = match property_id {
            0x1200 => 0x838,
            0x1201 => 0x848,
            0x1202 => 0x858,
            0x1600 => 0x868,
            0x1601 => {
                output.write(engine.add(0x878 / 4).read());
                return 1;
            }
            _ => {
                latch_first_error(engine, 0x500);
                return 0;
            }
        };
        copy_four_words_forward_property(engine.add(offset / 4), output);
        return 1;
    }
    latch_first_error(engine, 0x500);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognized_properties_copy_exact_width_without_mutating_engine() {
        for selector in [0x404, 0x405] {
            for (id, offset, width) in [
                (0x1200, 0x838, 4), (0x1201, 0x848, 4),
                (0x1202, 0x858, 4), (0x1600, 0x868, 4), (0x1601, 0x878, 1),
            ] {
                let mut engine = [0u32; 0x87c / 4];
                for (index, word) in engine.iter_mut().enumerate() {
                    *word = 0x8000_0000 | index as u32;
                }
                let before = engine;
                let mut output = [0xdead_beef; 6];
                let result = unsafe {
                    video_engine_read_vector_property(engine.as_mut_ptr(), selector, id,
                        output.as_mut_ptr().add(1))
                };
                assert_eq!(result, 1);
                assert_eq!(&output[1..1 + width], &before[offset / 4..offset / 4 + width]);
                assert_eq!(output[0], 0xdead_beef);
                assert!(output[1 + width..].iter().all(|&word| word == 0xdead_beef));
                assert_eq!(engine, before);
            }
        }
    }

    #[test]
    fn rejected_requests_preserve_output_and_first_error() {
        for selector in [0, 0x403, 0x404, 0x405, 0x406, u32::MAX] {
            for id in [0, 0x11ff, 0x1200, 0x1203, 0x15ff, 0x1602, 0x8000_0000, u32::MAX] {
                if (selector == 0x404 || selector == 0x405) && id == 0x1200 {
                    continue;
                }
                for initial_error in [0, 0x501] {
                    let mut error = initial_error;
                    let mut output = [0xdead_beef; 4];
                    assert_eq!(unsafe {
                        video_engine_read_vector_property(&mut error, selector, id, output.as_mut_ptr())
                    }, 0);
                    assert_eq!(error, if initial_error == 0 { 0x500 } else { initial_error });
                    assert_eq!(output, [0xdead_beef; 4]);
                }
            }
        }
    }

    #[test]
    fn overlapping_vector_copy_keeps_forward_load_store_order() {
        let mut engine = [0u32; 0x87c / 4];
        let start = 0x838 / 4;
        engine[start..start + 5].copy_from_slice(&[11, 22, 33, 44, 55]);
        let ptr = engine.as_mut_ptr();
        assert_eq!(unsafe {
            video_engine_read_vector_property(ptr, 0x404, 0x1200, ptr.add(start + 1))
        }, 1);
        assert_eq!(&engine[start..start + 5], &[11, 11, 11, 11, 11]);
        assert_eq!(engine[0], 0);
    }
}
