//! Mode-selected offset translation at retailOS 0x0814da30.
//!
//! Raw A32 extent [0x0814da30, 0x0814da54): 36 bytes, nine instructions,
//! no literals. The next function independently clears five object words.
//! Zero outgoing plain or predicated BLs; two incoming plain BLs at
//! 0x0813aa20 and 0x0814d968, zero incoming predicated BLs.
//! Mode 5 subtracts the object's fifth word from the input offset; mode 6
//! adds it. Other modes return zero without accessing the object. Caller
//! 0x0814d944 applies this translation to the first word of each pair;
//! 0x0813a83c uses mode 6 before a virtual operation at slot +0x94.
//! Deviations: none. Word indexing preserves the +0x10 field on hosts;
//! wrapping arithmetic preserves ARM's modulo-2^32 ADD/SUB behavior.

/// Translate an offset using mode 5 (subtract) or 6 (add).
///
/// # Safety
/// For modes 5 and 6, `context` must permit an aligned read of word 4.
/// Other modes do not require a valid pointer. No context words are written.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mode_offset_translate(context: *const u32, mode: u32, offset: u32) -> u32 {
    match mode {
        5 => offset.wrapping_sub(context.add(4).read()),
        6 => offset.wrapping_add(context.add(4).read()),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_modes_match_wide_reference_at_wrap_boundaries() {
        let values = [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, u32::MAX];
        for bias in values {
            let context = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, bias, 0x6666_6666];
            let original = context;
            for offset in values {
                for mode in [5, 6] {
                    let expected = if mode == 5 {
                        (offset as i64 - bias as i64) as u32
                    } else {
                        (offset as u64 + bias as u64) as u32
                    };
                    assert_eq!(unsafe { mode_offset_translate(context.as_ptr(), mode, offset) }, expected);
                }
            }
            assert_eq!(context, original);
        }
    }

    #[test]
    fn unsupported_modes_do_not_read_context() {
        for mode in [0, 1, 4, 7, 0x8000_0005, u32::MAX] {
            for offset in [0, 1, u32::MAX] {
                assert_eq!(unsafe { mode_offset_translate(core::ptr::null(), mode, offset) }, 0);
            }
        }
    }
}
