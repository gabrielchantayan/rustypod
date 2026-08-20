//! Port of the UI-object flag query at `0x0829d3a0`.

/// `flag_bit_2_at_4` — original: `FUN_0829d3a0` @ `0x0829d3a0`
/// (16 bytes, one direct `bl` call site, a pure leaf).
///
/// The shared collection-navigation body reached directly at `0x0826b858`
/// (and by the `0x0826b784` tail entry) receives an otherwise unidentified
/// UI object, then uses this predicate to decide whether to inspect its
/// follow-up display data. The routine loads that object's byte
/// at `+0x4`, masks bit 2 (`0x04`), and shifts it down so the ABI result is
/// normalized to exactly 0 or 1. It neither dereferences nor mutates any
/// other part of the object. The owning type and the flag's user-visible
/// meaning remain unidentified, so the name intentionally records its exact
/// field and bit instead of claiming semantics not established by its callers.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn flag_bit_2_at_4(object: *const u8) -> u32 {
    ((object.add(4).read() & 0x04) >> 2) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAG_OFFSET: usize = 4;

    fn call(flag_byte: u8) -> u32 {
        let mut object = [0xa5u8; 8];
        object[FLAG_OFFSET] = flag_byte;
        unsafe { flag_bit_2_at_4(object.as_ptr()) }
    }

    #[test]
    fn normalizes_every_combination_of_flag_byte_bits() {
        for flag_byte in 0u8..=u8::MAX {
            let expected = ((flag_byte & 0x04) >> 2) as u32;
            assert_eq!(call(flag_byte), expected, "flag byte {flag_byte:#04x}");
        }
    }

    #[test]
    fn ignores_all_unrelated_object_bytes() {
        for &offset in &[0usize, 1, 2, 3, 5, 6, 7] {
            for unrelated in 0u8..=u8::MAX {
                let mut object = [0u8; 8];
                object[FLAG_OFFSET] = 0x04;
                object[offset] = unrelated;
                assert_eq!(unsafe { flag_bit_2_at_4(object.as_ptr()) }, 1, "object +{offset:#x} = {unrelated:#04x}");
            }
        }
    }

    #[test]
    fn accepts_const_aliases_of_the_same_object_without_mutating_it() {
        let mut object = [0xa5u8; 8];
        object[FLAG_OFFSET] = 0x04;
        let before = object;
        let mutable_alias = object.as_mut_ptr();
        let const_alias = mutable_alias as *const u8;

        assert_eq!(unsafe { flag_bit_2_at_4(const_alias) }, 1);
        assert_eq!(unsafe { flag_bit_2_at_4(mutable_alias as *const u8) }, 1);
        assert_eq!(object, before);
    }
}
