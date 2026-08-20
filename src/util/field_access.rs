//! opaque_object_flags — original: `FUN_0804482c` @ `0x0804482c` (8 bytes).
//!
//! Raw ARM is a leaf `ldr r0, [r0, #0xc]; bx lr`: return the complete
//! 32-bit flags word at +0x0c of an opaque object, with no NULL, ownership,
//! or validity check. `FUN_08044628` constructs one observed 0x44-byte
//! instance shape, and its read paths test bits 0, 1, and 2 of this word;
//! the two direct callers respectively test bit 2 after replacing such an
//! object (0x08095f04) and bit 0 on a selected child object (0x082a2e60).
//! Those sites establish the field as flags but not a stable public object
//! type, so this port deliberately preserves the opaque-object boundary.

/// Byte offset of the opaque object's flags word.
const FLAGS: usize = 0x0c;

/// Reads the complete flags word from an opaque object.
///
/// # Safety
///
/// `object.add(0x0c)..object.add(0x10)` must be readable. The original
/// performs an unchecked word load; this port intentionally provides no
/// NULL check, bounds check, or ownership interpretation. `read_unaligned`
/// preserves the callable byte-pointer ABI without imposing Rust alignment
/// requirements that the firmware interface does not declare.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_object_flags(object: *const u8) -> u32 {
    (object.add(FLAGS) as *const u32).read_unaligned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT_LEN: usize = FLAGS + core::mem::size_of::<u32>();
    const SENTINEL: u8 = 0xa5;

    #[test]
    fn returns_the_full_little_endian_flags_word() {
        let mut object = [SENTINEL; OBJECT_LEN];
        let flags = 0x85a5_0201u32;
        object[FLAGS..FLAGS + 4].copy_from_slice(&flags.to_le_bytes());

        assert_eq!(unsafe { opaque_object_flags(object.as_ptr()) }, flags);
    }

    #[test]
    fn accepts_each_byte_alignment_without_changing_the_word() {
        let flags = 0xfedc_ba98u32;
        for alignment in 0..4usize {
            let mut storage = [SENTINEL; OBJECT_LEN + 3];
            let object = unsafe { storage.as_mut_ptr().add(alignment) };
            storage[alignment + FLAGS..alignment + FLAGS + 4]
                .copy_from_slice(&flags.to_le_bytes());

            assert_eq!(unsafe { opaque_object_flags(object) }, flags, "alignment {alignment}");
        }
    }

    #[test]
    fn reads_only_the_four_byte_flags_extent() {
        let mut storage = [SENTINEL; OBJECT_LEN + 2];
        let flags = 0x0102_0408u32;
        storage[FLAGS..FLAGS + 4].copy_from_slice(&flags.to_le_bytes());

        assert_eq!(unsafe { opaque_object_flags(storage.as_ptr()) }, flags);
        assert_eq!(&storage[..FLAGS], &[SENTINEL; FLAGS]);
        assert_eq!(&storage[FLAGS + 4..], &[SENTINEL; 2]);
    }
}
