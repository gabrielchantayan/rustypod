//! Opaque FreeType service metadata flag accessor.
//!
//! The concrete object and metadata layouts are not recovered. This module
//! records only the raw pointer and word offsets established by retailOS.

/// Byte offset of the metadata pointer word in the opaque object.
pub const OBJECT_METADATA_OFFSET: usize = 0xf00;
/// Byte offset of the accessed flag word in the opaque metadata block.
pub const METADATA_FLAGS_B00_OFFSET: usize = 0xb00;

/// ft_service_metadata_flags_at_b00 — original: `FUN_080514e0` @ `0x080514e0`
/// (12 bytes).
///
/// Loads the metadata pointer word at `object + 0xf00`, then returns the
/// unsigned word at `metadata + 0xb00`. The ARM body is `ldr; ldr; bx lr`;
/// recovered callers inspect bits 0 and 1 as independent service state flags.
/// The concrete layouts and ownership are not recovered, so this deliberately
/// retains direct aligned dereferences with no NULL or bounds checks.
///
/// Register usage: `r0 = object`; `r0 = metadata flag word`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_flags_at_b00(object: *const u8) -> u32 {
    let metadata = (object.add(OBJECT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_FLAGS_B00_OFFSET) as *const u32).read()
}

#[cfg(test)]
mod tests {
    use super::{
        ft_service_metadata_flags_at_b00, METADATA_FLAGS_B00_OFFSET, OBJECT_METADATA_OFFSET,
    };

    #[repr(C)]
    struct Object {
        before_metadata: [u8; OBJECT_METADATA_OFFSET],
        metadata: *const u8,
    }

    #[repr(C)]
    struct Metadata {
        before_flags: [u8; METADATA_FLAGS_B00_OFFSET],
        flags: u32,
    }

    #[test]
    fn reads_the_full_word_at_the_recovered_offsets() {
        let metadata = Metadata {
            before_flags: [0xa5; METADATA_FLAGS_B00_OFFSET],
            flags: 0x89ab_cdef,
        };
        let object = Object {
            before_metadata: [0x5a; OBJECT_METADATA_OFFSET],
            metadata: (&metadata as *const Metadata).cast(),
        };

        assert_eq!(
            unsafe { ft_service_metadata_flags_at_b00((&object as *const Object).cast()) },
            0x89ab_cdef,
        );
    }

    #[test]
    fn preserves_every_flag_word_bit_pattern() {
        for flags in [0x0000_0000, 0x0000_0003, 0x8000_0000, 0xffff_ffff] {
            let metadata = Metadata {
                before_flags: [0; METADATA_FLAGS_B00_OFFSET],
                flags,
            };
            let object = Object {
                before_metadata: [0; OBJECT_METADATA_OFFSET],
                metadata: (&metadata as *const Metadata).cast(),
            };

            assert_eq!(
                unsafe { ft_service_metadata_flags_at_b00((&object as *const Object).cast()) },
                flags,
            );
        }
    }

    #[test]
    fn test_layouts_place_the_raw_words_at_the_recovered_offsets() {
        assert_eq!(core::mem::offset_of!(Object, metadata), OBJECT_METADATA_OFFSET);
        assert_eq!(core::mem::offset_of!(Metadata, flags), METADATA_FLAGS_B00_OFFSET);
    }
}
