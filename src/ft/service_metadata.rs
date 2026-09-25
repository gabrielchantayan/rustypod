//! Opaque FreeType service metadata accessors.
//!
//! The concrete object and metadata layouts are not recovered. This module
//! records only the raw pointer and word offsets established by retailOS.

/// Byte offset of the metadata pointer word in the opaque object.
pub const OBJECT_METADATA_OFFSET: usize = 0xf00;
/// Byte offset of the accessed flag word in the opaque metadata block.
pub const METADATA_FLAGS_B00_OFFSET: usize = 0xb00;
/// Byte offset of the returned word in the opaque metadata block.
pub const METADATA_WORD_AF4_OFFSET: usize = 0xaf4;
/// Byte offset of the signed status byte in the opaque metadata block.
pub const METADATA_SIGNED_STATUS_B3C_OFFSET: usize = 0xb3c;
/// Byte offset of the returned status-flag word in the opaque metadata block.
pub const METADATA_FLAGS_B20_OFFSET: usize = 0xb20;

// These layouts name the two fields used by the +0xb20 accessor. Their
// padding is part of the retailOS ABI: the metadata pointer is a target word
// at +0xf00, and `flags` is a target word at +0xb20.
#[repr(C)]
struct ServiceObjectFlagsAtB20 {
    before_metadata: [u8; OBJECT_METADATA_OFFSET],
    metadata: *const MetadataFlagsAtB20,
}

#[repr(C)]
struct MetadataFlagsAtB20 {
    before_flags: [u8; METADATA_FLAGS_B20_OFFSET],
    flags: u32,
}

/// ft_service_metadata_flags_at_b20 — original: `FUN_08051b44` @ `0x08051b44`
/// (12 bytes; 6 verified direct `bl` call sites, all unconditional).
///
/// Loads the metadata pointer word at `object + 0xf00`, then returns the full
/// unsigned status-flag word at `metadata + 0xb20`. The ARM body is `ldr; ldr;
/// bx lr`. All six recovered callers inspect bits 0 and 1, caching changes for
/// UI notification; the concrete flag meanings remain unrecovered.
///
/// Deliberate deviations: none. As in retailOS, these are aligned direct
/// dereferences with no NULL or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_flags_at_b20(object: *const u8) -> u32 {
    let object = object.cast::<ServiceObjectFlagsAtB20>();
    let metadata = core::ptr::addr_of!((*object).metadata).read();
    core::ptr::addr_of!((*metadata).flags).read()
}


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

/// ft_service_metadata_word_at_af4 — original: `FUN_080514fc` @ `0x080514fc`
/// (12 bytes).
///
/// Loads the metadata pointer word at `object + 0xf00`, then returns the
/// unsigned word at `metadata + 0xaf4`. The ARM body is `ldr; ldr; bx lr`.
/// The concrete layouts and ownership are not recovered, so this deliberately
/// retains direct aligned dereferences with no NULL or bounds checks.
///
/// Register usage: `r0 = object`; `r0 = metadata word`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_word_at_af4(object: *const u8) -> u32 {
    let metadata = (object.add(OBJECT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_WORD_AF4_OFFSET) as *const u32).read()
}

/// ft_service_metadata_signed_status_at_b3c — original: `FUN_080514ec` @
/// `0x080514ec` (16 bytes; 3 verified direct `bl` call sites, all unconditional).
///
/// Loads the metadata pointer word at `object + 0xf00`, then sign-extends the
/// status byte at `metadata + 0xb3c`. Raw words `e5900f00 e2800c0b e1d003dc
/// e12fff1e` decode to `ldr; add #0xb00; ldrsb #0x3c; bx lr`; the next real
/// function begins at `0x080514fc`. The callers distinguish -1, 1, and other
/// values, but the byte's concrete meaning remains unrecovered.
///
/// Deliberate deviations: none. It retains retailOS's aligned direct pointer
/// load and unchecked byte read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_signed_status_at_b3c(object: *const u8) -> i32 {
    let metadata = (object.add(OBJECT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_SIGNED_STATUS_B3C_OFFSET) as *const i8).read() as i32
}

#[cfg(test)]
mod tests {
    use super::{
        ft_service_metadata_flags_at_b00, ft_service_metadata_flags_at_b20,
        ft_service_metadata_signed_status_at_b3c, ft_service_metadata_word_at_af4,
        MetadataFlagsAtB20, ServiceObjectFlagsAtB20, METADATA_FLAGS_B00_OFFSET,
        METADATA_FLAGS_B20_OFFSET, METADATA_SIGNED_STATUS_B3C_OFFSET,
        METADATA_WORD_AF4_OFFSET, OBJECT_METADATA_OFFSET,
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

    #[repr(C)]
    struct MetadataWordAtAf4 {
        before_word: [u8; METADATA_WORD_AF4_OFFSET],
        word: u32,
    }


    #[repr(C)]
    struct MetadataSignedStatusAtB3c {
        before_status: [u8; METADATA_SIGNED_STATUS_B3C_OFFSET],
        status: i8,
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
    fn reads_the_full_word_at_af4_through_the_metadata_pointer() {
        let metadata = MetadataWordAtAf4 {
            before_word: [0xa5; METADATA_WORD_AF4_OFFSET],
            word: 0x89ab_cdef,
        };
        let object = Object {
            before_metadata: [0x5a; OBJECT_METADATA_OFFSET],
            metadata: (&metadata as *const MetadataWordAtAf4).cast(),
        };

        assert_eq!(
            unsafe { ft_service_metadata_word_at_af4((&object as *const Object).cast()) },
            0x89ab_cdef,
        );
    }

    #[test]
    fn sign_extends_status_byte_at_b3c_through_metadata_pointer() {
        for (byte, expected) in [(0x00u8, 0), (0x01, 1), (0x7f, 127), (0x80, -128), (0xff, -1)] {
            let metadata = MetadataSignedStatusAtB3c {
                before_status: [0xa5; METADATA_SIGNED_STATUS_B3C_OFFSET],
                status: byte as i8,
            };
            let object = Object {
                before_metadata: [0x5a; OBJECT_METADATA_OFFSET],
                metadata: (&metadata as *const MetadataSignedStatusAtB3c).cast(),
            };

            assert_eq!(
                unsafe {
                    ft_service_metadata_signed_status_at_b3c((&object as *const Object).cast())
                },
                expected,
                "status byte {byte:#04x}",
            );
            assert_eq!(object.before_metadata, [0x5a; OBJECT_METADATA_OFFSET]);
            assert_eq!(metadata.before_status, [0xa5; METADATA_SIGNED_STATUS_B3C_OFFSET]);
        }
    }

    #[test]
    fn preserves_every_word_at_af4_bit_pattern() {
        for word in [0x0000_0000, 0x0000_0003, 0x8000_0000, 0xffff_ffff] {
            let metadata = MetadataWordAtAf4 {
                before_word: [0; METADATA_WORD_AF4_OFFSET],
                word,
            };
            let object = Object {
                before_metadata: [0; OBJECT_METADATA_OFFSET],
                metadata: (&metadata as *const MetadataWordAtAf4).cast(),
            };

            assert_eq!(
                unsafe { ft_service_metadata_word_at_af4((&object as *const Object).cast()) },
                word,
            );
        }
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
    fn b20_accessor_preserves_observed_flag_combinations_and_full_words() {
        // The six direct callers cache only bits 0 and 1. The full-word cases
        // prove the `ldr` returns the entire u32 rather than a synthesized
        // two-bit value.
        for flags in [0x0000_0000, 0x0000_0001, 0x0000_0002, 0x0000_0003,
                      0x8000_0000, 0xffff_ffff] {
            let metadata = MetadataFlagsAtB20 {
                before_flags: [0xa5; METADATA_FLAGS_B20_OFFSET],
                flags,
            };
            let object = ServiceObjectFlagsAtB20 {
                before_metadata: [0x5a; OBJECT_METADATA_OFFSET],
                metadata: &metadata,
            };

            assert_eq!(
                unsafe {
                    ft_service_metadata_flags_at_b20(
                        (&object as *const ServiceObjectFlagsAtB20).cast()
                    )
                },
                flags,
            );
            assert_eq!(object.before_metadata, [0x5a; OBJECT_METADATA_OFFSET]);
            assert_eq!(metadata.before_flags, [0xa5; METADATA_FLAGS_B20_OFFSET]);
        }
    }

    #[test]
    fn test_layouts_place_the_raw_words_at_the_recovered_offsets() {
        assert_eq!(core::mem::offset_of!(Object, metadata), OBJECT_METADATA_OFFSET);
        assert_eq!(core::mem::offset_of!(Metadata, flags), METADATA_FLAGS_B00_OFFSET);
        assert_eq!(
            core::mem::offset_of!(MetadataWordAtAf4, word),
            METADATA_WORD_AF4_OFFSET
        );
        assert_eq!(
            core::mem::offset_of!(ServiceObjectFlagsAtB20, metadata),
            OBJECT_METADATA_OFFSET
        );
        assert_eq!(
            core::mem::offset_of!(MetadataFlagsAtB20, flags),
            METADATA_FLAGS_B20_OFFSET
        );
        assert_eq!(
            core::mem::offset_of!(MetadataSignedStatusAtB3c, status),
            METADATA_SIGNED_STATUS_B3C_OFFSET
        );
    }
}
