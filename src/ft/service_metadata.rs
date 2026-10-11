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

/// ft_service_metadata_flags_at_b84 — retail `FUN_08053a8c` @ `0x08053a8c`.
/// True extent: [0x08053a8c, 0x08053a98), 12 bytes, ending at the next push.
/// Raw words: `e5900f00 e5900b84 e12fff1e` (`ldr; ldr; bx lr`).
/// Whole-image A32 decoding verifies two plain inbound BLs at 0x08172728
/// and 0x081729d0, zero predicated inbound BLs, and no outgoing BLs.
///
/// Follow the pointer at object+0xf00 and return the full flag word at
/// metadata+0xb84. Callers test, set, and clear selected bits; their concrete
/// meanings remain unrecovered. No callee seams or NULL/bounds checks.
/// Deliberate deviations: the host pointer is native-width, while ARM retains
/// the four-byte pointer slot; field offsets and aligned reads are unchanged.
///
/// # Safety
/// `object` has an aligned readable metadata pointer at +0xf00. Its pointee
/// has an aligned readable u32 at +0xb84.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_flags_at_b84(object: *const u8) -> u32 {
    let metadata = object.add(OBJECT_METADATA_OFFSET).cast::<*const u8>().read();
    metadata.add(0xb84).cast::<u32>().read()
}

/// ft_service_metadata_class_one_mask — retail `FUN_080538b0` @ `0x080538b0`.
/// True extent: [0x080538b0, 0x080538bc), 12 bytes; the next function
/// starts with `push {r4-r10,lr}`. Raw words `e5900f00 e5900b8c e12fff1e`
/// decode to `ldr r0,[r0,#0xf00]; ldr r0,[r0,#0xb8c]; bx lr`.
/// Whole-image aligned A32 decoding verifies two plain inbound BLs at
/// 0x08172588 and 0x0817264c, zero predicated inbound BLs, and zero
/// outgoing plain or predicated BLs.
///
/// Follow the metadata pointer at object+0xf00 and return the complete
/// class-one event mask at metadata+0xb8c. Callers test, set, and clear
/// selected event bits; individual bit meanings remain unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// unchanged offsets and aligned reads, with no NULL or bounds checks.
///
/// # Safety
/// `object` contains an aligned readable metadata pointer at +0xf00, whose
/// pointee contains an aligned readable u32 at +0xb8c.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_class_one_mask(object: *const u8) -> u32 {
    let metadata = object.add(OBJECT_METADATA_OFFSET).cast::<*const u8>().read();
    metadata.add(0xb8c).cast::<u32>().read()
}

#[cfg(test)]
mod class_one_mask_tests {
    use super::*;

    #[repr(C)]
    struct Owner {
        padding: [u8; OBJECT_METADATA_OFFSET],
        metadata: *const u32,
    }

    #[test]
    fn preserves_every_bit_and_follows_replaced_metadata() {
        let mut first = [0xa5a5_a5a5u32; 0xb90 / 4];
        let mut second = [0x5a5a_5a5au32; 0xb90 / 4];
        let mut owner = Owner { padding: [0xcc; OBJECT_METADATA_OFFSET], metadata: first.as_ptr() };
        for value in [0, u32::MAX, 0x8000_0000, 1, 0x0123_4567, 0xaaaa_5555] {
            first[0xb8c / 4] = value;
            second[0xb8c / 4] = !value;
            owner.metadata = first.as_ptr();
            assert_eq!(unsafe { ft_service_metadata_class_one_mask(
                (&owner as *const Owner).cast()) }, value);
            owner.metadata = second.as_ptr();
            assert_eq!(unsafe { ft_service_metadata_class_one_mask(
                (&owner as *const Owner).cast()) }, !value);
        }
        assert!(first[..0xb8c / 4].iter().all(|word| *word == 0xa5a5_a5a5));
        assert!(second[..0xb8c / 4].iter().all(|word| *word == 0x5a5a_5a5a));
        assert!(owner.padding.iter().all(|byte| *byte == 0xcc));
    }
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

#[cfg(test)]
mod flags_b84_tests {
    use super::*;

    #[repr(C)]
    struct Object {
        padding: [u8; OBJECT_METADATA_OFFSET],
        metadata: *const u32,
    }

    #[test]
    fn preserves_every_bit_and_follows_replaced_metadata() {
        let mut first = [0xa5a5_a5a5u32; 0xb88 / 4];
        let mut second = [0x5a5a_5a5au32; 0xb88 / 4];
        let mut object = Object {
            padding: [0xcc; OBJECT_METADATA_OFFSET],
            metadata: first.as_ptr(),
        };
        for value in [0, u32::MAX, 0x8000_0000, 0x7fff_ffff, 0x1234_5678]
            .into_iter().chain((0..32).map(|bit| 1u32 << bit))
        {
            first[0xb84 / 4] = value;
            assert_eq!(unsafe {
                ft_service_metadata_flags_at_b84((&object as *const Object).cast())
            }, value);
        }
        second[0xb84 / 4] = 0x89ab_cdef;
        object.metadata = second.as_ptr();
        assert_eq!(unsafe {
            ft_service_metadata_flags_at_b84((&object as *const Object).cast())
        }, 0x89ab_cdef);
        assert!(first[..0xb84 / 4].iter().all(|word| *word == 0xa5a5_a5a5));
        assert!(second[..0xb84 / 4].iter().all(|word| *word == 0x5a5a_5a5a));
        assert_eq!(object.padding, [0xcc; OBJECT_METADATA_OFFSET]);
    }
}
