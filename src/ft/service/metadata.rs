//! Opaque FreeType service-context metadata accessors.
//!
//! The concrete owner and metadata types are not recovered.  These routines
//! describe only the raw offsets observed in retailOS and preserve its direct
//! pointer dereferences.

/// Byte offset of the metadata pointer word in a service-context object.
pub const SERVICE_CONTEXT_METADATA_OFFSET: usize = 0xf00;
/// Byte offset of this unsigned halfword in the metadata block.
pub const METADATA_U16_B1C_OFFSET: usize = 0xb1c;
/// Byte offset of this byte in the metadata block.
pub const METADATA_BYTE_B50_OFFSET: usize = 0xb50;
/// Byte offset of this byte in the metadata block.
pub const METADATA_BYTE_B89_OFFSET: usize = 0xb89;



/// ft_service_metadata_u16_at_b1c — original: `FUN_0805129c` @ `0x0805129c`
/// (16 bytes).
///
/// Loads the metadata pointer word at `service_context + 0xf00`, then returns
/// the little-endian unsigned halfword at `metadata + 0xb1c`.  The ARM body is
/// `ldr; add; ldrh; bx lr`; `ldrh` zero-extends the value in `r0`.  The
/// concrete layouts and ownership are not recovered, so this deliberately
/// retains raw dereferences with no NULL or bounds checks.
///
/// Register usage: `r0 = service_context`; `r0 = zero-extended metadata
/// halfword`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_u16_at_b1c(service_context: *const u8) -> u16 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    let metadata_b00 = metadata.add(0xb00);
    (metadata_b00.add(0x1c) as *const u16).read()
}

/// ft_service_metadata_byte_at_b50 — original: `FUN_080512ac` @ `0x080512ac`
/// (12 bytes).
///
/// Loads the metadata pointer word at `service_context + 0xf00`, then returns
/// the unsigned byte at `metadata + 0xb50`. The ARM body is `ldr; ldrb; bx
/// lr`; `ldrb` zero-extends the value in `r0`. The concrete layouts and
/// ownership are not recovered, so this deliberately retains raw
/// dereferences with no NULL or bounds checks.
///
/// Register usage: `r0 = service_context`; `r0 = zero-extended metadata
/// byte`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_byte_at_b50(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_BYTE_B50_OFFSET) as *const u8).read() as u32
}

/// ft_service_metadata_byte_at_b89 — original: `FUN_080512b8` @ `0x080512b8`
/// (12 bytes).
///
/// Loads the metadata pointer word at `service_context + 0xf00`, then returns
/// the unsigned byte at `metadata + 0xb89`. The ARM body is `ldr; ldrb; bx
/// lr`; `ldrb` zero-extends the value in `r0`. The concrete layouts and
/// ownership are not recovered, so this deliberately retains raw
/// dereferences with no NULL or bounds checks.
///
/// Register usage: `r0 = service_context`; `r0 = zero-extended metadata
/// byte`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_byte_at_b89(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_BYTE_B89_OFFSET) as *const u8).read() as u32
}

/// ft_service_metadata_pointer — original: `FUN_080512c4` @ `0x080512c4`
/// (8 bytes).
///
/// Returns the raw metadata pointer word at `service_context + 0xf00`. The
/// entire ARM body is `ldr r0,[r0,#0xf00]; bx lr`, so this neither dereferences
/// the returned pointer nor adds NULL, bounds, or ownership handling.
///
/// Register usage: `r0 = service_context`; `r0 = metadata pointer`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_pointer(service_context: *const u8) -> *const u8 {
    (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read()
}





#[cfg(test)]
mod tests {
    use super::{
        ft_service_metadata_byte_at_b50, ft_service_metadata_u16_at_b1c,
        ft_service_metadata_pointer,
        METADATA_BYTE_B50_OFFSET, METADATA_U16_B1C_OFFSET,
        SERVICE_CONTEXT_METADATA_OFFSET,
        ft_service_metadata_byte_at_b89,
        METADATA_BYTE_B89_OFFSET,

    };

    #[repr(C)]
    struct ServiceContextFixture {
        before_metadata: [u8; SERVICE_CONTEXT_METADATA_OFFSET],
        metadata: *const u8,
    }

    #[repr(align(4))]
    struct MetadataFixture([u8; METADATA_U16_B1C_OFFSET + 2]);

    #[repr(align(4))]
    struct MetadataByteFixture([u8; METADATA_BYTE_B50_OFFSET + 1]);


    #[repr(align(4))]
    struct MetadataByteB89Fixture([u8; METADATA_BYTE_B89_OFFSET + 1]);


    #[test]
    fn reads_the_unsigned_halfword_at_the_recovered_offsets() {
        let mut metadata = MetadataFixture([0; METADATA_U16_B1C_OFFSET + 2]);
        metadata.0[METADATA_U16_B1C_OFFSET] = 0xff;
        metadata.0[METADATA_U16_B1C_OFFSET + 1] = 0x80;
        let service_context = ServiceContextFixture {
            before_metadata: [0x5a; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        let result = unsafe {
            ft_service_metadata_u16_at_b1c((&service_context as *const ServiceContextFixture).cast())
        };
        assert_eq!(result, 0x80ff);
        assert_eq!(result as u32, 0x0000_80ff, "ldrh zero-extends into r0");
    }

    #[test]
    fn reads_the_final_halfword_of_the_minimal_recovered_metadata_prefix() {
        let mut metadata = MetadataFixture([0; METADATA_U16_B1C_OFFSET + 2]);
        metadata.0[METADATA_U16_B1C_OFFSET] = 0x34;
        metadata.0[METADATA_U16_B1C_OFFSET + 1] = 0x12;
        let service_context = ServiceContextFixture {
            before_metadata: [0; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        assert_eq!(
            unsafe {
                ft_service_metadata_u16_at_b1c(
                    (&service_context as *const ServiceContextFixture).cast(),
                )
            },
            0x1234,
            "the raw load needs exactly the recovered two bytes",
        );
    }

    #[test]
    fn all_halfword_bit_patterns_survive_the_load() {
        for value in [0x0000u16, 0x7fff, 0x8000, 0xffff] {
            let mut metadata = MetadataFixture([0; METADATA_U16_B1C_OFFSET + 2]);
            metadata.0[METADATA_U16_B1C_OFFSET..].copy_from_slice(&value.to_le_bytes());
            let service_context = ServiceContextFixture {
                before_metadata: [0; SERVICE_CONTEXT_METADATA_OFFSET],
                metadata: metadata.0.as_ptr(),
            };
            assert_eq!(
                unsafe {
                    ft_service_metadata_u16_at_b1c(
                        (&service_context as *const ServiceContextFixture).cast(),
                    )
                },
                value,
            );
        }
    }

    #[test]
    fn reads_the_unsigned_byte_at_the_recovered_offsets() {
        let mut metadata = MetadataByteFixture([0; METADATA_BYTE_B50_OFFSET + 1]);
        metadata.0[METADATA_BYTE_B50_OFFSET] = 0xff;
        let service_context = ServiceContextFixture {
            before_metadata: [0x5a; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        let result = unsafe {
            ft_service_metadata_byte_at_b50((&service_context as *const ServiceContextFixture).cast())
        };
        assert_eq!(result, 0x0000_00ff, "ldrb zero-extends into r0");
    }

    #[test]
    fn reads_the_final_byte_of_the_minimal_recovered_metadata_prefix() {
        let mut metadata = MetadataByteFixture([0; METADATA_BYTE_B50_OFFSET + 1]);
        metadata.0[METADATA_BYTE_B50_OFFSET] = 0x83;
        let service_context = ServiceContextFixture {
            before_metadata: [0; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        assert_eq!(
            unsafe {
                ft_service_metadata_byte_at_b50(
                    (&service_context as *const ServiceContextFixture).cast(),
                )
            },
            0x83,
            "the raw load needs exactly the recovered one byte",
        );
    }
    #[test]
    fn reads_the_unsigned_byte_at_b89_with_arm_zero_extension() {
        let mut metadata = MetadataByteB89Fixture([0; METADATA_BYTE_B89_OFFSET + 1]);
        metadata.0[METADATA_BYTE_B89_OFFSET] = 0xff;
        let service_context = ServiceContextFixture {
            before_metadata: [0x5a; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        let result = unsafe {
            ft_service_metadata_byte_at_b89(
                (&service_context as *const ServiceContextFixture).cast(),
            )
        };
        assert_eq!(result, 0x0000_00ff, "ldrb zero-extends into r0");
    }

    #[test]
    fn reads_the_final_byte_of_the_minimal_b89_metadata_prefix() {
        let mut metadata = MetadataByteB89Fixture([0; METADATA_BYTE_B89_OFFSET + 1]);
        metadata.0[METADATA_BYTE_B89_OFFSET] = 0x83;
        let service_context = ServiceContextFixture {
            before_metadata: [0; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        assert_eq!(
            unsafe {
                ft_service_metadata_byte_at_b89(
                    (&service_context as *const ServiceContextFixture).cast(),
                )
            },
            0x83,
            "the raw load needs exactly the recovered one byte",
        );
    }

    #[test]
    fn returns_the_raw_metadata_pointer_word() {
        let metadata = [0xa5u8; 1];
        let service_context = ServiceContextFixture {
            before_metadata: [0x5a; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };

        let result = unsafe {
            ft_service_metadata_pointer((&service_context as *const ServiceContextFixture).cast())
        };
        assert_eq!(result, metadata.as_ptr(), "ldr returns the pointer word, not its contents");
        assert_eq!(core::mem::offset_of!(ServiceContextFixture, metadata), SERVICE_CONTEXT_METADATA_OFFSET);
    }
}

