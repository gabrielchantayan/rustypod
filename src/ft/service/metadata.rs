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
pub const METADATA_BYTE_B1A_OFFSET: usize = 0xb1a;
/// Byte offset of this signed byte in the metadata block.
pub const METADATA_SIGNED_BYTE_B4E_OFFSET: usize = 0xb4e;
/// Byte offset of this unsigned byte in the metadata block.
pub const METADATA_BYTE_B4F_OFFSET: usize = 0xb4f;
/// Byte offset of this unsigned byte in the metadata block.
pub const METADATA_BYTE_B4D_OFFSET: usize = 0xb4d;

/// Byte offset of this byte in the metadata block.
pub const METADATA_BYTE_B50_OFFSET: usize = 0xb50;
/// Byte offset of this signed byte in the metadata block.
pub const METADATA_SIGNED_BYTE_B52_OFFSET: usize = 0xb52;

/// Byte offset of this byte in the metadata block.
pub const METADATA_BYTE_B89_OFFSET: usize = 0xb89;
/// Byte offset of this unsigned byte in the metadata block.
pub const METADATA_BYTE_B8A_OFFSET: usize = 0xb8a;
/// Byte offset of this byte in the metadata block.
pub const METADATA_BYTE_B70_OFFSET: usize = 0xb70;

/// Byte offset of this unsigned word in the metadata block.
pub const METADATA_WORD_B74_OFFSET: usize = 0xb74;



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

/// ft_service_metadata_byte_at_b1a — original: `FUN_08054f68` @ `0x08054f68`
/// (12 bytes; three unconditional plain `bl` call sites, zero predicated
/// `bl` call sites).
///
/// Raw words `e5900f00`, `e5d00b1a`, and `e12fff1e` establish the complete
/// function from 0x08054f68 through 0x08054f74; the next separately linked
/// function begins at 0x08054f74. Loads the metadata pointer word at
/// `service_context + 0xf00`, then returns its unsigned byte at
/// `metadata + 0xb1a`; `ldrb` zero-extends into `r0`. The concrete layouts
/// and ownership are not recovered, so this deliberately retains raw
/// dereferences with no NULL or bounds checks.
///
/// Deliberate deviation: LLVM emits a frame prologue/epilogue around the two
/// loads; `match.py` confirms the two retail memory operations and offsets.
/// Direct ARM call sites are 0x08114990, 0x08172f00, and 0x08172f14.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_byte_at_b1a(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_BYTE_B1A_OFFSET).read() as u32
}
/// ft_service_metadata_byte_at_b4d — original: `FUN_08054e94` @
/// `0x08054e94` (12 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing BLs).
///
/// Raw words `e5900f00 e5d00b4d e12fff1e` establish the true extent
/// [0x08054e94, 0x08054ea0); the next function begins with a push.
/// Follow the aligned metadata pointer at context+0xf00, then zero-extend
/// the byte at metadata+0xb4d into r0. Callers at 0x08173454 and 0x08173468
/// compare/cache it at caller+0x70; its higher-level meaning is unrecovered.
/// Deliberate deviations: native-width pointers on hosts, four-byte pointers
/// on ARM; no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb4d.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_byte_at_b4d(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_BYTE_B4D_OFFSET).read() as u32
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

/// ft_service_metadata_signed_byte_at_b52 — original: `FUN_080549f4` @
/// `0x080549f4` (16 bytes; three unconditional plain `bl` call sites, zero
/// predicated `bl` call sites).
///
/// Raw words `e5900f00`, `e2800c0b`, `e1d005d2`, and `e12fff1e` establish the
/// complete function from 0x080549f4 through 0x08054a04; the next separately
/// linked function begins at 0x08054a04. Loads the metadata pointer word at
/// `service_context + 0xf00`, adds 0xb00, then sign-extends its byte at +0x52
/// into `r0`. The concrete layouts and ownership are not recovered, so this
/// deliberately retains raw dereferences with no NULL or bounds checks.
///
/// Deliberate deviations: none. Direct ARM call sites are 0x08173474,
/// 0x08173488, and 0x08173498.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_signed_byte_at_b52(
    service_context: *const u8,
) -> i32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_SIGNED_BYTE_B52_OFFSET).read() as i8 as i32
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

/// ft_service_metadata_signed_byte_at_b4e — original: `FUN_08054f74` @
/// `0x08054f74` (16 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing BLs).
///
/// Raw words `e5900f00 e2800c0b e1d004de e12fff1e` decode to
/// `ldr; add #0xb00; ldrsb #0x4e; bx lr`. The next separately called
/// accessor begins at 0x08054f84. Follow the aligned metadata pointer at
/// context+0xf00 and sign-extend the byte at metadata+0xb4e into r0.
/// Callers at 0x08173270 and 0x08173284 compare/cache it at caller+0x85;
/// its higher-level meaning is unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb4e.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_signed_byte_at_b4e(
    service_context: *const u8,
) -> i32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_SIGNED_BYTE_B4E_OFFSET).read() as i8 as i32
}

/// ft_service_metadata_byte_at_b4f — original: `FUN_08054f84` @ `0x08054f84`
/// (12 bytes; two plain inbound BLs, zero predicated inbound BLs,
/// zero outgoing BLs).
///
/// Raw words `e5900f00 e5d00b4f e12fff1e` decode to
/// `ldr r0,[r0,#0xf00]; ldrb r0,[r0,#0xb4f]; bx lr`, ending at the
/// separately called accessor at 0x08054f90. Follow the context's metadata
/// pointer and zero-extend its byte at +0xb4f. Callers at 0x08173238 and
/// 0x0817324c compare/cache the byte at caller+0x84; its meaning is unknown.
/// Deliberate deviations: native-width pointers on hosts, four-byte pointers
/// on ARM; no additional NULL or bounds checks.
/// Codegen deviation: LLVM adds frame setup/teardown; `match.py` confirms
/// both retail loads and their offsets are retained.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb4f.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_byte_at_b4f(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_BYTE_B4F_OFFSET).read() as u32
}

/// ft_service_metadata_byte_at_b8a — original: `FUN_08054f90` @ `0x08054f90`
/// (12 bytes; two plain inbound `bl` call sites, zero predicated inbound
/// `bl` call sites; zero outgoing BLs).
///
/// Raw words `e5900f00 e5d00b8a e12fff1e` decode to
/// `ldr r0,[r0,#0xf00]; ldrb r0,[r0,#0xb8a]; bx lr`. The next real function
/// begins at 0x08054f9c with a push and BL. Follow the context's metadata
/// pointer and zero-extend the byte at +0xb8a into r0. Callers at 0x08173574
/// and 0x08173588 compare/cache the byte; its meaning remains unrecovered.
/// Deliberate deviations: native-width pointers on hosts, target-width on
/// ARM; no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb8a.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_byte_at_b8a(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_BYTE_B8A_OFFSET).read() as u32
}

/// ft_service_metadata_byte_at_b70 — original: `FUN_08054fb0` @ `0x08054fb0`
/// (12 bytes; four unconditional `bl` call sites, zero predicated `bl` call
/// sites, binary-scanned).
///
/// Raw `osos.dec` words establish the complete function: `ldr r0,[r0,#0xf00]`
/// at 0x08054fb0, `ldrb r0,[r0,#0xb70]` at 0x08054fb4, and `bx lr` at
/// 0x08054fb8. The next separately linked function begins at 0x08054fbc.
/// This loads the metadata pointer word at `service_context + 0xf00`, then
/// returns its unsigned byte at `metadata + 0xb70`; `ldrb` zero-extends into
/// `r0`. The concrete layouts and ownership are not recovered, so this
/// deliberately retains raw dereferences with no NULL or bounds checks.
///
/// Deliberate deviations: none. Direct ARM call sites are 0x08112f30,
/// 0x08172300, 0x081734dc, and 0x081734f0.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_byte_at_b70(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_BYTE_B70_OFFSET) as *const u8).read() as u32
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

/// ft_service_metadata_word_at_b74 — original: `FUN_08054ffc` @ `0x08054ffc`
/// (12 bytes).
///
/// Loads the metadata pointer word at `service_context + 0xf00`, then returns
/// the little-endian unsigned word at `metadata + 0xb74`. The entire ARM body
/// is `ldr r0,[r0,#0xf00]; ldr r0,[r0,#0xb74]; bx lr`, so this is a pure
/// aligned word load with no zero-extension and no NULL or bounds checks.
/// Decoding every B/BL word in osos.dec finds exactly five callers, all
/// unconditional plain `bl` at 0x08112f24, 0x08171b4c, 0x08172314,
/// 0x081875a4, and 0x0819b094. The concrete layouts and ownership are not
/// recovered, so this deliberately retains raw dereferences.
///
/// Register usage: `r0 = service_context`; `r0 = metadata word`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_word_at_b74(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_WORD_B74_OFFSET) as *const u32).read()
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
        ft_service_metadata_word_at_b74,
        METADATA_WORD_B74_OFFSET,
        ft_service_metadata_byte_at_b70,
        METADATA_BYTE_B70_OFFSET,
        ft_service_metadata_byte_at_b1a,
        METADATA_BYTE_B1A_OFFSET,
        ft_service_metadata_signed_byte_at_b52,
        METADATA_SIGNED_BYTE_B52_OFFSET,


    };

    #[repr(C)]
    struct ServiceContextFixture {
        before_metadata: [u8; SERVICE_CONTEXT_METADATA_OFFSET],
        metadata: *const u8,
    }

    #[test]
    fn b4d_zero_extends_all_bytes_and_reloads_the_metadata_pointer() {
        use super::{ft_service_metadata_byte_at_b4d, METADATA_BYTE_B4D_OFFSET};
        let mut metadata = [0xa5u8; METADATA_BYTE_B4D_OFFSET + 2];
        let mut other = [0x5au8; METADATA_BYTE_B4D_OFFSET + 2];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in 0..=255u8 {
            metadata[METADATA_BYTE_B4D_OFFSET] = value;
            assert_eq!(unsafe {
                ft_service_metadata_byte_at_b4d((&context as *const ServiceContextFixture).cast())
            }, u32::from(value));
        }
        other[METADATA_BYTE_B4D_OFFSET] = 0x80;
        context.metadata = other.as_ptr();
        assert_eq!(unsafe {
            ft_service_metadata_byte_at_b4d((&context as *const ServiceContextFixture).cast())
        }, 128);
        assert!(metadata[..METADATA_BYTE_B4D_OFFSET].iter().all(|&byte| byte == 0xa5));
        assert_eq!(metadata[METADATA_BYTE_B4D_OFFSET], 255);
        assert_eq!(metadata[METADATA_BYTE_B4D_OFFSET + 1], 0xa5);
        assert!(other[..METADATA_BYTE_B4D_OFFSET].iter().all(|&byte| byte == 0x5a));
        assert_eq!(other[METADATA_BYTE_B4D_OFFSET + 1], 0x5a);
        assert!(context.before_metadata.iter().all(|&byte| byte == 0x3c));
    }

    #[test]
    fn b4e_sign_extends_every_byte_and_follows_replaced_metadata() {
        use super::{ft_service_metadata_signed_byte_at_b4e, METADATA_SIGNED_BYTE_B4E_OFFSET};
        let mut metadata = [0xa5u8; METADATA_SIGNED_BYTE_B4E_OFFSET + 2];
        let mut other = [0x5au8; METADATA_SIGNED_BYTE_B4E_OFFSET + 2];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in 0..=255u8 {
            metadata[METADATA_SIGNED_BYTE_B4E_OFFSET] = value;
            let expected = if value < 128 { i32::from(value) } else { i32::from(value) - 256 };
            assert_eq!(unsafe {
                ft_service_metadata_signed_byte_at_b4e((&context as *const ServiceContextFixture).cast())
            }, expected);
        }
        other[METADATA_SIGNED_BYTE_B4E_OFFSET] = 0x80;
        context.metadata = other.as_ptr();
        assert_eq!(unsafe {
            ft_service_metadata_signed_byte_at_b4e((&context as *const ServiceContextFixture).cast())
        }, -128);
        assert!(metadata[..METADATA_SIGNED_BYTE_B4E_OFFSET].iter().all(|&byte| byte == 0xa5));
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B4E_OFFSET], 255);
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B4E_OFFSET + 1], 0xa5);
        assert!(other[..METADATA_SIGNED_BYTE_B4E_OFFSET].iter().all(|&byte| byte == 0x5a));
        assert_eq!(other[METADATA_SIGNED_BYTE_B4E_OFFSET + 1], 0x5a);
        assert!(context.before_metadata.iter().all(|&byte| byte == 0x3c));
    }

    #[test]
    fn b4f_zero_extends_all_bytes_and_follows_replaced_metadata() {
        use super::{ft_service_metadata_byte_at_b4f, METADATA_BYTE_B4F_OFFSET};
        let mut metadata = [0xa5u8; METADATA_BYTE_B4F_OFFSET + 2];
        let mut other = [0x5au8; METADATA_BYTE_B4F_OFFSET + 2];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in 0..=255u8 {
            metadata[METADATA_BYTE_B4F_OFFSET] = value;
            assert_eq!(unsafe {
                ft_service_metadata_byte_at_b4f((&context as *const ServiceContextFixture).cast())
            }, u32::from(value));
        }
        other[METADATA_BYTE_B4F_OFFSET] = 0x81;
        context.metadata = other.as_ptr();
        assert_eq!(unsafe {
            ft_service_metadata_byte_at_b4f((&context as *const ServiceContextFixture).cast())
        }, 0x81);
        assert!(metadata[..METADATA_BYTE_B4F_OFFSET].iter().all(|&byte| byte == 0xa5));
        assert_eq!(metadata[METADATA_BYTE_B4F_OFFSET], 255);
        assert_eq!(metadata[METADATA_BYTE_B4F_OFFSET + 1], 0xa5);
        assert!(other[..METADATA_BYTE_B4F_OFFSET].iter().all(|&byte| byte == 0x5a));
        assert_eq!(other[METADATA_BYTE_B4F_OFFSET + 1], 0x5a);
        assert!(context.before_metadata.iter().all(|&byte| byte == 0x3c));
    }

    #[test]
    fn b8a_returns_every_unsigned_byte_without_touching_neighbors() {
        use super::{ft_service_metadata_byte_at_b8a, METADATA_BYTE_B8A_OFFSET};
        let mut metadata = [0xa5u8; METADATA_BYTE_B8A_OFFSET + 1];
        let mut other = [0x5au8; METADATA_BYTE_B8A_OFFSET + 1];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in 0..=255u8 {
            metadata[METADATA_BYTE_B8A_OFFSET] = value;
            let result = unsafe {
                ft_service_metadata_byte_at_b8a((&context as *const ServiceContextFixture).cast())
            };
            assert_eq!(result, u32::from(value));
            assert!(metadata[..METADATA_BYTE_B8A_OFFSET].iter().all(|&byte| byte == 0xa5));
        }
        other[METADATA_BYTE_B8A_OFFSET] = 0x81;
        context.metadata = other.as_ptr();
        assert_eq!(unsafe {
            ft_service_metadata_byte_at_b8a((&context as *const ServiceContextFixture).cast())
        }, 0x81, "follow the current pointer rather than a cached metadata block");
        assert!(context.before_metadata.iter().all(|&byte| byte == 0x3c));
    }

    #[repr(align(4))]
    struct MetadataFixture([u8; METADATA_U16_B1C_OFFSET + 2]);
    #[repr(align(4))]
    struct MetadataByteB1AFixture([u8; METADATA_BYTE_B1A_OFFSET + 1]);
    #[repr(align(4))]
    struct MetadataSignedByteB52Fixture([u8; METADATA_SIGNED_BYTE_B52_OFFSET + 1]);



    #[repr(align(4))]
    struct MetadataByteFixture([u8; METADATA_BYTE_B50_OFFSET + 1]);


    #[repr(align(4))]
    struct MetadataByteB89Fixture([u8; METADATA_BYTE_B89_OFFSET + 1]);

    #[repr(align(4))]
    struct MetadataByteB70Fixture([u8; METADATA_BYTE_B70_OFFSET + 1]);


    #[repr(align(4))]
    struct MetadataWordB74Fixture([u8; METADATA_WORD_B74_OFFSET + 4]);


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
    fn reads_the_unsigned_byte_at_b1a_with_arm_zero_extension() {
        let mut metadata = MetadataByteB1AFixture([0; METADATA_BYTE_B1A_OFFSET + 1]);
        metadata.0[METADATA_BYTE_B1A_OFFSET] = 0xff;
        let service_context = ServiceContextFixture {
            before_metadata: [0x5a; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        let result = unsafe {
            ft_service_metadata_byte_at_b1a(
                (&service_context as *const ServiceContextFixture).cast(),
            )
        };
        assert_eq!(result, 0x0000_00ff, "ldrb zero-extends into r0");
    }

    #[test]
    fn all_byte_bit_patterns_survive_the_b1a_load() {
        for value in [0x00u8, 0x7f, 0x80, 0xff] {
            let mut metadata = MetadataByteB1AFixture([0; METADATA_BYTE_B1A_OFFSET + 1]);
            metadata.0[METADATA_BYTE_B1A_OFFSET] = value;
            let service_context = ServiceContextFixture {
                before_metadata: [0; SERVICE_CONTEXT_METADATA_OFFSET],
                metadata: metadata.0.as_ptr(),
            };
            assert_eq!(
                unsafe {
                    ft_service_metadata_byte_at_b1a(
                        (&service_context as *const ServiceContextFixture).cast(),
                    )
                },
                value as u32,
            );
        }
    }

    #[test]
    fn sign_extends_every_signed_metadata_byte_at_b52() {
        for (raw, expected) in [(0x00u8, 0), (0x7f, 127), (0x80, -128), (0xff, -1)] {
            let mut metadata =
                MetadataSignedByteB52Fixture([0; METADATA_SIGNED_BYTE_B52_OFFSET + 1]);
            metadata.0[METADATA_SIGNED_BYTE_B52_OFFSET] = raw;
            let service_context = ServiceContextFixture {
                before_metadata: [0x5a; SERVICE_CONTEXT_METADATA_OFFSET],
                metadata: metadata.0.as_ptr(),
            };

            assert_eq!(
                unsafe {
                    ft_service_metadata_signed_byte_at_b52(
                        (&service_context as *const ServiceContextFixture).cast(),
                    )
                },
                expected,
                "ldrsb sign-extends {raw:#04x} into r0",
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
    fn reads_the_unsigned_byte_at_b70_with_arm_zero_extension() {
        let mut metadata = MetadataByteB70Fixture([0; METADATA_BYTE_B70_OFFSET + 1]);
        metadata.0[METADATA_BYTE_B70_OFFSET] = 0xff;
        let service_context = ServiceContextFixture {
            before_metadata: [0x5a; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        let result = unsafe {
            ft_service_metadata_byte_at_b70(
                (&service_context as *const ServiceContextFixture).cast(),
            )
        };
        assert_eq!(result, 0x0000_00ff, "ldrb zero-extends into r0");
    }

    #[test]
    fn reads_the_final_byte_of_the_minimal_b70_metadata_prefix() {
        let mut metadata = MetadataByteB70Fixture([0; METADATA_BYTE_B70_OFFSET + 1]);
        metadata.0[METADATA_BYTE_B70_OFFSET] = 0x83;
        let service_context = ServiceContextFixture {
            before_metadata: [0; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        assert_eq!(
            unsafe {
                ft_service_metadata_byte_at_b70(
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

    #[test]
    fn reads_the_unsigned_word_at_b74_without_extension() {
        let mut metadata = MetadataWordB74Fixture([0; METADATA_WORD_B74_OFFSET + 4]);
        metadata.0[METADATA_WORD_B74_OFFSET..].copy_from_slice(&0xdec0_addeu32.to_le_bytes());
        let service_context = ServiceContextFixture {
            before_metadata: [0x5a; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        let result = unsafe {
            ft_service_metadata_word_at_b74((&service_context as *const ServiceContextFixture).cast())
        };
        assert_eq!(result, 0xdec0_adde, "ldr preserves all 32 bits, including the high byte");
    }

    #[test]
    fn reads_the_final_word_of_the_minimal_b74_metadata_prefix() {
        let mut metadata = MetadataWordB74Fixture([0; METADATA_WORD_B74_OFFSET + 4]);
        metadata.0[METADATA_WORD_B74_OFFSET..].copy_from_slice(&0x7856_3412u32.to_le_bytes());
        let service_context = ServiceContextFixture {
            before_metadata: [0; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.0.as_ptr(),
        };

        assert_eq!(
            unsafe {
                ft_service_metadata_word_at_b74(
                    (&service_context as *const ServiceContextFixture).cast(),
                )
            },
            0x7856_3412,
            "the raw load needs exactly the recovered four aligned bytes",
        );
    }

    #[test]
    fn all_word_bit_patterns_survive_the_b74_load() {
        for value in [0x0000_0000u32, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
            let mut metadata = MetadataWordB74Fixture([0; METADATA_WORD_B74_OFFSET + 4]);
            metadata.0[METADATA_WORD_B74_OFFSET..].copy_from_slice(&value.to_le_bytes());
            let service_context = ServiceContextFixture {
                before_metadata: [0; SERVICE_CONTEXT_METADATA_OFFSET],
                metadata: metadata.0.as_ptr(),
            };
            assert_eq!(
                unsafe {
                    ft_service_metadata_word_at_b74(
                        (&service_context as *const ServiceContextFixture).cast(),
                    )
                },
                value,
            );
        }
    }
}

