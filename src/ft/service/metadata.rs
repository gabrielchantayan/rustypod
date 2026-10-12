//! Opaque FreeType service-context metadata accessors.
//!
//! The concrete owner and metadata types are not recovered.  These routines
//! describe only the raw offsets observed in retailOS and preserve its direct
//! pointer dereferences.

/// Byte offset of the metadata pointer word in a service-context object.
pub const SERVICE_CONTEXT_METADATA_OFFSET: usize = 0xf00;
/// Byte offset of this unsigned halfword in the metadata block.
pub const METADATA_U16_B1C_OFFSET: usize = 0xb1c;
/// Byte offset of this unsigned halfword in the metadata block.
pub const METADATA_U16_B06_OFFSET: usize = 0xb06;
/// Byte offset of this byte in the metadata block.
pub const METADATA_BYTE_B1A_OFFSET: usize = 0xb1a;
/// Byte offset of this signed byte in the metadata block.
pub const METADATA_SIGNED_BYTE_B4E_OFFSET: usize = 0xb4e;
/// Byte offset of this unsigned byte in the metadata block.
pub const METADATA_BYTE_B4F_OFFSET: usize = 0xb4f;
/// Byte offset of this unsigned byte in the metadata block.
pub const METADATA_BYTE_B4D_OFFSET: usize = 0xb4d;
/// Byte offset of this signed byte in the metadata block.
pub const METADATA_SIGNED_BYTE_B3F_OFFSET: usize = 0xb3f;
/// Byte offset of this signed byte in the metadata block.
pub const METADATA_SIGNED_BYTE_B3E_OFFSET: usize = 0xb3e;
/// Byte offset of this signed byte in the metadata block.
pub const METADATA_SIGNED_BYTE_B3D_OFFSET: usize = 0xb3d;
/// Byte offset of this signed byte in the metadata block.
pub const METADATA_SIGNED_BYTE_B41_OFFSET: usize = 0xb41;
/// Byte offset of this signed byte in the metadata block.
pub const METADATA_SIGNED_BYTE_B40_OFFSET: usize = 0xb40;
/// Byte offset of the low word of this 64-bit metadata value.
pub const METADATA_U64_B44_OFFSET: usize = 0xb44;

/// Byte offset of this signed byte in the metadata block.
pub const METADATA_SIGNED_BYTE_B42_OFFSET: usize = 0xb42;

/// Byte offset of this signed byte in the metadata block.
pub const METADATA_SIGNED_BYTE_B43_OFFSET: usize = 0xb43;

/// Byte offset of this unsigned word in the metadata block.
pub const METADATA_WORD_AF8_OFFSET: usize = 0xaf8;

/// ft_service_metadata_halfword_at_b26 — original: `FUN_0805128c` @
/// `0x0805128c` (16 bytes; two plain inbound BLs at 0x081730b8 and
/// 0x081730cc, zero predicated inbound BLs, zero outgoing BLs of either kind).
///
/// Raw words `e5900f00 e2800c0b e1d002b6 e12fff1e` establish the true
/// extent [0x0805128c, 0x0805129c); the next function reads halfword +0xb1c.
/// Follow the aligned metadata pointer at service_context+0xf00 and
/// zero-extend the aligned halfword at metadata+0xb26. FUN_08172c6c
/// compares/caches it at caller+0x54 and issues three virtual notifications
/// on change. The field's higher-level meaning remains unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` contains an aligned readable metadata pointer at +0xf00,
/// whose pointee has an aligned readable halfword at +0xb26.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_halfword_at_b26(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(0xb26) as *const u16).read() as u32
}

#[cfg(test)]
mod halfword_b26_tests {
    use super::*;

    #[test]
    fn zero_extension_exact_field_and_live_pointer_replacement() {
        #[repr(C)]
        struct Owner {
            padding: [u8; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: *const u16,
        }
        let mut metadata = [0xa5a5u16; 0xb26 / 2 + 2];
        let mut replacement = [0x5a5au16; 0xb26 / 2 + 2];
        let mut owner = Owner {
            padding: [0xcc; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in [0u16, 1, 0xff, 0x100, 0x7fff, 0x8000, 0xabcd, u16::MAX] {
            metadata[0xb26 / 2] = value;
            replacement[0xb26 / 2] = !value;
            let before = metadata;
            let before_replacement = replacement;
            owner.metadata = metadata.as_ptr();
            assert_eq!(unsafe { ft_service_metadata_halfword_at_b26(
                (&owner as *const Owner).cast()) }, u32::from_le_bytes([
                    value as u8, (value >> 8) as u8, 0, 0]));
            owner.metadata = replacement.as_ptr();
            assert_eq!(unsafe { ft_service_metadata_halfword_at_b26(
                (&owner as *const Owner).cast()) }, u32::from(!value));
            assert_eq!(metadata, before);
            assert_eq!(replacement, before_replacement);
            assert_eq!(owner.metadata, replacement.as_ptr());
            assert!(owner.padding.iter().all(|byte| *byte == 0xcc));
        }
    }
}

/// ft_service_metadata_byte_at_b58 — original: `FUN_080515e8` @
/// `0x080515e8` (12 bytes; two plain inbound BLs at 0x08172d90 and
/// 0x08172da4, zero predicated inbound BLs, zero outgoing BLs of either kind).
///
/// Raw words `e5900f00 e5d00b58 e12fff1e` establish the true extent
/// [0x080515e8, 0x080515f4); the next function independently reads +0xb78.
/// Follow the aligned metadata pointer at service_context+0xf00 and
/// zero-extend the byte at metadata+0xb58. FUN_08172c6c compares/caches
/// the result at caller+0x38 and dispatches a virtual notification on change.
/// The field's higher-level meaning remains unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` contains an aligned readable metadata pointer at +0xf00,
/// whose pointee has a readable byte at +0xb58.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_byte_at_b58(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(0xb58).read() as u32
}

#[cfg(test)]
mod byte_b58_tests {
    use super::*;

    #[test]
    fn zero_extends_every_byte_and_follows_live_metadata_without_writes() {
        #[repr(C)]
        struct Owner {
            padding: [u8; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: *const u8,
        }
        let mut metadata = [0xa5u8; 0xb59];
        let mut replacement = [0x5au8; 0xb59];
        let mut owner = Owner {
            padding: [0xcc; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in 0..=u8::MAX {
            metadata[0xb58] = value;
            replacement[0xb58] = !value;
            let before = metadata;
            let before_replacement = replacement;
            owner.metadata = metadata.as_ptr();
            assert_eq!(unsafe { ft_service_metadata_byte_at_b58(
                (&owner as *const Owner).cast()) }, u32::from(value));
            owner.metadata = replacement.as_ptr();
            assert_eq!(unsafe { ft_service_metadata_byte_at_b58(
                (&owner as *const Owner).cast()) }, u32::from(!value));
            assert_eq!(metadata, before);
            assert_eq!(replacement, before_replacement);
            assert_eq!(owner.metadata, replacement.as_ptr());
            assert!(owner.padding.iter().all(|byte| *byte == 0xcc));
        }
    }
}

/// ft_service_metadata_halfword_at_b18 — original: `FUN_08051b50` @
/// `0x08051b50` (16 bytes; two plain inbound BLs at 0x08173018 and
/// 0x0817302c, zero predicated inbound BLs, zero outgoing BLs of either kind).
///
/// Raw words `e5900f00 e2800c0b e1d001b8 e12fff1e` establish the true
/// extent [0x08051b50, 0x08051b60), ending at the independent b10 accessor.
/// Follow the aligned metadata pointer at service_context+0xf00 and
/// zero-extend the aligned halfword at metadata+0xb18. FUN_08172c6c
/// compares/caches it at caller+0x50 and notifies virtually on change.
/// The field's higher-level meaning remains unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` contains an aligned readable metadata pointer at +0xf00,
/// whose pointee has an aligned readable halfword at +0xb18.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_halfword_at_b18(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(0xb18) as *const u16).read() as u32
}

#[cfg(test)]
mod halfword_b18_tests {
    use super::*;

    #[test]
    fn zero_extension_exact_field_and_live_pointer_replacement() {
        #[repr(C)]
        struct Owner {
            padding: [u8; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: *const u16,
        }
        let mut metadata = [0xa5a5u16; 0xb18 / 2 + 2];
        let mut replacement = [0x5a5au16; 0xb18 / 2 + 2];
        let mut owner = Owner {
            padding: [0xcc; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in [0u16, 1, 0xff, 0x100, 0x7fff, 0x8000, 0xabcd, u16::MAX] {
            metadata[0xb18 / 2] = value;
            replacement[0xb18 / 2] = !value;
            let before = metadata;
            let before_replacement = replacement;
            owner.metadata = metadata.as_ptr();
            assert_eq!(unsafe { ft_service_metadata_halfword_at_b18(
                (&owner as *const Owner).cast()) }, u32::from_le_bytes([
                    value as u8, (value >> 8) as u8, 0, 0]));
            owner.metadata = replacement.as_ptr();
            assert_eq!(unsafe { ft_service_metadata_halfword_at_b18(
                (&owner as *const Owner).cast()) }, u32::from(!value));
            assert_eq!(metadata, before);
            assert_eq!(replacement, before_replacement);
            assert_eq!(owner.metadata, replacement.as_ptr());
            assert!(owner.padding.iter().all(|byte| *byte == 0xcc));
        }
    }
}

/// ft_service_metadata_halfword_at_b10 — original: `FUN_08051b60` @
/// `0x08051b60` (16 bytes; two plain inbound BLs at 0x08172fe0 and
/// 0x08172ff4, zero predicated inbound BLs, zero outgoing BLs).
///
/// Raw words `e5900f00 e2800c0b e1d001b0 e12fff1e` establish the true
/// extent [0x08051b60, 0x08051b70), ending at the independent af0 accessor.
/// Follow the aligned metadata pointer at service_context+0xf00 and
/// zero-extend the aligned halfword at metadata+0xb10. FUN_08172c6c
/// compares/caches it at caller+0x4e and notifies virtually on change.
/// The field's higher-level meaning remains unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` contains an aligned readable metadata pointer at +0xf00,
/// whose pointee has an aligned readable halfword at +0xb10.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_halfword_at_b10(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(0xb10) as *const u16).read() as u32
}

#[cfg(test)]
mod halfword_b10_tests {
    use super::*;

    #[test]
    fn zero_extends_halfwords_and_follows_replaced_metadata_without_writes() {
        #[repr(C)]
        struct Owner {
            padding: [u8; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: *const u16,
        }
        let mut metadata = [0xa5a5u16; 0xb10 / 2 + 2];
        let mut replacement = [0x5a5au16; 0xb10 / 2 + 2];
        let mut owner = Owner {
            padding: [0xcc; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in [0u16, 1, 0xff, 0x100, 0x7fff, 0x8000, 0xabcd, u16::MAX] {
            metadata[0xb10 / 2] = value;
            replacement[0xb10 / 2] = !value;
            let before = metadata;
            let before_replacement = replacement;
            owner.metadata = metadata.as_ptr();
            assert_eq!(unsafe { ft_service_metadata_halfword_at_b10(
                (&owner as *const Owner).cast()) }, u32::from(value));
            owner.metadata = replacement.as_ptr();
            assert_eq!(unsafe { ft_service_metadata_halfword_at_b10(
                (&owner as *const Owner).cast()) }, u32::from(!value));
            assert_eq!(metadata, before);
            assert_eq!(replacement, before_replacement);
            assert_eq!(owner.metadata, replacement.as_ptr());
            assert!(owner.padding.iter().all(|byte| *byte == 0xcc));
        }
    }
}

/// ft_service_metadata_word_at_af0 — original: `FUN_08051b70` @
/// `0x08051b70` (12 bytes; two plain inbound BLs at 0x08172d54 and
/// 0x08172d6c, zero predicated inbound BLs, zero outgoing BLs of either kind).
///
/// Raw words `e5900f00 e5900af0 e12fff1e` establish the true extent
/// [0x08051b70, 0x08051b7c); the next function independently loads byte +0xb1b.
/// Follow the aligned metadata pointer at service_context+0xf00 and return
/// the complete word at metadata+0xaf0. FUN_08172c6c compares/caches it at
/// caller+0x3c and dispatches a virtual notification when it changes.
/// The field's higher-level meaning is unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee has an aligned readable word at +0xaf0.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_word_at_af0(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(0xaf0) as *const u32).read()
}

#[cfg(test)]
mod word_af0_tests {
    use super::*;

    #[test]
    fn full_width_values_live_updates_and_pointer_replacement() {
        let mut owner = [0usize; 0xf00 / core::mem::size_of::<usize>() + 1];
        let mut metadata = [0xa5a5a5a5u32; 0xaf0 / 4 + 2];
        let mut replacement = [0x5a5a5a5au32; 0xaf0 / 4 + 2];
        let context = owner.as_mut_ptr().cast::<u8>();
        unsafe {
            context.add(0xf00).cast::<*const u8>().write(metadata.as_ptr().cast());
            for value in [0, 1, 0xff, 0x100, 0x7fffffff, 0x80000000, 0x89abcdef, u32::MAX] {
                metadata[0xaf0 / 4] = value;
                assert_eq!(ft_service_metadata_word_at_af0(context), value);
            }
            replacement[0xaf0 / 4] = 0x12345678;
            context.add(0xf00).cast::<*const u8>().write(replacement.as_ptr().cast());
            assert_eq!(ft_service_metadata_word_at_af0(context), 0x12345678);
            context.add(0xf00).cast::<*const u8>().write(metadata.as_ptr().cast());
            assert_eq!(ft_service_metadata_word_at_af0(context), u32::MAX);
        }
        assert!(metadata.iter().enumerate().all(|(i, word)| i == 0xaf0 / 4 || *word == 0xa5a5a5a5));
        assert!(replacement.iter().enumerate().all(|(i, word)| i == 0xaf0 / 4 || *word == 0x5a5a5a5a));
    }
}

/// ft_service_metadata_byte_at_b4c — original: `FUN_08052328` @
/// `0x08052328` (12 bytes; two plain inbound BLs at 0x08172f38 and
/// 0x08172f4c, zero predicated inbound BLs, zero outgoing BLs).
///
/// Raw words `e5900f00 e5d00b4c e12fff1e` establish the true extent
/// [0x08052328, 0x08052334); the next function tail-branches to 0x080b4444.
/// Follow the aligned pointer at service_context+0xf00 and zero-extend
/// metadata byte +0xb4c. The caller compares/caches it at caller+0x57;
/// its higher-level meaning is unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb4c.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_byte_at_b4c(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(0xb4c).read() as u32
}

#[cfg(test)]
mod byte_b4c_tests {
    use super::*;

    #[test]
    fn unsigned_byte_values_and_live_pointer_replacement() {
        let mut owner = [0usize; 0xf00 / core::mem::size_of::<usize>() + 1];
        let mut metadata = [0xa5u8; 0xb4d];
        let mut replacement = [0x5au8; 0xb4d];
        let context = owner.as_mut_ptr().cast::<u8>();
        unsafe {
            context.add(0xf00).cast::<*const u8>().write(metadata.as_ptr());
            for value in 0..=255u8 {
                metadata[0xb4c] = value;
                assert_eq!(ft_service_metadata_byte_at_b4c(context), value as u32);
            }
            replacement[0xb4c] = 0x80;
            context.add(0xf00).cast::<*const u8>().write(replacement.as_ptr());
            assert_eq!(ft_service_metadata_byte_at_b4c(context), 128);
            context.add(0xf00).cast::<*const u8>().write(metadata.as_ptr());
            assert_eq!(ft_service_metadata_byte_at_b4c(context), 255);
        }
        assert!(metadata[..0xb4c].iter().all(|byte| *byte == 0xa5));
        assert!(replacement[..0xb4c].iter().all(|byte| *byte == 0x5a));
    }
}

/// ft_service_metadata_action — original: `FUN_08054de0` @ `0x08054de0`.
///
/// True size 40 bytes, [0x08054de0, 0x08054e08), ending at the independent
/// af8 accessor. Raw A32 words verify two plain inbound BLs (0x08172c78,
/// 0x0817b970), zero predicated inbound BLs, and zero outgoing BLs of either
/// kind. Follow the aligned pointer at context+0xf00. A zero byte at
/// metadata+0x1c returns 0 without reading +0x8e; otherwise return 1 for a
/// zero byte at +0x8e and 2 for any nonzero byte. The playback-action caller
/// uses the result as nonzero/exactly-two flags; deeper field meanings
/// remain unrecovered. Deliberate deviations: native-width host pointers,
/// four-byte ARM pointers; no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00. Metadata must be readable at +0x1c and, if nonzero, at +0x8e.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_action(service_context: *const u8) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    if metadata.add(0x1c).read() == 0 { return 0; }
    if metadata.add(0x8e).read() == 0 { 1 } else { 2 }
}

#[cfg(test)]
mod action_tests {
    use super::*;

    #[test]
    fn exhaustive_unsigned_flags_and_pointer_replacement() {
        let mut owner = [0usize; 0xf00 / core::mem::size_of::<usize>() + 1];
        let mut metadata = [0xa5u8; 0x8f];
        let context = owner.as_mut_ptr().cast::<u8>();
        unsafe {
            context.add(0xf00).cast::<*const u8>().write(metadata.as_ptr());
            for gate in 0..=255u8 {
                for secondary in 0..=255u8 {
                    metadata[0x1c] = gate;
                    metadata[0x8e] = secondary;
                    let expected = if gate == 0 { 0 } else if secondary == 0 { 1 } else { 2 };
                    assert_eq!(ft_service_metadata_action(context), expected);
                }
            }
            // Only the first byte is valid: the zero path must not read +0x8e.
            let short = [0u8; 0x1d];
            context.add(0xf00).cast::<*const u8>().write(short.as_ptr());
            assert_eq!(ft_service_metadata_action(context), 0);
            metadata[0x1c] = 0x80;
            metadata[0x8e] = 0xff;
            context.add(0xf00).cast::<*const u8>().write(metadata.as_ptr());
            assert_eq!(ft_service_metadata_action(context), 2);
        }
        assert!(metadata.iter().enumerate().all(|(i, b)| i == 0x1c || i == 0x8e || *b == 0xa5));
    }
}

/// ft_service_metadata_word_at_af8 — original: `FUN_08054e08` @
/// `0x08054e08` (12 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing plain or predicated BLs).
///
/// Raw words `e5900f00 e5900af8 e12fff1e` establish the true extent
/// [0x08054e08, 0x08054e14), ending at the separately called b43 accessor.
/// Follow the aligned metadata pointer at context+0xf00 and return the
/// complete word at metadata+0xaf8. Callers at 0x08172e14 and 0x08172e28
/// compare it with a byte at caller+0x41 and cache its low byte there.
/// The field's higher-level meaning is unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee has an aligned readable word at +0xaf8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_word_at_af8(
    service_context: *const u8,
) -> u32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_WORD_AF8_OFFSET) as *const u32).read()
}

/// ft_service_metadata_signed_byte_at_b43 — original: `FUN_08054e14` @
/// `0x08054e14` (16 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing plain or predicated BLs).
///
/// Raw words `e5900f00 e2800c0b e1d004d3 e12fff1e` establish the extent
/// [0x08054e14, 0x08054e24), ending at the separately called b42 accessor.
/// Follow the aligned metadata pointer at context+0xf00 and sign-extend
/// the byte at metadata+0xb43 into r0. Callers at 0x08173410 and 0x08173424
/// compare/cache it at caller+0x65; its higher-level meaning is unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb43.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_signed_byte_at_b43(
    service_context: *const u8,
) -> i32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_SIGNED_BYTE_B43_OFFSET) as *const i8).read() as i32
}

/// ft_service_metadata_signed_byte_at_b42 — original: `FUN_08054e24` @
/// `0x08054e24` (16 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing plain or predicated BLs).
///
/// Raw words `e5900f00 e2800c0b e1d004d2 e12fff1e` establish the extent
/// [0x08054e24, 0x08054e34), ending at the separately called u64 accessor.
/// Follow the aligned metadata pointer at context+0xf00 and sign-extend
/// the byte at metadata+0xb42 into r0. Callers at 0x081733f0 and 0x08173404
/// compare/cache it at caller+0x64; its higher-level meaning is unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb42.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_signed_byte_at_b42(
    service_context: *const u8,
) -> i32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_SIGNED_BYTE_B42_OFFSET) as *const i8).read() as i32
}

/// ft_service_metadata_u64_at_b44 — original: `FUN_08054e34` @
/// `0x08054e34` (16 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing plain or predicated BLs).
///
/// Raw words `e5901f00 e5910b44 e5911b48 e12fff1e` establish the extent
/// [0x08054e34, 0x08054e44), ending at the separately called signed-byte
/// accessor. Follow the aligned pointer at context+0xf00, load the low
/// word at metadata+0xb44 and high word at +0xb48, and return them in r0:r1.
/// Callers at 0x08173430 and 0x08173448 compare/cache both words at
/// caller+0x68; the field's higher-level meaning is unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no added NULL or bounds checks. Separate u32 reads retain four-byte
/// alignment rather than requiring an eight-byte-aligned u64 pointer.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee has aligned readable words at +0xb44 and +0xb48.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_u64_at_b44(
    service_context: *const u8,
) -> u64 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    let words = metadata.add(METADATA_U64_B44_OFFSET) as *const u32;
    let low = words.read();
    let high = words.add(1).read();
    (low as u64) | ((high as u64) << 32)
}

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

/// ft_service_metadata_u16_at_b06 — original: `FUN_08053e40` @ `0x08053e40`.
///
/// True extent [0x08053e40, 0x08053e50), 16 bytes, ending at the next
/// independent push-based function. Raw words are `e5900f00 e2800c0b
/// e1d000b6 e12fff1e`. Two plain inbound BLs at 0x08172ce4 and 0x08172cf8,
/// zero predicated inbound BLs, zero outgoing BLs of either kind.
/// Follow the aligned metadata pointer at context+0xf00 and zero-extend
/// the halfword at metadata+0xb06. The caller compares/caches it at +0x4c;
/// its higher-level meaning remains unknown.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee has an aligned readable halfword at +0xb06.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_u16_at_b06(service_context: *const u8) -> u16 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    (metadata.add(METADATA_U16_B06_OFFSET) as *const u16).read()
}

#[cfg(test)]
mod b06_tests {
    use super::*;

    #[test]
    fn unsigned_halfword_live_updates_and_pointer_replacement() {
        let mut owner = [0usize; 0xf00 / core::mem::size_of::<usize>() + 1];
        let mut metadata = [0xa55au16; 0xb08 / 2];
        let other = [0x1234u16; 0xb08 / 2];
        let context = owner.as_mut_ptr().cast::<u8>();
        unsafe {
            context.add(0xf00).cast::<*const u8>().write(metadata.as_ptr().cast());
            for value in 0..=u16::MAX {
                metadata[0xb06 / 2] = value;
                assert_eq!(ft_service_metadata_u16_at_b06(context), value);
            }
            context.add(0xf00).cast::<*const u8>().write(other.as_ptr().cast());
            assert_eq!(ft_service_metadata_u16_at_b06(context), 0x1234);
            context.add(0xf00).cast::<*const u8>().write(metadata.as_ptr().cast());
            assert_eq!(ft_service_metadata_u16_at_b06(context), u16::MAX);
        }
        assert!(metadata[..0xb06 / 2].iter().all(|&word| word == 0xa55a));
    }
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

/// ft_service_metadata_signed_byte_at_b40 — original: `FUN_08054e44` @
/// `0x08054e44` (16 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing plain or predicated BLs).
///
/// Raw words `e5900f00 e2800c0b e1d004d0 e12fff1e` decode to
/// `ldr; add #0xb00; ldrsb #0x40; bx lr`. The next real function is the
/// separately called accessor at 0x08054e54. Follow the aligned metadata
/// pointer at context+0xf00 and sign-extend its byte at +0xb40 into r0.
/// Callers at 0x081733b0 and 0x081733c4 compare/cache it at caller+0x62;
/// its higher-level meaning is unknown.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
/// Codegen deviation: LLVM adds frame setup/teardown and uses a register
/// offset of 0xb40 for `ldrsb` instead of `add #0xb00; ldrsb #0x40`.
/// The aligned pointer load and signed byte load are retained.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb40.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_signed_byte_at_b40(
    service_context: *const u8,
) -> i32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_SIGNED_BYTE_B40_OFFSET).read() as i8 as i32
}

/// ft_service_metadata_signed_byte_at_b41 — original: `FUN_08054e54` @
/// `0x08054e54` (16 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing plain or predicated BLs).
///
/// Raw words `e5900f00 e2800c0b e1d004d1 e12fff1e` decode to
/// `ldr; add #0xb00; ldrsb #0x41; bx lr`. The next real function is the
/// separately called accessor at 0x08054e64. Follow the aligned metadata
/// pointer at context+0xf00 and sign-extend its byte at +0xb41 into r0.
/// Callers at 0x081733d0 and 0x081733e4 compare/cache it at caller+0x63;
/// its higher-level meaning is unknown.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb41.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_signed_byte_at_b41(
    service_context: *const u8,
) -> i32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_SIGNED_BYTE_B41_OFFSET).read() as i8 as i32
}

/// ft_service_metadata_signed_byte_at_b3d — original: `FUN_08054e64` @
/// `0x08054e64` (16 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing plain or predicated BLs).
///
/// Raw words `e5900f00 e2800c0b e1d003dd e12fff1e` decode to
/// `ldr; add #0xb00; ldrsb #0x3d; bx lr`. The next real function is the
/// separately called accessor at 0x08054e74. Follow the aligned metadata
/// pointer at context+0xf00 and sign-extend its byte at +0xb3d into r0.
/// Callers at 0x08173320 and 0x08173334 compare/cache it at caller+0x60
/// and notify through a virtual method; its higher-level meaning is unknown.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb3d.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_signed_byte_at_b3d(
    service_context: *const u8,
) -> i32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_SIGNED_BYTE_B3D_OFFSET).read() as i8 as i32
}

/// ft_service_metadata_signed_byte_at_b3e — original: `FUN_08054e74` @
/// `0x08054e74` (16 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing plain or predicated BLs).
///
/// Raw words `e5900f00 e2800c0b e1d003de e12fff1e` decode to
/// `ldr; add #0xb00; ldrsb #0x3e; bx lr`. The next real function is the
/// separately called accessor at 0x08054e84. Follow the aligned metadata
/// pointer at context+0xf00 and sign-extend its byte at +0xb3e into r0.
/// Callers at 0x08173358 and 0x0817336c compare/cache it at caller+0x61
/// and notify through a virtual method; its higher-level meaning is unknown.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb3e.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_signed_byte_at_b3e(
    service_context: *const u8,
) -> i32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_SIGNED_BYTE_B3E_OFFSET).read() as i8 as i32
}

/// ft_service_metadata_signed_byte_at_b3f — original: `FUN_08054e84` @
/// `0x08054e84` (16 bytes; two plain inbound BLs, zero predicated inbound
/// BLs, zero outgoing BLs).
///
/// Raw words `e5900f00 e2800c0b e1d003df e12fff1e` decode to
/// `ldr; add #0xb00; ldrsb #0x3f; bx lr`. The next real function is the
/// separately called accessor at 0x08054e94. Follow the aligned metadata
/// pointer at context+0xf00 and sign-extend its byte at +0xb3f into r0.
/// Callers at 0x08173390 and 0x081733a4 compare/cache it at caller+0x66;
/// its higher-level meaning is unrecovered.
/// Deliberate deviations: native-width host pointers, four-byte ARM pointers;
/// no additional NULL or bounds checks.
///
/// # Safety
/// `service_context` must contain an aligned readable metadata pointer at
/// +0xf00, whose pointee is readable through +0xb3f.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_metadata_signed_byte_at_b3f(
    service_context: *const u8,
) -> i32 {
    let metadata = (service_context.add(SERVICE_CONTEXT_METADATA_OFFSET) as *const *const u8).read();
    metadata.add(METADATA_SIGNED_BYTE_B3F_OFFSET).read() as i8 as i32
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
    fn af8_preserves_all_bits_and_follows_replaced_metadata() {
        use super::{ft_service_metadata_word_at_af8, METADATA_WORD_AF8_OFFSET};
        // The requested word is the last readable word of each fixture.
        let mut metadata = [0x5a5a_5a5au32; METADATA_WORD_AF8_OFFSET / 4 + 1];
        let mut alternate = [0xa5a5_a5a5u32; METADATA_WORD_AF8_OFFSET / 4 + 1];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr().cast(),
        };
        for value in [0u32, 1, 0xff, 0x100, 0x7fff_ffff, 0x8000_0000, 0x1234_5678, u32::MAX] {
            metadata[METADATA_WORD_AF8_OFFSET / 4] = value;
            alternate[METADATA_WORD_AF8_OFFSET / 4] = !value;
            for (pointer, expected) in [
                (metadata.as_ptr(), value),
                (alternate.as_ptr(), !value),
            ] {
                context.metadata = pointer.cast();
                assert_eq!(unsafe {
                    ft_service_metadata_word_at_af8(
                        (&context as *const ServiceContextFixture).cast(),
                    )
                }, expected);
            }
        }
    }

    #[test]
    fn b43_sign_extends_every_byte_and_follows_replaced_metadata() {
        use super::{ft_service_metadata_signed_byte_at_b43, METADATA_SIGNED_BYTE_B43_OFFSET};
        let mut metadata = [0x5au8; METADATA_SIGNED_BYTE_B43_OFFSET + 2];
        let mut alternate = [0xa5u8; METADATA_SIGNED_BYTE_B43_OFFSET + 2];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for byte in 0u16..=255 {
            metadata[METADATA_SIGNED_BYTE_B43_OFFSET] = byte as u8;
            alternate[METADATA_SIGNED_BYTE_B43_OFFSET] = !byte as u8;
            for (pointer, value) in [
                (metadata.as_ptr(), byte as i32),
                (alternate.as_ptr(), 255 - byte as i32),
            ] {
                context.metadata = pointer;
                let expected = if value < 128 { value } else { value - 256 };
                assert_eq!(unsafe {
                    ft_service_metadata_signed_byte_at_b43(
                        (&context as *const ServiceContextFixture).cast(),
                    )
                }, expected, "byte {value:#04x}");
            }
        }
    }

    #[test]
    fn b42_sign_extends_every_byte_and_follows_replaced_metadata() {
        use super::{ft_service_metadata_signed_byte_at_b42, METADATA_SIGNED_BYTE_B42_OFFSET};
        let mut metadata = [0x5au8; METADATA_SIGNED_BYTE_B42_OFFSET + 2];
        let mut alternate = [0xa5u8; METADATA_SIGNED_BYTE_B42_OFFSET + 2];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for byte in 0u16..=255 {
            metadata[METADATA_SIGNED_BYTE_B42_OFFSET] = byte as u8;
            alternate[METADATA_SIGNED_BYTE_B42_OFFSET] = !byte as u8;
            for (pointer, value) in [
                (metadata.as_ptr(), byte as i32),
                (alternate.as_ptr(), 255 - byte as i32),
            ] {
                context.metadata = pointer;
                let expected = if value < 128 { value } else { value - 256 };
                assert_eq!(unsafe {
                    ft_service_metadata_signed_byte_at_b42(
                        (&context as *const ServiceContextFixture).cast(),
                    )
                }, expected, "byte {value:#04x}");
            }
        }
    }

    #[test]
    fn b44_preserves_word_order_and_all_boundary_bits() {
        use super::{ft_service_metadata_u64_at_b44, METADATA_U64_B44_OFFSET};
        // The final pair starts at +0xb44, only four-byte aligned.
        let mut metadata = [0xa5a5_a5a5u32; (METADATA_U64_B44_OFFSET + 8) / 4];
        let context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr().cast(),
        };
        for low in [0u32, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            for high in [0u32, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                metadata[METADATA_U64_B44_OFFSET / 4] = low;
                metadata[METADATA_U64_B44_OFFSET / 4 + 1] = high;
                let bytes: [u8; 8] = [
                    low.to_le_bytes(), high.to_le_bytes(),
                ].concat().try_into().unwrap();
                assert_eq!(unsafe {
                    ft_service_metadata_u64_at_b44((&context as *const ServiceContextFixture).cast())
                }, u64::from_le_bytes(bytes));
            }
        }
    }

    #[test]
    fn b44_reloads_both_words_and_replaced_metadata_pointer() {
        use super::{ft_service_metadata_u64_at_b44, METADATA_U64_B44_OFFSET};
        let mut first = [0u32; (METADATA_U64_B44_OFFSET + 8) / 4];
        let mut second = first;
        first[METADATA_U64_B44_OFFSET / 4] = 0x7654_3210;
        second[METADATA_U64_B44_OFFSET / 4 + 1] = 0xfedc_ba98;
        let mut context = ServiceContextFixture {
            before_metadata: [0; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: first.as_ptr().cast(),
        };
        let read = |context: &ServiceContextFixture| unsafe {
            ft_service_metadata_u64_at_b44((context as *const ServiceContextFixture).cast())
        };
        assert_eq!(read(&context), 0x7654_3210);
        first[METADATA_U64_B44_OFFSET / 4 + 1] = 0x8000_0000;
        assert_eq!(read(&context), 0x8000_0000_7654_3210);
        context.metadata = second.as_ptr().cast();
        assert_eq!(read(&context), 0xfedc_ba98_0000_0000);
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
    fn b40_sign_extends_every_byte_and_follows_replaced_metadata() {
        use super::{ft_service_metadata_signed_byte_at_b40, METADATA_SIGNED_BYTE_B40_OFFSET};
        let mut metadata = [0xa5u8; METADATA_SIGNED_BYTE_B40_OFFSET + 2];
        let mut other = [0x5au8; METADATA_SIGNED_BYTE_B40_OFFSET + 2];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in 0..=255u8 {
            metadata[METADATA_SIGNED_BYTE_B40_OFFSET] = value;
            let expected = if value < 128 { i32::from(value) } else { i32::from(value) - 256 };
            assert_eq!(unsafe {
                ft_service_metadata_signed_byte_at_b40((&context as *const ServiceContextFixture).cast())
            }, expected);
        }
        other[METADATA_SIGNED_BYTE_B40_OFFSET] = 0x80;
        context.metadata = other.as_ptr();
        assert_eq!(unsafe {
            ft_service_metadata_signed_byte_at_b40((&context as *const ServiceContextFixture).cast())
        }, -128);
        assert!(metadata[..METADATA_SIGNED_BYTE_B40_OFFSET].iter().all(|&byte| byte == 0xa5));
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B40_OFFSET], 255);
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B40_OFFSET + 1], 0xa5);
        assert!(other[..METADATA_SIGNED_BYTE_B40_OFFSET].iter().all(|&byte| byte == 0x5a));
        assert_eq!(other[METADATA_SIGNED_BYTE_B40_OFFSET + 1], 0x5a);
        assert!(context.before_metadata.iter().all(|&byte| byte == 0x3c));
    }

    #[test]
    fn b41_sign_extends_every_byte_and_follows_replaced_metadata() {
        use super::{ft_service_metadata_signed_byte_at_b41, METADATA_SIGNED_BYTE_B41_OFFSET};
        let mut metadata = [0xa5u8; METADATA_SIGNED_BYTE_B41_OFFSET + 2];
        let mut other = [0x5au8; METADATA_SIGNED_BYTE_B41_OFFSET + 2];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in 0..=255u8 {
            metadata[METADATA_SIGNED_BYTE_B41_OFFSET] = value;
            let expected = if value < 128 { i32::from(value) } else { i32::from(value) - 256 };
            assert_eq!(unsafe {
                ft_service_metadata_signed_byte_at_b41((&context as *const ServiceContextFixture).cast())
            }, expected);
        }
        other[METADATA_SIGNED_BYTE_B41_OFFSET] = 0x80;
        context.metadata = other.as_ptr();
        assert_eq!(unsafe {
            ft_service_metadata_signed_byte_at_b41((&context as *const ServiceContextFixture).cast())
        }, -128);
        assert!(metadata[..METADATA_SIGNED_BYTE_B41_OFFSET].iter().all(|&byte| byte == 0xa5));
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B41_OFFSET], 255);
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B41_OFFSET + 1], 0xa5);
        assert!(other[..METADATA_SIGNED_BYTE_B41_OFFSET].iter().all(|&byte| byte == 0x5a));
        assert_eq!(other[METADATA_SIGNED_BYTE_B41_OFFSET + 1], 0x5a);
        assert!(context.before_metadata.iter().all(|&byte| byte == 0x3c));
    }

    #[test]
    fn b3d_sign_extends_every_byte_and_follows_replaced_metadata() {
        use super::{ft_service_metadata_signed_byte_at_b3d, METADATA_SIGNED_BYTE_B3D_OFFSET};
        let mut metadata = [0xa5u8; METADATA_SIGNED_BYTE_B3D_OFFSET + 2];
        let mut other = [0x5au8; METADATA_SIGNED_BYTE_B3D_OFFSET + 2];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in 0..=255u8 {
            metadata[METADATA_SIGNED_BYTE_B3D_OFFSET] = value;
            let expected = if value < 128 { i32::from(value) } else { i32::from(value) - 256 };
            assert_eq!(unsafe {
                ft_service_metadata_signed_byte_at_b3d((&context as *const ServiceContextFixture).cast())
            }, expected);
        }
        other[METADATA_SIGNED_BYTE_B3D_OFFSET] = 0x80;
        context.metadata = other.as_ptr();
        assert_eq!(unsafe {
            ft_service_metadata_signed_byte_at_b3d((&context as *const ServiceContextFixture).cast())
        }, -128);
        assert!(metadata[..METADATA_SIGNED_BYTE_B3D_OFFSET].iter().all(|&byte| byte == 0xa5));
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B3D_OFFSET], 255);
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B3D_OFFSET + 1], 0xa5);
        assert!(other[..METADATA_SIGNED_BYTE_B3D_OFFSET].iter().all(|&byte| byte == 0x5a));
        assert_eq!(other[METADATA_SIGNED_BYTE_B3D_OFFSET + 1], 0x5a);
        assert!(context.before_metadata.iter().all(|&byte| byte == 0x3c));
    }

    #[test]
    fn b3e_sign_extends_every_byte_and_follows_replaced_metadata() {
        use super::{ft_service_metadata_signed_byte_at_b3e, METADATA_SIGNED_BYTE_B3E_OFFSET};
        let mut metadata = [0xa5u8; METADATA_SIGNED_BYTE_B3E_OFFSET + 2];
        let mut other = [0x5au8; METADATA_SIGNED_BYTE_B3E_OFFSET + 1];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in 0..=255u8 {
            metadata[METADATA_SIGNED_BYTE_B3E_OFFSET] = value;
            let expected = if value < 128 { i32::from(value) } else { i32::from(value) - 256 };
            assert_eq!(unsafe {
                ft_service_metadata_signed_byte_at_b3e((&context as *const ServiceContextFixture).cast())
            }, expected);
        }
        other[METADATA_SIGNED_BYTE_B3E_OFFSET] = 0x80;
        context.metadata = other.as_ptr();
        assert_eq!(unsafe {
            ft_service_metadata_signed_byte_at_b3e((&context as *const ServiceContextFixture).cast())
        }, -128);
        assert!(metadata[..METADATA_SIGNED_BYTE_B3E_OFFSET].iter().all(|&byte| byte == 0xa5));
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B3E_OFFSET], 255);
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B3E_OFFSET + 1], 0xa5);
        assert!(other[..METADATA_SIGNED_BYTE_B3E_OFFSET].iter().all(|&byte| byte == 0x5a));
        assert!(context.before_metadata.iter().all(|&byte| byte == 0x3c));
    }

    #[test]
    fn b3f_sign_extends_every_byte_and_follows_replaced_metadata() {
        use super::{ft_service_metadata_signed_byte_at_b3f, METADATA_SIGNED_BYTE_B3F_OFFSET};
        let mut metadata = [0xa5u8; METADATA_SIGNED_BYTE_B3F_OFFSET + 2];
        let mut other = [0x5au8; METADATA_SIGNED_BYTE_B3F_OFFSET + 2];
        let mut context = ServiceContextFixture {
            before_metadata: [0x3c; SERVICE_CONTEXT_METADATA_OFFSET],
            metadata: metadata.as_ptr(),
        };
        for value in 0..=255u8 {
            metadata[METADATA_SIGNED_BYTE_B3F_OFFSET] = value;
            let expected = if value < 128 { i32::from(value) } else { i32::from(value) - 256 };
            assert_eq!(unsafe {
                ft_service_metadata_signed_byte_at_b3f((&context as *const ServiceContextFixture).cast())
            }, expected);
        }
        other[METADATA_SIGNED_BYTE_B3F_OFFSET] = 0x80;
        context.metadata = other.as_ptr();
        assert_eq!(unsafe {
            ft_service_metadata_signed_byte_at_b3f((&context as *const ServiceContextFixture).cast())
        }, -128);
        assert!(metadata[..METADATA_SIGNED_BYTE_B3F_OFFSET].iter().all(|&byte| byte == 0xa5));
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B3F_OFFSET], 255);
        assert_eq!(metadata[METADATA_SIGNED_BYTE_B3F_OFFSET + 1], 0xa5);
        assert!(other[..METADATA_SIGNED_BYTE_B3F_OFFSET].iter().all(|&byte| byte == 0x5a));
        assert_eq!(other[METADATA_SIGNED_BYTE_B3F_OFFSET + 1], 0x5a);
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

