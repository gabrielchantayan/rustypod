//! Kind-resolved backend control-byte write.

use super::object_state::object_backend_for_kind;

/// object_backend_set_primary_control_byte — `FUN_08067478` @ `0x08067478`.
/// True extent: 20 bytes, ending at the next PUSH at `0x0806748c`.
///
/// Raw words: `e1a02001 e52de004 ebffaa4f e5c02f4c e49df004`:
/// preserve r1 in r2, save LR, call `object_backend_for_kind`, store r2's
/// low byte at backend+0xf4c, and return. Whole-image ARM BL decoding finds
/// two plain inbound calls (`0x08230dac`, `0x08230e5c`), no predicated
/// callers, and one plain outbound BL to `0x08051dc4`. The callers set 1
/// and 0 respectively. "Primary" distinguishes this byte from adjacent
/// +0xf4d; the higher-level meaning of both control bytes remains unknown.
///
/// Deliberate deviations: preserve the value through Rust's normal ABI
/// rather than depending on the resolver preserving r2. Host proxies use
/// the existing resolver's aligned host-width pointer seam; firmware
/// pointers remain four bytes wide. No null or kind validation is added.
///
/// # Safety
/// `object` must satisfy [`object_backend_for_kind`] and resolve to a
/// non-null backend writable at +0xf4c, even when storing zero.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_backend_set_primary_control_byte(object: *mut u8, value: u32) {
    let backend = object_backend_for_kind(object) as *mut u8;
    backend.add(0xf4c).write(value as u8);
}

/// object_backend_set_control_byte — original: `FUN_08067d68` @ `0x08067d68`
/// (20 bytes; next real function begins at `0x08067d7c`).
///
/// Raw words `e1a02001 e52de004 ebffa813 e5c02f4d e49df004` decode to
/// `mov r2,r1; str lr,[sp,#-4]!; bl 0x08051dc4; strb r2,[r0,#0xf4d];
/// ldr pc,[sp],#4`. There are two inbound plain BL calls, at `0x0822a4b4`
/// and `0x0822a564`, and no predicated BL callers. The body has one plain
/// BL and no predicated BL calls. Resolve the kind-1 backend or kind-2 proxy
/// through the existing accessor, then overwrite its byte at `+0xf4d`.
/// The callers supply 1 and 0; the field's higher-level meaning is unknown.
///
/// Deliberate deviation: Rust preserves the value across the call using its
/// normal ABI rather than relying on the stock resolver leaving r2 intact.
/// A u32 argument preserves STRB's low-byte truncation for all register values.
/// Host proxy fixtures follow the existing resolver's host-width pointer seam;
/// firmware pointer fields remain four bytes wide. No validation is added.
///
/// # Safety
/// `object` must satisfy [`object_backend_for_kind`] and resolve to a non-null
/// backend writable at `+0xf4d`, including when the byte being stored is zero.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_backend_set_control_byte(object: *mut u8, value: u32) {
    let backend = object_backend_for_kind(object) as *mut u8;
    backend.add(0xf4d).write(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(8))]
    struct Buffer([u8; 0x1008]);

    #[test]
    fn primary_direct_backend_truncates_without_changing_adjacent_control_byte() {
        let mut backend = Buffer([0xa5; 0x1008]);
        backend.0[0] = 1;
        for value in [0, 1, 0xff, 0x100, 0x12345678, u32::MAX] {
            let mut expected = backend.0;
            expected[0xf4c] = value as u8;
            unsafe { object_backend_set_primary_control_byte(backend.0.as_mut_ptr(), value); }
            assert_eq!(backend.0, expected);
        }
    }

    #[test]
    fn primary_proxy_resolves_backend_and_clears_without_mutating_proxy() {
        let mut backend = Buffer([0x5a; 0x1008]);
        backend.0[0] = 1;
        let mut proxy = Buffer([0xa5; 0x1008]);
        let object = unsafe { proxy.0.as_mut_ptr().add(4) };
        unsafe {
            object.write(2);
            object.add(0xefc).cast::<*const u8>().write(backend.0.as_ptr());
        }
        let unchanged_proxy = proxy.0;
        for value in [1, 0x100, 0xff, 0] {
            let mut expected = backend.0;
            expected[0xf4c] = value as u8;
            unsafe { object_backend_set_primary_control_byte(object, value); }
            assert_eq!(backend.0, expected);
            assert_eq!(proxy.0, unchanged_proxy);
        }
    }

    #[test]
    fn direct_backend_truncates_and_preserves_other_bytes() {
        let mut backend = Buffer([0xa5; 0x1008]);
        backend.0[0] = 1;
        for value in [0, 1, 0xff, 0x100, 0x12345678, u32::MAX] {
            let mut expected = backend.0;
            expected[0xf4d] = value as u8;
            unsafe { object_backend_set_control_byte(backend.0.as_mut_ptr(), value); }
            assert_eq!(backend.0, expected);
        }
    }

    #[test]
    fn proxy_updates_only_resolved_backend_and_can_clear() {
        let mut backend = Buffer([0x5a; 0x1008]);
        backend.0[0] = 1;
        let mut proxy = Buffer([0xa5; 0x1008]);
        // +4 makes proxy+0xefc aligned for the resolver's host-width pointer.
        let object = unsafe { proxy.0.as_mut_ptr().add(4) };
        unsafe {
            object.write(2);
            object.add(0xefc).cast::<*const u8>().write(backend.0.as_ptr());
        }
        let unchanged_proxy = proxy.0;
        for value in [1, 0x100, 0xff, 0] {
            let mut expected = backend.0;
            expected[0xf4d] = value as u8;
            unsafe { object_backend_set_control_byte(object, value); }
            assert_eq!(backend.0, expected);
            assert_eq!(proxy.0, unchanged_proxy);
        }
    }
}
