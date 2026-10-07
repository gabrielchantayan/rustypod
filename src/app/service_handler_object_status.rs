//! Service-handler object status query — FUN_081637fc @ 0x081637fc.
//! True extent: 72 bytes [0x081637fc, 0x08163844), next function's push.
//! Raw full-image decoding verifies two inbound plain BLs (0x0818f8e4,
//! 0x08190980), zero predicated BLs; body has one plain BL, no predicated BL.
//! Read signed status at +0x908. If above 10, call resident 0x081638d4
//! with a zero-initialized scratch word and reload status. If still above
//! 10, return the resident result without touching output; otherwise write
//! status and return zero, even when refresh returned an error.
//! Deliberate deviations: volatile aligned word access preserves refresh
//! mutations; host tests inject refresh into the same algorithm. The
//! unported helper resolves the +0x904 metadata word and may update +0x908;
//! no protocol or class identity is assumed.

const STATUS_WORD: usize = 0x908 / 4;
type ResolveMetadata = unsafe extern "C" fn(*mut u8, *mut u32) -> u32;

#[inline(always)]
unsafe fn query_with_resolver(
    object: *mut u8, output: *mut i32, resolve: ResolveMetadata,
) -> u32 {
    let status = object.cast::<i32>().add(STATUS_WORD);
    if status.read_volatile() > 10 {
        let mut metadata = 0;
        let result = resolve(object, &mut metadata);
        if status.read_volatile() > 10 { return result; }
    }
    output.write(status.read_volatile());
    0
}

/// Requires a live, word-aligned firmware object through +0x90b and writable
/// output when status becomes <= 10. Resident metadata resolution may access
/// the rest of the object. An unresolved status leaves output untouched.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_object_status(object: *mut u8, output: *mut i32) -> u32 {
    let resolve: ResolveMetadata = core::mem::transmute(0x0816_38d4usize);
    query_with_resolver(object, output, resolve)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn forbidden(_object: *mut u8, _metadata: *mut u32) -> u32 {
        panic!("cached status must not resolve metadata");
    }
    unsafe extern "C" fn resolve(object: *mut u8, metadata: *mut u32) -> u32 {
        assert_eq!(metadata.read(), 0);
        let words = object.cast::<u32>();
        words.add(STATUS_WORD).write(words.read());
        metadata.write(0x13bf);
        words.add(2).write(words.add(2).read() + 1);
        words.add(1).read()
    }

    #[test]
    fn signed_cached_boundary_and_output_alias() {
        let mut object = [0u32; STATUS_WORD + 1];
        for value in [i32::MIN, -1, 0, 9, 10] {
            object[STATUS_WORD] = value as u32;
            let mut output = 123;
            assert_eq!(unsafe { query_with_resolver(object.as_mut_ptr().cast(), &mut output, forbidden) }, 0);
            assert_eq!(output, value);
            let output = unsafe { object.as_mut_ptr().add(STATUS_WORD).cast() };
            assert_eq!(unsafe { query_with_resolver(object.as_mut_ptr().cast(), output, forbidden) }, 0);
            assert_eq!(object[STATUS_WORD], value as u32);
        }
    }

    #[test]
    fn refresh_reload_error_precedence_and_output_preservation() {
        for initial in [11, i32::MAX] {
            for updated in [i32::MIN, -1, 0, 10, 11, i32::MAX] {
                for result in [0, 9, u32::MAX] {
                    let mut object = [0u32; STATUS_WORD + 1];
                    object[0] = updated as u32;
                    object[1] = result;
                    object[STATUS_WORD] = initial as u32;
                    let mut output = 0x12345678;
                    let actual = unsafe { query_with_resolver(object.as_mut_ptr().cast(), &mut output, resolve) };
                    assert_eq!(object[2], 1);
                    assert_eq!(actual, if updated > 10 { result } else { 0 });
                    assert_eq!(output, if updated > 10 { 0x12345678 } else { updated });
                }
            }
        }
    }
}
