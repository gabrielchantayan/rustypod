//! FreeType's internal service-descriptor lookup.
//!
//! - `ft_service_list_lookup` — original: `FUN_082cfdc0` @ `0x082cfdc0`
//!   (76 bytes; source: `ipod-decomp/decomp/c/031/082cfdc0_FUN_082cfdc0.c`).
//!
//! Algorithm: reject a NULL descriptor table or service name.  Otherwise,
//! linearly inspect 2-word `FT_ServiceDescRec` records until the NULL
//! `service_id` sentinel.  Each identifier is compared with retailOS's
//! unsigned-byte `strcmp`; on equality return the record's service pointer,
//! and return NULL when no descriptor matches.  This is FreeType's internal
//! `ft_service_list_lookup` from `src/base/ftobjs.c`.
pub mod metadata;

use crate::libc::strcmp::strcmp;

/// A FreeType `FT_ServiceDescRec` entry.
///
/// The retail ABI lays this out as two words: `service_id` at offset 0 and
/// `service_data` at offset 4.  A table terminates when `service_id` is NULL.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FtServiceDesc {
    pub service_id: *const u8,
    pub service_data: *mut u8,
}

/// ft_service_list_lookup — original: `FUN_082cfdc0` @ `0x082cfdc0`
/// (76 bytes).
///
/// Search the NULL-terminated `service_descriptors` table for `service_id`.
/// Returns that descriptor's opaque service pointer, or NULL if either input
/// is NULL, the table is empty, or no identifier compares equal.
///
/// Register usage: r0 = `service_descriptors`; r1 = `service_id`; r0 =
/// returned service pointer.  On ARM, [`FtServiceDesc`] has the recovered
/// eight-byte, two-word record stride.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_service_list_lookup(
    mut service_descriptors: *const FtServiceDesc,
    service_id: *const u8,
) -> *mut u8 {
    if service_descriptors.is_null() || service_id.is_null() {
        return core::ptr::null_mut();
    }

    loop {
        let descriptor = service_descriptors.read_volatile();
        if descriptor.service_id.is_null() {
            return core::ptr::null_mut();
        }
        if strcmp(descriptor.service_id, service_id) == 0 {
            return descriptor.service_data;
        }
        service_descriptors = service_descriptors.add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn rejects_null_table_or_service_name() {
        let empty = [FtServiceDesc {
            service_id: core::ptr::null(),
            service_data: 1usize as *mut u8,
        }];
        unsafe {
            assert!(ft_service_list_lookup(core::ptr::null(), b"glyph\0".as_ptr()).is_null());
            assert!(ft_service_list_lookup(empty.as_ptr(), core::ptr::null()).is_null());
        }
    }

    #[test]
    fn returns_the_matching_second_record_value() {
        let mut first_value = [0u8; 1];
        let mut matched_value = [0u8; 1];
        let descriptors = [
            FtServiceDesc {
                service_id: b"kerning\0".as_ptr(),
                service_data: first_value.as_mut_ptr(),
            },
            FtServiceDesc {
                service_id: b"glyph-dictionary\0".as_ptr(),
                service_data: matched_value.as_mut_ptr(),
            },
            FtServiceDesc {
                service_id: core::ptr::null(),
                service_data: core::ptr::null_mut(),
            },
        ];

        unsafe {
            assert_eq!(
                ft_service_list_lookup(descriptors.as_ptr(), b"glyph-dictionary\0".as_ptr()),
                matched_value.as_mut_ptr(),
                "the two-word stride reaches the later descriptor"
            );
        }
    }

    #[test]
    fn returns_null_for_a_missing_or_case_mismatched_name() {
        let mut value = [0u8; 1];
        let descriptors = [
            FtServiceDesc {
                service_id: b"glyph\0".as_ptr(),
                service_data: value.as_mut_ptr(),
            },
            FtServiceDesc {
                service_id: core::ptr::null(),
                service_data: core::ptr::null_mut(),
            },
        ];

        unsafe {
            assert!(ft_service_list_lookup(descriptors.as_ptr(), b"Glyph\0".as_ptr()).is_null());
            assert!(ft_service_list_lookup(descriptors.as_ptr(), b"metrics\0".as_ptr()).is_null());
        }
    }
}
