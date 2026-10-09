//! Attached string/query owner constructor, FUN_08102db8 @ 0x08102db8.
//! True extent [0x08102db8, 0x08102dfc): 68 bytes (64 code + 4 literal).
//! Two incoming plain BL sites, zero predicated; three outgoing plain BLs,
//! zero predicated. Saves the owner word and low flag byte, installs
//! 0x089806bc, default-constructs the string, allocates 72 bytes, constructs
//! a query with id/mode zero, stores its return, and returns this.
//! Deviations: existing Rust string/heap ports and query constructor seam;
//! reuse the destructor's host-widened repr(C) owner representation. Padding
//! stays untouched and no allocation-failure guard is added.

use crate::cxx::attached_string_owner_destroy::AttachedStringOwner;
use crate::cxx::string_object::string_default_construct;

/// # Safety
/// `this` must be aligned writable owner storage. Firmware heap and query
/// backend must be initialized; hosts must install the existing query seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn query_owner_construct(
    this: *mut AttachedStringOwner, owner: u32, flag: u32,
) -> *mut AttachedStringOwner {
    construct(this, owner, flag, || {
        let storage = crate::heap::veneers::operator_new(0x48);
        crate::fp::fp_misc::query_object_construct(storage, 0, 0)
    })
}

unsafe fn construct(
    this: *mut AttachedStringOwner, owner: u32, flag: u32,
    create_query: impl FnOnce() -> *mut u8,
) -> *mut AttachedStringOwner {
    core::ptr::addr_of_mut!((*this).opaque_words[0]).write(owner);
    core::ptr::addr_of_mut!((*this).vtable).write(0x0898_06bc);
    core::ptr::addr_of_mut!((*this).opaque_words[1]).cast::<u8>().write(flag as u8);
    string_default_construct(core::ptr::addr_of_mut!((*this).string));
    core::ptr::addr_of_mut!((*this).attachment).write(create_query().cast());
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    #[test]
    fn preserves_padding_truncates_flag_and_initializes_empty_string() {
        for pattern in [0u8, 0x5a, 0xff] {
            for flag in [0u32, 1, 0x100, 0x1234_5678, u32::MAX] {
                let mut storage = core::mem::MaybeUninit::<AttachedStringOwner>::uninit();
                unsafe {
                    storage.as_mut_ptr().cast::<u8>().write_bytes(
                        pattern, core::mem::size_of::<AttachedStringOwner>());
                    let this = storage.as_mut_ptr();
                    let returned = construct(this, u32::MAX, flag, || {
                        assert_eq!((*this).opaque_words[0], u32::MAX);
                        assert_eq!((*this).vtable, 0x0898_06bc);
                        assert!((*this).string.payload.is_null());
                        core::ptr::null_mut()
                    });
                    assert_eq!(returned, this);
                    let bytes = core::ptr::addr_of!((*this).opaque_words[1]).cast::<u8>();
                    assert_eq!(bytes.read(), flag as u8);
                    assert_eq!(core::slice::from_raw_parts(bytes.add(1), 3), &[pattern; 3]);
                    assert!((*this).attachment.is_null());
                    assert_eq!((*this).string.vtable, &STRING_OBJECT_VTABLE as *const _);
                    assert!((*this).string.payload.is_null());
                }
            }
        }
    }
}
