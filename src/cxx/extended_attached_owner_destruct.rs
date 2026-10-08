//! `extended_attached_owner_destruct` — `FUN_081363f8` @ 0x081363f8.
//!
//! True extent [0x081363f8,0x0813642c): 52 bytes, 48 executable bytes plus
//! vtable literal 0x08984b5c at 0x08136428. The next function starts with
//! push {r3,lr} at 0x0813642c. Raw aligned whole-image decoding finds two
//! inbound plain BLs (0x0808e57c, 0x0808e5d4), zero predicated BLs.
//! Body: zero plain/predicated BLs, one BLXNE through virtual slot +4,
//! and a tail B to embedded_array_attached_owner_destruct @ 0x081486a8.
//!
//! Install the derived vtable, release the optional object at +0x70, then
//! destroy the embedded-array owner base using the original receiver. Return
//! the base destructor's result. Neither attachment word is cleared here.
//! Deliberate deviations: behavior-based class name (concrete identity is
//! unknown), Rust conditional dispatch rather than ARM predication, and a
//! test closure for target-width virtual dispatch. The base is called directly.

use super::embedded_array_attached_owner_destruct::{
    embedded_array_attached_owner_destruct, EmbeddedArrayAttachedOwner,
};

#[repr(C)]
pub struct ExtendedAttachedOwner {
    pub base: EmbeddedArrayAttachedOwner,
    pub words_50_to_6c: [u32; 8],
    pub attachment: u32,
}

const _: [u8; 0x70] = [0; core::mem::offset_of!(ExtendedAttachedOwner, attachment)];

unsafe fn destruct_with(
    this: *mut ExtendedAttachedOwner, release: impl FnOnce(u32),
) -> *mut ExtendedAttachedOwner {
    core::ptr::addr_of_mut!((*this).base.vtable).write_volatile(0x0898_4b5c);
    let attachment = core::ptr::addr_of!((*this).attachment).read();
    if attachment != 0 { release(attachment); }
    embedded_array_attached_owner_destruct(core::ptr::addr_of_mut!((*this).base)).cast()
}

/// # Safety
/// `this` must be a writable live target-layout owner, with a base valid for
/// destruction. Nonzero attachment words must address live target-width
/// objects whose vtable slot +4 is an `extern "C" fn(*mut u32)` release.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn extended_attached_owner_destruct(
    this: *mut ExtendedAttachedOwner,
) -> *mut ExtendedAttachedOwner {
    destruct_with(this, |attachment| {
        let object = attachment as usize as *mut u32;
        let vtable = object.read() as usize as *const u32;
        let release: unsafe extern "C" fn(*mut u32) =
            core::mem::transmute(vtable.add(1).read() as usize);
        release(object);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::{FrameworkObject, ObservableArray, OBSERVABLE_ARRAY_VTABLE};

    fn owner(attachment: u32, length: u32) -> ExtendedAttachedOwner {
        ExtendedAttachedOwner {
            base: EmbeddedArrayAttachedOwner {
                vtable: 0xdeadbeef, words_04_to_38: [0x51515151; 14], attached: 0,
                array: ObservableArray {
                    base: FrameworkObject { vtable: 0xdeadbeef },
                    len: length, storage: 0, observers: 0,
                },
            },
            words_50_to_6c: [0x62626262; 8], attachment,
        }
    }

    #[test]
    fn null_attachment_runs_real_base_and_preserves_unrelated_words() {
        for length in [0, 1, u32::MAX] {
            let mut value = owner(0, length);
            let this = &mut value as *mut ExtendedAttachedOwner;
            unsafe { assert_eq!(extended_attached_owner_destruct(this), this); }
            assert_eq!(value.base.vtable, 0x089865b4);
            assert_eq!(value.base.array.base.vtable, OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(value.base.array.len, 0);
            assert_eq!(value.base.words_04_to_38, [0x51515151; 14]);
            assert_eq!(value.words_50_to_6c, [0x62626262; 8]);
            assert_eq!(value.attachment, 0);
        }
    }

    #[test]
    fn release_sees_derived_vtable_before_base_and_pointer_is_retained() {
        let mut value = owner(0xfedcba98, 7);
        let this = &mut value as *mut ExtendedAttachedOwner;
        let mut releases = 0;
        unsafe {
            assert_eq!(destruct_with(this, |attachment| {
                releases += 1;
                assert_eq!(attachment, 0xfedcba98);
                assert_eq!((*this).base.vtable, 0x08984b5c);
                assert_eq!((*this).base.array.len, 7);
                // The following base destruction must observe callback effects.
                (*this).base.words_04_to_38[0] = 0x12345678;
                (*this).base.array.len = u32::MAX;
            }), this);
        }
        assert_eq!(releases, 1);
        assert_eq!(value.base.vtable, 0x089865b4);
        assert_eq!(value.base.array.base.vtable, OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(value.base.array.len, 0);
        assert_eq!(value.base.words_04_to_38[0], 0x12345678);
        assert_eq!(value.attachment, 0xfedcba98);
        assert_eq!(value.words_50_to_6c, [0x62626262; 8]);
    }
}
