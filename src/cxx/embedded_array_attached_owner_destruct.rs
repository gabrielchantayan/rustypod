//! `embedded_array_attached_owner_destruct` — `FUN_081486a8` @ 0x081486a8.
//!
//! True extent: 52 bytes, comprising 48 code bytes and vtable literal
//! 0x089865b4 at 0x081486d8; next real function starts at 0x081486dc.
//! Whole-image aligned A32 decoding finds two inbound plain BLs at
//! 0x080c6d0c and 0x081dcf64, zero predicated BLs. The body has one plain
//! BL to observable_array_destruct, zero predicated BLs, and one BLXNE.
//!
//! Install the owner vtable, destroy its embedded observable array at +0x40,
//! then release the optional attached object at +0x3c via virtual slot +4.
//! Return the array destructor's receiver minus 0x40; do not clear the attached
//! word. Deliberate deviations: behavior-based class name, ordinary Rust
//! conditional dispatch in place of predication, and a host-test closure for
//! target-width virtual dispatch. The real array destructor is reused.

use super::observable_array::{observable_array_destruct, ObservableArray};

#[repr(C)]
pub struct EmbeddedArrayAttachedOwner {
    pub vtable: u32,
    pub words_04_to_38: [u32; 14],
    pub attached: u32,
    pub array: ObservableArray,
}

const _: [u8; 0x40] = [0; core::mem::offset_of!(EmbeddedArrayAttachedOwner, array)];
const _: [u8; 0x50] = [0; core::mem::size_of::<EmbeddedArrayAttachedOwner>()];

unsafe fn destruct_with(
    this: *mut EmbeddedArrayAttachedOwner,
    release: impl FnOnce(u32),
) -> *mut EmbeddedArrayAttachedOwner {
    core::ptr::addr_of_mut!((*this).vtable).write_volatile(0x0898_65b4);
    let array = observable_array_destruct(core::ptr::addr_of_mut!((*this).array));
    let owner = array.cast::<u8>().sub(0x40).cast::<EmbeddedArrayAttachedOwner>();
    let attached = core::ptr::addr_of!((*owner).attached).read();
    if attached != 0 {
        release(attached);
    }
    owner
}

/// # Safety
/// `this` must be a writable live owner with an array valid for destruction.
/// A nonzero attached word must address a live target-width object whose
/// vtable slot +4 is a callable `extern "C" fn(*mut u32)` release operation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn embedded_array_attached_owner_destruct(
    this: *mut EmbeddedArrayAttachedOwner,
) -> *mut EmbeddedArrayAttachedOwner {
    destruct_with(this, |attached| {
        let object = attached as usize as *mut u32;
        let vtable = object.read() as usize as *const u32;
        let release: unsafe extern "C" fn(*mut u32) =
            core::mem::transmute(vtable.add(1).read() as usize);
        release(object);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::observable_array::{FrameworkObject, OBSERVABLE_ARRAY_VTABLE};

    fn owner(length: u32, attached: u32) -> EmbeddedArrayAttachedOwner {
        EmbeddedArrayAttachedOwner {
            vtable: 0xdeadbeef,
            words_04_to_38: [0x5a5a5a5a; 14],
            attached,
            array: ObservableArray {
                base: FrameworkObject { vtable: 0xdeadbeef },
                len: length, storage: 0, observers: 0,
            },
        }
    }

    #[test]
    fn null_attachment_clears_array_and_preserves_owner_and_guards() {
        for length in [0, 1, u32::MAX] {
            let mut guarded = (0x12345678u32, owner(length, 0), 0x87654321u32);
            let this = &mut guarded.1 as *mut EmbeddedArrayAttachedOwner;
            unsafe { assert_eq!(embedded_array_attached_owner_destruct(this), this); }
            assert_eq!(guarded.0, 0x12345678);
            assert_eq!(guarded.2, 0x87654321);
            assert_eq!(guarded.1.vtable, 0x089865b4);
            assert_eq!(guarded.1.words_04_to_38, [0x5a5a5a5a; 14]);
            assert_eq!(guarded.1.attached, 0);
            assert_eq!(guarded.1.array.base.vtable, OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(guarded.1.array.len, 0);
            assert_eq!(guarded.1.array.storage, 0);
            assert_eq!(guarded.1.array.observers, 0);
        }
    }

    #[test]
    fn release_observes_completed_array_destruction_and_attachment_is_not_cleared() {
        let mut value = owner(u32::MAX, 0x12345678);
        let this = &mut value as *mut EmbeddedArrayAttachedOwner;
        let mut calls = 0;
        unsafe {
            assert_eq!(destruct_with(this, |attached| {
                calls += 1;
                assert_eq!(attached, 0x12345678);
                assert_eq!((*this).vtable, 0x089865b4);
                assert_eq!((*this).array.base.vtable, OBSERVABLE_ARRAY_VTABLE);
                assert_eq!((*this).array.len, 0);
                assert_eq!((*this).array.storage, 0);
                assert_eq!((*this).array.observers, 0);
            }), this);
        }
        assert_eq!(calls, 1);
        assert_eq!(value.attached, 0x12345678);
        assert_eq!(value.words_04_to_38, [0x5a5a5a5a; 14]);
    }
}
