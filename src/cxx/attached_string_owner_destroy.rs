//! Teardown of an owner with a virtual attachment and an embedded string.
//!
//! Original: FUN_08102dfc @ 0x08102dfc. True extent [0x08102dfc,
//! 0x08102e34): 56 bytes, comprising 52 code bytes and the 0x089806bc
//! vtable literal. The next real function begins with push at 0x08102e34.
//! Verified raw calls: two inbound plain BLs (0x0828abcc, 0x0828adcc),
//! zero predicated inbound BLs; one outbound plain BL to string_object_destroy
//! @ 0x08277484, zero predicated direct BLs, and one BLXNE through slot +0x1c.
//! Installs the owner vtable, invokes the non-NULL attachment's slot +0x1c,
//! then destroys the string at +0x10 and returns the enclosing owner. Neither
//! the attachment pointer nor the two opaque words are cleared. The concrete
//! class and virtual callee identity remain unresolved.
//!
//! Deliberate representation deviation: repr(C) native pointers and native
//! vtable slots widen on hosts; target offsets remain +0x0c/+0x10 and +0x1c.
//! The owner vtable stays the verified retail address (not called here).

use super::string_object::{string_object_destroy, StringObject};

#[repr(C)]
pub struct AttachmentVtable {
    pub preceding_slots: [usize; 7],
    pub teardown: unsafe extern "C" fn(*mut VirtualAttachment),
}

#[repr(C)]
pub struct VirtualAttachment {
    pub vtable: *const AttachmentVtable,
}

#[repr(C)]
pub struct AttachedStringOwner {
    pub vtable: usize,
    pub opaque_words: [u32; 2],
    pub attachment: *mut VirtualAttachment,
    pub string: StringObject,
}

/// Non-deleting teardown; the owner and its string must be valid, and any
/// non-NULL attachment must expose a callable slot +0x1c.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn attached_string_owner_destroy(
    owner: *mut AttachedStringOwner,
) -> *mut AttachedStringOwner {
    (*owner).vtable = 0x089806bc;
    let attachment = (*owner).attachment;
    if !attachment.is_null() {
        ((*(*attachment).vtable).teardown)(attachment);
    }
    let string = core::ptr::addr_of_mut!((*owner).string);
    let destroyed = string_object_destroy(string);
    // Preserve the original return's derivation from the string destructor.
    (destroyed as *mut u8)
        .sub(core::mem::offset_of!(AttachedStringOwner, string))
        .cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::string_object::STRING_OBJECT_VTABLE;

    #[repr(C)]
    struct ObservingAttachment {
        base: VirtualAttachment,
        owner: *mut AttachedStringOwner,
        calls: u32,
    }

    unsafe extern "C" fn observe_teardown(attachment: *mut VirtualAttachment) {
        let observer = &mut *attachment.cast::<ObservingAttachment>();
        let owner = &mut *observer.owner;
        assert_eq!(owner.vtable, 0x089806bc);
        assert!(owner.string.vtable.is_null(), "string teardown must follow attachment");
        assert_eq!(owner.opaque_words, [0x12345678, 0xffffffff]);
        observer.calls += 1;
        // A virtual teardown may mutate the owner; the port must not overwrite it.
        owner.opaque_words[1] = 0x87654321;
    }

    static VTABLE: AttachmentVtable = AttachmentVtable {
        preceding_slots: [0; 7],
        teardown: observe_teardown,
    };

    fn owner() -> AttachedStringOwner {
        AttachedStringOwner {
            vtable: 0,
            opaque_words: [0x12345678, 0xffffffff],
            attachment: core::ptr::null_mut(),
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
        }
    }

    #[test]
    fn null_attachment_still_destroys_string_and_preserves_header() {
        let mut owner = owner();
        let pointer = &mut owner as *mut _;
        assert_eq!(unsafe { attached_string_owner_destroy(pointer) }, pointer);
        assert_eq!(owner.vtable, 0x089806bc);
        assert_eq!(owner.opaque_words, [0x12345678, 0xffffffff]);
        assert!(owner.attachment.is_null());
        assert_eq!(owner.string.vtable, &STRING_OBJECT_VTABLE as *const _);
        assert!(owner.string.payload.is_null());
    }

    #[test]
    fn attachment_runs_before_string_teardown_and_is_not_cleared() {
        let mut owner = owner();
        let mut attachment = ObservingAttachment {
            base: VirtualAttachment { vtable: &VTABLE },
            owner: &mut owner,
            calls: 0,
        };
        owner.attachment = &mut attachment.base;
        let pointer = &mut owner as *mut _;
        assert_eq!(unsafe { attached_string_owner_destroy(pointer) }, pointer);
        assert_eq!(attachment.calls, 1);
        assert_eq!(owner.attachment, &mut attachment.base as *mut _);
        assert_eq!(owner.opaque_words, [0x12345678, 0x87654321]);
        assert_eq!(owner.string.vtable, &STRING_OBJECT_VTABLE as *const _);
        assert!(owner.string.payload.is_null());
    }
}
