//! Optional UI-element link virtual dispatch.
//!
//! Original `FUN_0826ed80` at **0x0826ed80**, true size **24 bytes**:
//! six ARM words ending in `bx lr` at 0x0826ed94, before the separately
//! entered function at 0x0826ed98. Raw immediate-branch decoding finds two
//! inbound plain BL calls (0x0815c858 and 0x081dd344), zero predicated BL
//! calls. The body itself has no BL: it uses a predicated `bxne r1`.
//!
//! Load the optional link at element +0x34; if non-NULL, dispatch its vtable
//! slot +0x138 with the linked object as `this`. The method's identity is not
//! established, so the name describes only the verified dispatch operation.
//! Deliberate deviations: Rust expresses the tail branch as a final void call;
//! both raw callers discard its result. Host pointers and vtable words widen,
//! while a packed host element view retains the link's byte offset +0x34.

/// UI element prefix through its optional linked object.
#[repr(C)]
#[cfg_attr(not(target_os = "none"), repr(packed))]
pub struct OptionalLinkElement {
    pub unknown_00_30: [u32; 13],
    pub link: *mut LinkedDispatchObject,
}

/// Only the first word of the linked object is interpreted by this wrapper.
#[repr(C)]
pub struct LinkedDispatchObject {
    pub vtable: *const LinkedDispatchVtable,
}

/// Word-indexed vtable: slot 78 is byte offset +0x138 on the ARM target.
#[repr(C)]
pub struct LinkedDispatchVtable {
    pub unknown_00_134: [usize; 78],
    pub dispatch: unsafe extern "C" fn(*mut LinkedDispatchObject),
}

#[cfg(target_os = "none")]
const _: () = assert!(core::mem::offset_of!(OptionalLinkElement, link) == 0x34
    && core::mem::offset_of!(LinkedDispatchVtable, dispatch) == 0x138);

/// Dispatch the optional link's unresolved +0x138 virtual method.
///
/// # Safety
/// `element` must be readable through its link field. A non-NULL link must
/// have a readable vtable and a valid method with the declared `this` ABI.
/// The original does not guard the element, vtable, or method pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_dispatch_optional_link(element: *const OptionalLinkElement) {
    #[cfg(target_os = "none")]
    let link = core::ptr::addr_of!((*element).link).read();
    #[cfg(not(target_os = "none"))]
    let link = core::ptr::addr_of!((*element).link).read_unaligned();
    if !link.is_null() {
        let vtable = core::ptr::addr_of!((*link).vtable).read();
        ((*vtable).dispatch)(link);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct RecordingLink {
        object: LinkedDispatchObject,
        calls: u32,
        received_self: *mut LinkedDispatchObject,
    }

    unsafe extern "C" fn record_dispatch(link: *mut LinkedDispatchObject) {
        let record = link.cast::<RecordingLink>();
        (*record).calls += 1;
        (*record).received_self = link;
    }

    #[test]
    fn null_link_returns_without_dispatch_or_mutation() {
        let element = OptionalLinkElement { unknown_00_30: [0xdead_beef; 13], link: core::ptr::null_mut() };
        unsafe { ui_element_dispatch_optional_link(&element); }
        let prefix = element.unknown_00_30;
        assert_eq!(prefix, [0xdead_beef; 13]);
        assert!(unsafe { core::ptr::addr_of!(element.link).read_unaligned() }.is_null());
    }

    #[test]
    fn dispatches_selected_link_once_and_preserves_element() {
        let vtable = LinkedDispatchVtable { unknown_00_134: [0; 78], dispatch: record_dispatch };
        let mut record = RecordingLink {
            object: LinkedDispatchObject { vtable: &vtable },
            calls: 0,
            received_self: core::ptr::null_mut(),
        };
        let link = core::ptr::addr_of_mut!(record.object);
        let element = OptionalLinkElement { unknown_00_30: [0xa5a5_a5a5; 13], link };
        unsafe { ui_element_dispatch_optional_link(&element); }
        assert_eq!(record.calls, 1);
        assert_eq!(record.received_self, link);
        let prefix = element.unknown_00_30;
        assert_eq!(prefix, [0xa5a5_a5a5; 13]);
        assert_eq!(unsafe { core::ptr::addr_of!(element.link).read_unaligned() }, link);
    }
}
