//! `owner_link_base_construct` — `FUN_08168764` @ `0x08168764`.
//!
//! True extent: 20 bytes (16 bytes of A32 instructions and the vtable literal
//! at 0x08168774); the next real function starts at 0x08168778 and has an
//! independent inbound branch at 0x081e2394. Verified inbound calls: two plain
//! BL (0x0813aff4, 0x081e236c), zero predicated BL. Outbound calls: zero.
//! Stores the owner word at +4, installs base vtable 0x089a746c at +0, and
//! returns the unchanged receiver. Both callers replace the base vtable with
//! a derived one before registering the receiver through 0x0816874c.
//! Deliberate deviations: the concrete class identity remains unknown; names
//! describe only the verified owner link and base initialization. Target
//! addresses remain u32 words even on hosts. No behavioral deviations.

pub const OWNER_LINK_BASE_VTABLE: u32 = 0x089a_746c;

/// Two-word target-layout prefix; derived objects may have trailing fields.
#[repr(C)]
pub struct OwnerLinkBase {
    pub vtable: u32,
    pub owner: u32,
}

/// Initialize the base prefix and preserve the constructor's r0 result.
///
/// # Safety
/// `receiver` must point to at least two aligned, writable u32 words.
/// The owner is stored without validation or dereferencing, including zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_link_base_construct(
    receiver: *mut OwnerLinkBase, owner: u32,
) -> *mut OwnerLinkBase {
    unsafe {
        (*receiver).owner = owner;
        (*receiver).vtable = OWNER_LINK_BASE_VTABLE;
    }
    receiver
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_only_the_prefix_for_all_owner_word_boundaries() {
        #[repr(C)]
        struct Derived {
            before: u32,
            base: OwnerLinkBase,
            trailing: [u32; 3],
        }
        for owner in [0, 1, 0x08a7_62a0, 0x8000_0000, u32::MAX] {
            let mut object = Derived {
                before: 0x1357_2468,
                base: OwnerLinkBase { vtable: u32::MAX, owner: !owner },
                trailing: [0xdead_beef, 0, u32::MAX],
            };
            let receiver = &mut object.base as *mut OwnerLinkBase;
            let result = unsafe { owner_link_base_construct(receiver, owner) };
            assert_eq!(result, receiver);
            assert_eq!([object.base.vtable, object.base.owner],
                [OWNER_LINK_BASE_VTABLE, owner]);
            assert_eq!(object.before, 0x1357_2468);
            assert_eq!(object.trailing, [0xdead_beef, 0, u32::MAX]);
        }
    }
}
