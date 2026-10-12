//! Looks up a descriptor and attaches it to its owner.

use core::ptr;

/// Retail lookup ABI at 0x0806a5cc. The key and lookup option remain opaque.
pub type DescriptorLookup = unsafe extern "C" fn(u32, *const u8, u32) -> *mut u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_descriptor_lookup(kind: u32, key: *const u8, option: u32) -> *mut u32 {
    let lookup: DescriptorLookup = core::mem::transmute(0x0806_a5ccusize);
    lookup(kind, key, option)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_descriptor_lookup(_kind: u32, _key: *const u8, _option: u32) -> *mut u32 {
    panic!("retail descriptor lookup requires a device or an installed host boundary")
}

/// Unported lookup boundary; defaults to the verified retail address on device.
pub static mut DESCRIPTOR_LOOKUP: DescriptorLookup = retail_descriptor_lookup;

/// Original: FUN_0803bf08 at load address 0x0803bf08, 64 bytes, ending
/// immediately before the independent PUSH at 0x0803bf48.
/// Two incoming plain BLs (0x0803becc, 0x0803bfac), no predicated BLs.
/// Two outgoing plain BLs (0x0803bf20 to 0x0806a5cc, 0x0803bf38 to
/// 0x0803c034), no predicated BLs.
///
/// Read the owner's descriptor type at +0x0c and look up a descriptor with
/// the supplied key and option. Return NULL on lookup failure; otherwise
/// attach the descriptor using the supplied context and return the link.
/// Deliberate deviations: attachment uses the existing Rust port; the
/// unported lookup uses a volatile replaceable boundary. No extra guards.
/// The original leaves r3 caller-clobbered after lookup; the verified
/// attachment port takes only the three meaningful arguments.
///
/// # Safety
/// `owner` must be aligned and readable through word 3, and all pointers
/// must satisfy the installed lookup and attachment contracts. The boundary
/// must not be changed concurrently with a call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn lookup_and_attach_descriptor(
    owner: *mut u32,
    key: *const u8,
    context: *mut u8,
    option: u32,
) -> *mut u32 {
    let lookup = ptr::read_volatile(ptr::addr_of!(DESCRIPTOR_LOOKUP));
    lookup_and_attach_with(owner, key, context, option, lookup)
}

#[inline(always)]
unsafe fn lookup_and_attach_with(
    owner: *mut u32,
    key: *const u8,
    context: *mut u8,
    option: u32,
    lookup: DescriptorLookup,
) -> *mut u32 {
    let descriptor = lookup(owner.add(3).read(), key, option);
    if descriptor.is_null() {
        ptr::null_mut()
    } else {
        super::descriptor_attachment::attach_matching_descriptor(owner, descriptor, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn missing(_kind: u32, _key: *const u8, _option: u32) -> *mut u32 {
        ptr::null_mut()
    }

    unsafe extern "C" fn found(_kind: u32, key: *const u8, _option: u32) -> *mut u32 {
        key as *mut u32
    }

    #[test]
    fn missing_descriptor_does_not_enter_attachment() {
        // Only the four words lookup needs exist; attachment would read past them.
        let mut owner = [0xdead_beef; 4];
        let before = owner;
        let result = unsafe {
            lookup_and_attach_with(owner.as_mut_ptr(), ptr::null(), ptr::null_mut(), u32::MAX, missing)
        };
        assert!(result.is_null());
        assert_eq!(owner, before);
    }

    #[test]
    fn found_wrong_type_is_rejected_without_mutation() {
        let mut owner = [0xa5a5_a5a5; 107];
        let descriptor = [0x5a5a_5a5a; 48];
        let before_owner = owner;
        let before_descriptor = descriptor;
        let result = unsafe {
            lookup_and_attach_with(owner.as_mut_ptr(), descriptor.as_ptr().cast(), ptr::null_mut(), 0, found)
        };
        assert!(result.is_null());
        assert_eq!(owner, before_owner);
        assert_eq!(descriptor, before_descriptor);
    }
}
