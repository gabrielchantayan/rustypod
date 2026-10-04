//! Owned string-pair getter — FUN_08203250 @ 0x08203250.
//! True size: 32 bytes, ending at the independently entered constructor
//! 0x08203270. Raw-word scan: two inbound plain BLs (0x081dcc64,
//! 0x081dcc94), zero predicated BLs. Body: zero direct BLs, one BLX.
//! Invoke the owner's virtual slot +8, ignore its result, then reload and
//! return the owned string-pair address word at +20. The virtual method may
//! replace that word; there are no NULL guards. Its concrete identity is
//! deliberately unspecified. No fixed-address callee seam is introduced.
//! Deliberate deviation: host vtable pointers/slots widen natively; the four
//! base payload words and returned address remain u32, as in the constructor.

#[repr(C)]
pub struct StringPairOwnerVtable {
    pub reserved: [usize; 2],
    pub prepare: unsafe extern "C" fn(*mut StringPairOwner) -> u32,
}

#[repr(C)]
pub struct StringPairOwner {
    pub vtable: *const StringPairOwnerVtable,
    pub pairs: [u32; 4],
    pub strings: u32,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(StringPairOwnerVtable, prepare) == 8);
    assert!(core::mem::offset_of!(StringPairOwner, strings) == 20);
    assert!(core::mem::size_of::<StringPairOwner>() == 24);
};

/// Prepare an owner through virtual slot +8 and return its current string pair.
///
/// # Safety
/// `owner` must be aligned, readable and writable, with a valid vtable and
/// callable slot +8. The virtual method must leave the owner readable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn two_pair_string_pair_owner_get(owner: *mut StringPairOwner) -> u32 {
    let vtable = core::ptr::addr_of!((*owner).vtable).read();
    ((*vtable).prepare)(owner);
    core::ptr::addr_of!((*owner).strings).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn replace_strings(owner: *mut StringPairOwner) -> u32 {
        // A stateful virtual operation: each getter must dispatch, including
        // when the current address word is zero or wraps at the u32 boundary.
        let calls = core::ptr::addr_of_mut!((*owner).pairs[0]);
        calls.write(calls.read().wrapping_add(1));
        let strings = core::ptr::addr_of_mut!((*owner).strings);
        strings.write(strings.read().wrapping_add(1));
        !strings.read()
    }

    unsafe extern "C" fn preserve_strings(owner: *mut StringPairOwner) -> u32 {
        core::ptr::addr_of!((*owner).strings).read() ^ 0xdead_beef
    }

    #[test]
    fn reloads_after_dispatch_and_dispatches_on_every_read() {
        let vtable = StringPairOwnerVtable { reserved: [0; 2], prepare: replace_strings };
        for initial in [0, 0x1234_5678, u32::MAX] {
            let mut owner = StringPairOwner {
                vtable: &vtable, pairs: [0, 0x11, 0x22, 0x33], strings: initial,
            };
            for calls in 1..=3 {
                let result = unsafe { two_pair_string_pair_owner_get(&mut owner) };
                assert_eq!(result, initial.wrapping_add(calls));
                assert_eq!(owner.strings, result);
                assert_eq!(owner.pairs, [calls, 0x11, 0x22, 0x33]);
                assert_eq!(owner.vtable, &vtable as *const _);
            }
        }
    }

    #[test]
    fn ignores_virtual_return_and_preserves_unmodified_address_bits() {
        let vtable = StringPairOwnerVtable { reserved: [0; 2], prepare: preserve_strings };
        for strings in [0, 0x8000_0000, u32::MAX] {
            let mut owner = StringPairOwner {
                vtable: &vtable, pairs: [1, 2, 3, 4], strings,
            };
            assert_eq!(unsafe { two_pair_string_pair_owner_get(&mut owner) }, strings);
            assert_eq!(owner.pairs, [1, 2, 3, 4]);
            assert_eq!(owner.strings, strings);
        }
    }
}
