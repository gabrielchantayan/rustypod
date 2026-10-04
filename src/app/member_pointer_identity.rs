//! `member_pointer_identity` — original `FUN_0820a004` @ `0x0820a004`.
//!
//! True extent: 4 bytes, [0x0820a004, 0x0820a008). Raw word `e12fff1e`
//! is `bx lr`; the next real function starts with `e59f0040` (literal load).
//! Independent whole-image aligned A32 decoding verifies two inbound plain
//! BLs, at 0x081e5cf8 and 0x08206c54, zero predicated BLs, and zero outbound
//! calls. No aligned data words reference the entry.
//!
//! Algorithm: return the incoming member pointer in r0 without accessing it.
//! Callers pass object+0x13c6 and object+0x61a, respectively, then subtract
//! the same offset from the returned pointer to recover the containing object.
//! The bytes establish neither a constructor nor a destructor identity.
//! Deliberate deviations: LLVM adds frame bookkeeping. A dedicated text
//! section prevents identical-code folding so this entry stays independently
//! visible to the hook and codegen tooling.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.member_pointer_identity")]
pub extern "C" fn member_pointer_identity(member: *mut u8) -> *mut u8 {
    member
}

#[cfg(test)]
mod tests {
    use super::member_pointer_identity;

    #[test]
    fn preserves_null_and_non_dereferenceable_pointer_bits() {
        for address in [0, 1, 3, 0x8000_0000, u32::MAX as usize, usize::MAX] {
            let member = address as *mut u8;
            assert_eq!(member_pointer_identity(member), member);
        }
    }

    #[test]
    fn callers_recover_container_without_changing_member_storage() {
        let mut storage = [0xa5u8; 0x13c8];
        let base = storage.as_mut_ptr();
        for offset in [0x13c6, 0x61a] {
            let member = unsafe { base.add(offset) };
            let returned = member_pointer_identity(member);
            assert_eq!(unsafe { returned.sub(offset) }, base);
            assert_eq!(storage, [0xa5; 0x13c8]);
        }
    }
}
