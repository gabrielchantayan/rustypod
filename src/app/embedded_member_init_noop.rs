//! `embedded_member_init_noop` — original: `FUN_081a2d80` @ **0x081a2d80**.
//!
//! True size: 4 bytes, the sole raw A32 word `0xe12fff1e` (`bx lr`).
//! The next independently called function starts at 0x081a2d84 (also `bx lr`),
//! reached by BL at 0x080648c0. Whole-image aligned raw A32 decoding verifies
//! two incoming plain BLs (0x0806380c, 0x080be100), zero predicated BLs,
//! and zero outgoing calls. No aligned DATA pointer references were found.
//!
//! Algorithm: return the incoming member pointer unchanged, without accessing
//! memory. The callers initialize an embedded member at +0xb55 of the object
//! initialized by 0x080bdfd0, or +0xb59 of its enclosing object when migrating
//! versions below 0x35. Neither caller consumes r0 after the call. The member's
//! domain meaning is unknown; this is not identified as a destructor.
//! Deliberate deviations: none. Naked target assembly preserves the original
//! register-transparent single-word body, including r0 pass-through.

/// No-op initialization; NULL, dangling, and unaligned pointers are accepted.
#[cfg(target_os = "none")]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn embedded_member_init_noop(_member: *mut u8) -> *mut u8 {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn embedded_member_init_noop(member: *mut u8) -> *mut u8 {
    member
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_dangling_pointer_words() {
        for word in [0usize, 1, 0x0800_0b55, 0x089c_0b59, u32::MAX as usize, usize::MAX] {
            let member = word as *mut u8;
            assert_eq!(unsafe { embedded_member_init_noop(member) }, member);
        }
    }

    #[test]
    fn leaves_embedded_member_and_neighbors_unchanged() {
        let mut object = [0xa5u8; 0xb80];
        object[0xb55..0xb63].fill(0x3c);
        let before = object;
        for offset in [0xb55, 0xb59] {
            let member = unsafe { object.as_mut_ptr().add(offset) };
            assert_eq!(unsafe { embedded_member_init_noop(member) }, member);
            assert_eq!(object, before);
        }
    }
}
