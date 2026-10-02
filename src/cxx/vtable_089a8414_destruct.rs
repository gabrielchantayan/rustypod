//! `vtable_089a8414_destruct` — retailOS `FUN_0827c748` @ `0x0827c748`.
//!
//! Raw A32 body: 28 bytes, 0x0827c748..0x0827c764; a four-byte
//! literal pool follows, before the real function boundary at 0x0827c768.
//! Verified calls: one plain BL, zero predicated BL, and one tail B.
//! Two plain BL sites (zero predicated) call this wrapper in the firmware.
//! Install vtable 0x089a8414, destroy the member at +0xa8 via 0x0827ca8c,
//! rebase its returned pointer by -0xa8, then tail-destroy the base via
//! 0x0827c334. These opaque destructor identities follow their raw vtable
//! resets and constructor counterparts, not Ghidra's expanded call graph.
//!
//! No target behavior deviations. Host builds expose replaceable destructor
//! seams because the retail callees are unported; unset seams fail explicitly.

pub type OpaqueDestruct = unsafe extern "C" fn(*mut u32) -> *mut u32;
const MEMBER_WORDS: usize = 0x2a;
const VTABLE: u32 = 0x089a_8414;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable(_: *mut u32) -> *mut u32 {
    panic!("retail destructor seam is not installed")
}
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_089A8414_MEMBER_DESTRUCT: OpaqueDestruct = unavailable;
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_089A8414_BASE_DESTRUCT: OpaqueDestruct = unavailable;

#[inline(always)]
unsafe fn destruct_with(object: *mut u32, member: OpaqueDestruct, base: OpaqueDestruct) -> *mut u32 {
    object.write(VTABLE);
    base(member(object.add(MEMBER_WORDS)).sub(MEMBER_WORDS))
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_089a8414_destruct(object: *mut u32) -> *mut u32 {
    #[cfg(target_os = "none")]
    let (member, base) = (
        core::mem::transmute::<usize, OpaqueDestruct>(0x0827_ca8c),
        core::mem::transmute::<usize, OpaqueDestruct>(0x0827_c334),
    );
    #[cfg(not(target_os = "none"))]
    let (member, base) = (
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089A8414_MEMBER_DESTRUCT)),
        core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089A8414_BASE_DESTRUCT)),
    );
    destruct_with(object, member, base)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Destruction model with visible teardown effects, not argument echoes.
    unsafe extern "C" fn member_destroy(member: *mut u32) -> *mut u32 {
        assert_eq!(member.sub(MEMBER_WORDS).read(), VTABLE);
        member.write(0x089a_84a0);
        member.add(1).write(0); // release modeled owned payload
        member
    }
    unsafe extern "C" fn base_destroy(base: *mut u32) -> *mut u32 {
        assert_eq!(base.add(MEMBER_WORDS).read(), 0x089a_84a0);
        assert_eq!(base.add(MEMBER_WORDS + 1).read(), 0);
        base.write(0x089a_82d8);
        base.add(3).write(0x089a_83e0);
        base
    }
    #[test]
    fn tears_down_member_before_base_without_touching_neighbors() {
        for padding in 0..4 {
            let mut words = [0xdead_beef; 96];
            let object = unsafe { words.as_mut_ptr().add(padding) };
            unsafe { assert_eq!(destruct_with(object, member_destroy, base_destroy), object); }
            let mut expected = [0xdead_beef; 96];
            expected[padding] = 0x089a_82d8;
            expected[padding + 3] = 0x089a_83e0;
            expected[padding + MEMBER_WORDS] = 0x089a_84a0;
            expected[padding + MEMBER_WORDS + 1] = 0;
            assert_eq!(words, expected);
        }
    }
    unsafe extern "C" fn relocated_member_destroy(member: *mut u32) -> *mut u32 {
        member_destroy(member);
        member.add(48).write(0x089a_84a0);
        member.add(49).write(0);
        member.add(48)
    }
    #[test]
    fn returned_member_controls_base_teardown_and_return_value() {
        let mut words = [0xdead_beef; 144];
        let object = words.as_mut_ptr();
        unsafe {
            assert_eq!(destruct_with(object, relocated_member_destroy, base_destroy), object.add(48));
        }
        assert_eq!(words[0], VTABLE); // original base was not destroyed
        assert_eq!(words[48], 0x089a_82d8);
        assert_eq!(words[51], 0x089a_83e0);
        assert_eq!(words[47], 0xdead_beef);
        assert_eq!(words[52], 0xdead_beef);
    }
}
