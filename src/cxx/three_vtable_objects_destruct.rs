//! Three-subobject destructor — retailOS `FUN_08159c08` @ `0x08159c08`.
//!
//! True size: 32 bytes, ending at the independently entered 0x08159c28.
//! Verified outgoing calls: two plain BL, zero predicated BL, one tail B;
//! all three target 0x0827c748. Two incoming plain BL, zero predicated BL.
//! Destroy the last subobject at +0x2b8, subtract 0x15c from its returned
//! pointer, destroy the middle, then subtract 0x15c from that returned
//! pointer and tail-destroy the first. Return the last destructor's result.
//! Ghidra's 56-byte extent and expanded transitive calls are incorrect.
//! No deliberate behavioral deviations; reuse the existing Rust destructor.
//!
//! # Safety
//! Each derived pointer (including callee-return rebases) must reference a
//! live writable subobject accepted by `vtable_089a8414_destruct`. Null is
//! not accepted, and the caller remains responsible for storage deallocation.

use super::vtable_089a8414_destruct::vtable_089a8414_destruct;

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn three_vtable_objects_destruct(object: *mut u32) -> *mut u32 {
    let returned = vtable_089a8414_destruct(object.add(0x2b8 / 4));
    let returned = vtable_089a8414_destruct(returned.sub(0x15c / 4));
    vtable_089a8414_destruct(returned.sub(0x15c / 4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::vtable_089a8414_destruct::{
        VTABLE_089A8414_MEMBER_DESTRUCT, VTABLE_089A8414_BASE_DESTRUCT,
    };

    unsafe extern "C" fn member_destroy(member: *mut u32) -> *mut u32 {
        let object = member.sub(0xa8 / 4);
        assert_eq!(object.read(), 0x089a_8414);
        // For the first two destructions, the next subobject is still live.
        if object.add(1).read() != 0 {
            assert_eq!(object.sub(0x15c / 4).read(), 0x1234_5678);
        }
        member.write(0x089a_84a0);
        member.add(1).write(0);
        member
    }
    unsafe extern "C" fn base_destroy(object: *mut u32) -> *mut u32 {
        assert_eq!(object.add(0xa8 / 4).read(), 0x089a_84a0);
        assert_eq!(object.add(0xac / 4).read(), 0);
        object.write(0x089a_82d8);
        // Model a relocated destructor return using a per-object word.
        object.add(object.add(2).read() as usize)
    }

    #[test]
    fn exported_destructor_preserves_guards_and_follows_returned_pointers() {
        unsafe {
            let old_member = VTABLE_089A8414_MEMBER_DESTRUCT;
            let old_base = VTABLE_089A8414_BASE_DESTRUCT;
            VTABLE_089A8414_MEMBER_DESTRUCT = member_destroy;
            VTABLE_089A8414_BASE_DESTRUCT = base_destroy;
            for relocation in [0, 4] {
                for padding in 1..5 {
                    let mut words = [0xdead_beef; 320];
                    let mut expected = words;
                    let object = words.as_mut_ptr().add(padding);
                    let positions = [174, 87 + relocation, 2 * relocation];
                    for (index, &offset) in positions.iter().enumerate() {
                        object.add(offset).write(0x1234_5678);
                        object.add(offset + 1).write(if index == 2 { 0 } else { 1 });
                        object.add(offset + 2).write(relocation as u32);
                        expected[padding + offset] = 0x089a_82d8;
                        expected[padding + offset + 1] = if index == 2 { 0 } else { 1 };
                        expected[padding + offset + 2] = relocation as u32;
                        expected[padding + offset + 42] = 0x089a_84a0;
                        expected[padding + offset + 43] = 0;
                    }
                    // The next live object is rebase-dependent when relocation != 0.
                    // Keep the raw -0x15c order sentinel live as well.
                    for &offset in &positions[..2] {
                        object.add(offset - 87).write(0x1234_5678);
                        if !positions.contains(&(offset - 87)) {
                            expected[padding + offset - 87] = 0x1234_5678;
                        }
                    }
                    assert_eq!(three_vtable_objects_destruct(object), object.add(3 * relocation));
                    assert_eq!(words, expected);
                }
            }
            VTABLE_089A8414_MEMBER_DESTRUCT = old_member;
            VTABLE_089A8414_BASE_DESTRUCT = old_base;
        }
    }
}
