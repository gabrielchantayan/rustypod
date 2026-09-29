//! Unpack a tagged code-generator operand — retailOS `FUN_082c4e10` at
//! `0x082c4e10` (116 bytes).
//!
//! Raw `osos.dec` words establish the true extent `0x082c4e10..0x082c4e84`:
//! the final `bx lr` is at `0x082c4e80`, and the next independent function
//! begins with `push {r4-r8,lr}` at `0x082c4e84`. The body is a leaf with no
//! outbound `bl`; full-image A32 decoding finds two inbound plain `bl` call
//! sites (both in `FUN_082d6a90`) and no predicated inbound `bl` calls.
//!
//! The input is a two-word operand slot. Its first word identifies a wrapper
//! whose `+0x18` child is accepted only when child byte `+0x09` is one. A
//! child kind of two supplies the child `+0x14` and `+0x18` words and returns
//! two. Kind fifteen does the same only for a signed child `+0x18` in
//! `0..=255`, returning one. All other layouts leave the slot untouched and
//! return zero.
//!
//! Deliberate deviations: target pointers are represented as 32-bit words at
//! their firmware offsets rather than host pointer fields.

/// `cg_unpack_tagged_operand` — original: `FUN_082c4e10` @ `0x082c4e10`
/// (116 bytes; two inbound plain-`bl` call sites).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cg_unpack_tagged_operand")]
#[inline(never)]
pub unsafe extern "C" fn cg_unpack_tagged_operand(operand_slot: *mut u32) -> i32 {
    let wrapper = *operand_slot as usize as *const u8;
    let child = *(wrapper.add(0x18) as *const u32) as usize as *const u8;
    if child.is_null() || *child.add(9) != 1 {
        return 0;
    }

    match *child.add(8) {
        2 => {
            *operand_slot = *(child.add(0x14) as *const u32);
            *operand_slot.add(1) = *(child.add(0x18) as *const u32);
            2
        }
        15 => {
            let value = *(child.add(0x18) as *const i32);
            if !(0..=255).contains(&value) {
                return 0;
            }
            *operand_slot = *(child.add(0x14) as *const u32);
            *operand_slot.add(1) = value as u32;
            1
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const FIXTURE_LEN: usize = 0x400;
    const SLOT: usize = 0x00;
    const WRAPPER: usize = 0x40;
    const CHILD: usize = 0x100;

    unsafe fn write_word(base: *mut u8, offset: usize, value: u32) {
        (base.add(offset) as *mut u32).write(value);
    }

    unsafe fn invoke(base: *mut u8, kind: u8, ready: u8, value: i32) -> i32 {
        base.write_bytes(0, FIXTURE_LEN);
        write_word(base, SLOT, base.add(WRAPPER) as usize as u32);
        write_word(base, SLOT + 4, 0xdead_beef);
        write_word(base, WRAPPER + 0x18, base.add(CHILD) as usize as u32);
        *base.add(CHILD + 8) = kind;
        *base.add(CHILD + 9) = ready;
        write_word(base, CHILD + 0x14, 0x1234_5678);
        write_word(base, CHILD + 0x18, value as u32);
        cg_unpack_tagged_operand(base.add(SLOT) as *mut u32)
    }

    #[test]
    fn unpacks_kind_two_and_bounded_kind_fifteen_only() {
        let Some(base) = try_map_u32_slab(hints::CG_UNPACK_TAGGED_OPERAND, FIXTURE_LEN) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };

        unsafe {
            assert_eq!(invoke(base, 2, 1, -1), 2);
            assert_eq!((base.add(SLOT) as *const u32).read(), 0x1234_5678);
            assert_eq!((base.add(SLOT + 4) as *const u32).read(), u32::MAX);

            assert_eq!(invoke(base, 15, 1, 0), 1);
            assert_eq!((base.add(SLOT + 4) as *const u32).read(), 0);
            assert_eq!(invoke(base, 15, 1, 255), 1);
            assert_eq!((base.add(SLOT + 4) as *const u32).read(), 255);

            assert_eq!(invoke(base, 15, 1, -1), 0);
            assert_eq!((base.add(SLOT) as *const u32).read(), base.add(WRAPPER) as usize as u32);
            assert_eq!(invoke(base, 15, 1, 256), 0);
            assert_eq!(invoke(base, 2, 0, 7), 0);
            assert_eq!(invoke(base, 6, 1, 7), 0);
        }
    }
}
