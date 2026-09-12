//! Deferred Parse Vdbe release.
//!
//! `parse_release_deferred_vdbe` is retailOS `FUN_083960e8` at
//! `0x083960e8` (72 bytes; `0x083960e8..0x08396130`). The following distinct
//! `push {r4-r11,lr}` at `0x08396130` establishes the end; there is no literal
//! pool. Decoding every ARM B/BL word in `osos.dec` finds 8 direct call sites,
//! all unconditional plain `bl` (at `0x082bdba8`, `0x08370908`, `0x08370b4c`,
//! `0x08370cc0`, `0x08371880`, `0x083718bc`, `0x08371a74`, and `0x08372b8c`).
//! There are no predicated caller branches.
//!
//! The raw function leaves the deferred child intact while either the byte at
//! target offset +0x30 or the word at +0x08 is nonzero. Otherwise, a nonzero
//! word at +0x0c means an owner child is pending: it releases the owner's
//! +0x48 child only when that target-width pointer is signed-positive, then
//! clears +0x0c and the byte at +0x10. It deliberately has no NULL guards;
//! callers supply a valid state and owner whenever +0x0c is nonzero.
//!
//! Deliberate deviation: host fixtures scale target pointer-word slots to the
//! host pointer width so their fields do not overlap. This preserves every
//! target offset on ARM and the target-width signed pointer test.

const TARGET_WORD: usize = 4;
const HOST_WORD: usize = core::mem::size_of::<*mut u8>();

const OWNER: usize = 0;
const RELEASE_BLOCKED: usize = 0x30;
const RETAINING_GUARD: usize = 0x08;
const DEFERRED_CHILD: usize = 0x0c;
const DEFERRED_FLAG: usize = 0x10;
const OWNER_CHILD: usize = 0x48;

#[inline(always)]
const fn pointer_offset(target_offset: usize) -> usize {
    target_offset / TARGET_WORD * HOST_WORD
}

#[inline(always)]
unsafe fn read_pointer(base: *mut u8, target_offset: usize) -> *mut u8 {
    (base.add(pointer_offset(target_offset)) as *const *mut u8).read()
}

#[inline(always)]
unsafe fn read_word(base: *mut u8, target_offset: usize) -> usize {
    (base.add(pointer_offset(target_offset)) as *const usize).read()
}

/// parse_release_deferred_vdbe — original: `FUN_083960e8` @ `0x083960e8`
/// (72 bytes; 8 direct `bl` call sites, all unconditional).
///
/// Releases an owner's retained child only after this state no longer blocks
/// release and records that the deferred child and flag are gone. `state` and,
/// on the release path, its owner at target offset +0x00 must be valid; the
/// original dereferences both without NULL guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_release_deferred_vdbe(state: *mut u8) {
    if state.add(pointer_offset(RELEASE_BLOCKED)).read() != 0
        || read_word(state, RETAINING_GUARD) != 0
        || read_word(state, DEFERRED_CHILD) == 0
    {
        return;
    }

    let owner = read_pointer(state, OWNER);
    let owner_child = read_pointer(owner, OWNER_CHILD);
    if (owner_child as usize as u32 as i32) >= 1 {
        crate::cxx::release::release_via_field_0x48(owner);
    }

    (state.add(pointer_offset(DEFERRED_CHILD)) as *mut usize).write(0);
    state.add(pointer_offset(DEFERRED_FLAG)).write(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const SLAB_LEN: usize = 0x1000;
    const OWNER_OFFSET: usize = 0x200;
    const CHILD_OFFSET: usize = 0x400;
    const CONTEXT_OFFSET: usize = 0x600;

    unsafe fn write_pointer(base: *mut u8, target_offset: usize, value: *mut u8) {
        (base.add(pointer_offset(target_offset)) as *mut *mut u8).write(value);
    }

    unsafe fn write_word(base: *mut u8, target_offset: usize, value: usize) {
        (base.add(pointer_offset(target_offset)) as *mut usize).write(value);
    }

    unsafe fn fixture(hint: usize) -> Option<(*mut u8, *mut u8, *mut u8, *mut u8)> {
        let slab = try_map_u32_slab(hint, SLAB_LEN)?;
        slab.write_bytes(0, SLAB_LEN);

        let owner = slab.add(OWNER_OFFSET);
        let child = slab.add(CHILD_OFFSET);
        let context = slab.add(CONTEXT_OFFSET);
        write_pointer(slab, OWNER, owner);
        write_pointer(owner, OWNER_CHILD, child);
        write_pointer(child, 0, context);
        (child.add(0x22) as *mut u16).write(1);
        (context.add(0x48) as *mut u32).write(1);
        Some((slab, owner, child, context))
    }

    #[test]
    fn release_path_drops_owner_child_and_clears_deferred_state() {
        let Some((state, _owner, child, context)) =
            (unsafe { fixture(hints::DEFERRED_OWNER_CHILD_RELEASE) })
        else {
            note_missing_u32_fixture("sqlite/parse_release_deferred_vdbe");
            return;
        };

        unsafe {
            write_word(state, DEFERRED_CHILD, 0xfeed_face);
            state.add(pointer_offset(DEFERRED_FLAG)).write(1);
            parse_release_deferred_vdbe(state);

            assert_eq!(read_word(state, DEFERRED_CHILD), 0);
            assert_eq!(state.add(pointer_offset(DEFERRED_FLAG)).read(), 0);
            assert_eq!((child.add(0x22) as *const u16).read(), 0);
            assert_eq!((context.add(0x48) as *const u32).read(), 0);
        }
    }

    #[test]
    fn release_blockers_preserve_deferred_state() {
        let Some((state, _owner, child, _context)) =
            (unsafe { fixture(hints::DEFERRED_OWNER_CHILD_RELEASE_BLOCKED) })
        else {
            note_missing_u32_fixture("sqlite/parse_release_deferred_vdbe");
            return;
        };

        unsafe {
            write_word(state, DEFERRED_CHILD, 0xfeed_face);
            state.add(pointer_offset(DEFERRED_FLAG)).write(1);
            state.add(pointer_offset(RELEASE_BLOCKED)).write(1);
            parse_release_deferred_vdbe(state);
            assert_eq!(read_word(state, DEFERRED_CHILD), 0xfeed_face);
            assert_eq!(state.add(pointer_offset(DEFERRED_FLAG)).read(), 1);
            assert_eq!((child.add(0x22) as *const u16).read(), 1);

            state.add(pointer_offset(RELEASE_BLOCKED)).write(0);
            write_word(state, RETAINING_GUARD, 1);
            parse_release_deferred_vdbe(state);
            assert_eq!(read_word(state, DEFERRED_CHILD), 0xfeed_face);
            assert_eq!(state.add(pointer_offset(DEFERRED_FLAG)).read(), 1);
            assert_eq!((child.add(0x22) as *const u16).read(), 1);
        }
    }

    #[test]
    fn absent_deferred_child_skips_release() {
        let Some((state, _owner, child, _context)) =
            (unsafe { fixture(hints::DEFERRED_OWNER_CHILD_ABSENT) })
        else {
            note_missing_u32_fixture("sqlite/parse_release_deferred_vdbe");
            return;
        };

        unsafe {
            state.add(pointer_offset(DEFERRED_FLAG)).write(1);
            parse_release_deferred_vdbe(state);
            assert_eq!(state.add(pointer_offset(DEFERRED_FLAG)).read(), 1);
            assert_eq!((child.add(0x22) as *const u16).read(), 1);
        }
    }

    #[test]
    fn signed_nonpositive_owner_child_skips_release_but_clears_state() {
        let Some((state, owner, child, _context)) =
            (unsafe { fixture(hints::DEFERRED_OWNER_CHILD_SIGNED) })
        else {
            note_missing_u32_fixture("sqlite/parse_release_deferred_vdbe");
            return;
        };

        unsafe {
            write_pointer(owner, OWNER_CHILD, 0x8000_0000usize as *mut u8);
            write_word(state, DEFERRED_CHILD, 1);
            state.add(pointer_offset(DEFERRED_FLAG)).write(1);
            parse_release_deferred_vdbe(state);
            assert_eq!(read_word(state, DEFERRED_CHILD), 0);
            assert_eq!(state.add(pointer_offset(DEFERRED_FLAG)).read(), 0);
            assert_eq!((child.add(0x22) as *const u16).read(), 1);
        }
    }
}
