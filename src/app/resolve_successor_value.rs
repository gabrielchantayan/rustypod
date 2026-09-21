//! RetailOS port of `FUN_082a2cac` at load address `0x082a2cac` (48 bytes).
//!
//! Raw ARM establishes the true extent `0x082a2cac..0x082a2cdb`; the `ldr
//! r0,[r0,#8]; bx lr` at `0x082a2cdc` is the next distinct function. Decoding
//! every A32 branch-immediate word finds three direct unconditional plain `bl`
//! callers (`0x082a2770`, `0x082a3350`, and `0x082a44e4`) and no predicated
//! `bl` callers. The function follows a flagged successor node: when its byte
//! `+0x1d` has bit 0, it obtains the `+0x20` child; if that non-null child's
//! byte `+0x1d` has bit 0 clear, it returns the child's `+0x20` value.
//!
//! Deliberate deviation: opaque target nodes are represented as aligned `u32`
//! words, preserving the target's four-byte `+0x20` field on 64-bit hosts. The
//! first ABI argument is deliberately unused, as verified by the raw words.

/// Resolves the value reached through one flagged successor node.
///
/// # Safety
///
/// When non-null, `successor` and its flagged child must each be readable
/// through byte offset `+0x20`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resolve_successor_value(_object: *mut u32, successor: *mut u32) -> *mut u32 {
    if successor.is_null() || (successor.cast::<u8>().add(0x1d).read() & 1) == 0 {
        return core::ptr::null_mut();
    }

    let child = successor.add(8).read() as *mut u32;
    if child.is_null() || (child.cast::<u8>().add(0x1d).read() & 1) != 0 {
        return core::ptr::null_mut();
    }

    child.add(8).read() as *mut u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn resolves_only_a_flagged_successor_to_an_unflagged_child_value() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::RESOLVE_SUCCESSOR_VALUE,
            0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        let successor = slab.cast::<u32>();
        let child = unsafe { slab.add(0x100).cast::<u32>() };
        let value = unsafe { slab.add(0x200).cast::<u32>() };

        unsafe {
            assert!(resolve_successor_value(core::ptr::null_mut(), core::ptr::null_mut()).is_null());

            successor.cast::<u8>().add(0x1d).write(0);
            successor.add(8).write(child as usize as u32);
            assert!(resolve_successor_value(core::ptr::null_mut(), successor).is_null());

            successor.cast::<u8>().add(0x1d).write(1);
            successor.add(8).write(0);
            assert!(resolve_successor_value(core::ptr::null_mut(), successor).is_null());

            successor.add(8).write(child as usize as u32);
            child.cast::<u8>().add(0x1d).write(1);
            child.add(8).write(value as usize as u32);
            assert!(resolve_successor_value(core::ptr::null_mut(), successor).is_null());

            child.cast::<u8>().add(0x1d).write(0);
            assert_eq!(resolve_successor_value(core::ptr::null_mut(), successor), value);
        }
    }
}
