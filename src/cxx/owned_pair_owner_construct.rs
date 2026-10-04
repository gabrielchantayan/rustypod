//! Owned-pair owner construction — `FUN_081d8748` @ `0x081d8748`.
//!
//! True extent [0x081d8748,0x081d8764): 28 bytes, comprising 24 code
//! bytes and the 0x0898e0a8 vtable literal at 0x081d8760. The next real
//! function is owned_pair_owner_destruct at 0x081d8764. Raw aligned ARM
//! decoding finds two incoming plain BLs (0x081f4de4, 0x081f4dfc), zero
//! incoming predicated BLs, and zero outgoing BLs of either kind.
//!
//! Install the base vtable, store the supplied context at +0x0c, and clear
//! the auxiliary word at +0x04. Preserve the pair word at +0x08 and return
//! the original owner pointer (r0 is unchanged, despite Ghidra's void
//! signature). Caller 0x081f4dd8 constructs embedded owners at +0x18 and
//! +0x2c and replaces their vtables. Concrete class identity is unknown.
//! No behavioral deviations; u32 word indexing preserves target offsets
//! on 64-bit hosts without interpreting firmware pointer words.

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_pair_owner_construct(owner: *mut u32, context: u32) -> *mut u32 {
    owner.write(0x0898_e0a8);
    owner.add(3).write(context);
    owner.add(1).write(0);
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_preserves_pair_and_neighbors_with_full_width_context() {
        for context in [0, 1, 0x8000_0000, 0xffff_ffff] {
            let mut words = [0xaaaa_aaaa, 0x1111_1111, 0x2222_2222,
                             0x3333_3333, 0x4444_4444, 0xbbbb_bbbb];
            let owner = unsafe { words.as_mut_ptr().add(1) };
            assert_eq!(unsafe { owned_pair_owner_construct(owner, context) }, owner);
            assert_eq!(words, [0xaaaa_aaaa, 0x0898_e0a8, 0,
                               0x3333_3333, context, 0xbbbb_bbbb]);
        }
    }

    #[test]
    fn reconstruction_replaces_context_without_clearing_owned_pair() {
        let mut words = [0, 0xffff_ffff, 0x1234_5678, 0];
        let owner = words.as_mut_ptr();
        unsafe { owned_pair_owner_construct(owner, 0xffff_ffff); }
        words[1] = 0x8765_4321;
        unsafe { owned_pair_owner_construct(owner, 0); }
        assert_eq!(words, [0x0898_e0a8, 0, 0x1234_5678, 0]);
    }
}
