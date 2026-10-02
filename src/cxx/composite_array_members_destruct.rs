//! Composite member destructor — `FUN_08284a88` @ **0x08284a88**.
//!
//! True size: 48 bytes, ending with `b 0x08277484` at 0x08284ab4;
//! the next function starts with `push {r4,lr}` at 0x08284ab8.
//! Raw A32 decoding verifies four plain BLs, zero predicated BLs, and
//! two inbound plain BLs (0x0839c814, 0x0839c858), zero predicated inbound BLs.
//! Destroys members in reverse order at +0x78, +0x4c, +0x34, +0x08,
//! then the leading StringObject. Each next address is derived from the
//! preceding destructor's RETURN value, not from a saved original pointer.
//! Class identity is unknown. Deliberate deviations: Rust expresses the tail
//! branch as a return and uses the existing ported callees; byte arithmetic
//! keeps member offsets target-width even on hosts. The private inline chain
//! permits isolated tests without invoking target-layout virtual dispatch.

#[inline(always)]
unsafe fn destruct_chain(
    this: *mut u8,
    mut destroy: impl FnMut(usize, *mut u8) -> *mut u8,
) -> *mut u8 {
    let mut member = this.wrapping_add(0x78);
    for (stage, retreat) in [0x2c, 0x18, 0x2c, 8].into_iter().enumerate() {
        member = destroy(stage, member).wrapping_sub(retreat);
    }
    destroy(4, member)
}

/// Destroys the four array-derived members, then the leading string object.
///
/// # Safety
/// `this` must name a live composite object with valid member storage and
/// resources for all five existing destructor contracts. No NULL guard exists.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn composite_array_members_destruct(this: *mut u8) -> *mut u8 {
    unsafe {
        destruct_chain(this, |stage, member| match stage {
            0 => super::observable_array_pre_destruct_check_destruct::observable_array_pre_destruct_check_destruct(member.cast()).cast(),
            1 => super::vtable_0898285c_destruct::vtable_0898285c_destruct(member.cast()).cast(),
            2 => super::observable_array_attached_release_cells_destruct_083d0250::observable_array_attached_release_cells_destruct_083d0250(member.cast()).cast(),
            3 => super::vtable_089820c4_destruct::vtable_089820c4_destruct(member.cast()).cast(),
            _ => super::string_object::string_object_destroy(member.cast()).cast(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_teardown_preserves_neighboring_storage() {
        let mut words = [0xfeed_faceu32; 40];
        let base = words.as_mut_ptr().cast::<u8>();
        let offsets = [0x78, 0x4c, 0x34, 8, 0];
        let mut completed = 0;
        let result = unsafe { destruct_chain(base, |stage, member| {
            assert_eq!(stage, completed);
            assert_eq!(member, base.wrapping_add(offsets[stage]));
            if stage != 0 {
                assert_eq!(base.wrapping_add(offsets[stage - 1]).cast::<u32>().read(), 0);
            }
            member.cast::<u32>().write(0);
            completed += 1;
            member
        }) };
        assert_eq!(result, base);
        for (index, word) in words.into_iter().enumerate() {
            assert_eq!(word, if offsets.contains(&(index * 4)) { 0 } else { 0xfeed_face });
        }
    }

    #[test]
    fn adjusted_returns_drive_remaining_teardown_and_final_result() {
        let mut words = [0xfeed_faceu32; 48];
        let base = words.as_mut_ptr().cast::<u8>();
        // Every member destructor returns an address four bytes later.
        // Saving the original this or discarding a callee return would clear
        // different storage, even though normal destructors return their input.
        let offsets = [0x78, 0x50, 0x3c, 0x14, 0x10];
        let result = unsafe { destruct_chain(base, |stage, member| {
            assert_eq!(member, base.wrapping_add(offsets[stage]));
            member.cast::<u32>().write(0);
            member.wrapping_add(4)
        }) };
        assert_eq!(result, base.wrapping_add(0x14));
        for (index, word) in words.into_iter().enumerate() {
            assert_eq!(word, if offsets.contains(&(index * 4)) { 0 } else { 0xfeed_face });
        }
    }
}
