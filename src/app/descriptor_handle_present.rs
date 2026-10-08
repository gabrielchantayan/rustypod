//! Test whether a descriptor slot selects a populated handle.
//!
//! Original FUN_0811f074 @ 0x0811f074, 76 bytes, ending at the real
//! prologue at 0x0811f0c0. Raw A32 decoding: two inbound plain BLs
//! (0x081fcc00, 0x0820874c), three outbound plain BLs, no predicated BLs.
//! Load the descriptor table at owner +0x14; selectors 0..17 map through
//! records of nine words, with the vector index at record +0x24. Reject
//! UINT32_MAX and indices outside the unsigned vector count, then test
//! the selected handle cell and its payload for nonzero.
//!
//! Deliberate deviation: inline the verified algorithms at 0x081d5fe0,
//! vector_size_elem4 (0x083d76d8), and handle_deref_or_null's alias
//! (0x083d60bc). Raw u32 fields preserve firmware layout on 64-bit hosts;
//! the vector count retains the original wrapping subtraction and ASR.

/// Return exactly zero or one for the selected descriptor's handle.
///
/// # Safety
/// `owner` is aligned and readable through word five. For selectors below
/// eighteen its table must contain the selected index word. A non-sentinel
/// in-range index requires readable vector storage and, if nonzero, a
/// readable handle cell. Embedded addresses must fit in u32.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn descriptor_handle_present(owner: *const u32, selector: u32) -> u32 {
    let table = owner.add(5).read() as usize as *const u32;
    let index = if selector < 18 {
        table.add(selector as usize * 9 + 9).read()
    } else {
        u32::MAX
    };
    if index == u32::MAX { return 0; }
    let begin = owner.add(1).read();
    let end = owner.add(2).read();
    let count = ((end.wrapping_sub(begin) as i32) >> 2) as u32;
    if index >= count { return 0; }
    let slot = begin.wrapping_add(index.wrapping_mul(4)) as usize as *const u32;
    let cell = slot.read();
    if cell == 0 { return 0; }
    ((cell as usize as *const u32).read() != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_bounds_index_bounds_and_both_handle_null_levels() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::DESCRIPTOR_HANDLE_PRESENT, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("descriptor_handle_present"));
            return;
        };
        unsafe {
            let owner = slab.cast::<u32>();
            let table = slab.add(0x100).cast::<u32>();
            let vector = slab.add(0x400).cast::<u32>();
            let cell = slab.add(0x500).cast::<u32>();
            owner.add(5).write(table as usize as u32);
            owner.add(1).write(vector as usize as u32);
            owner.add(2).write(vector.add(3) as usize as u32);
            vector.write(0);
            vector.add(1).write(cell as usize as u32);
            vector.add(2).write(cell as usize as u32);
            cell.write(0x1234);
            for selector in 0..18 {
                for (index, expected) in [(u32::MAX, 0), (0, 0), (1, 1), (2, 1), (3, 0), (0x8000_0000, 0)] {
                    table.add(selector as usize * 9 + 9).write(index);
                    assert_eq!(descriptor_handle_present(owner, selector), expected);
                }
            }
            table.add(9).write(1);
            cell.write(0);
            assert_eq!(descriptor_handle_present(owner, 0), 0);
            cell.write(1);
            owner.add(2).write(vector as usize as u32);
            assert_eq!(descriptor_handle_present(owner, 0), 0);
            // ASR produces -1, compared as UINT32_MAX: index one remains valid.
            owner.add(2).write((vector as usize as u32).wrapping_sub(4));
            assert_eq!(descriptor_handle_present(owner, 0), 1);
            // Invalid selectors must not dereference the descriptor table.
            owner.add(5).write(0);
            for selector in [18, 19, 0x8000_0000, u32::MAX] {
                assert_eq!(descriptor_handle_present(owner, selector), 0);
            }
        }
    }
}
