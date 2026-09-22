//! `mov_atom_table_root` — original: `FUN_08280114` at load address
//! `0x08280114` (**8 bytes**, `0x08280114..0x0828011b`; all code). The
//! next real function begins at `0x0828011c` with `push {r4, lr}`. Raw
//! `osos.dec` words are `e5900000` (`ldr r0, [r0]`) and `e12fff1e` (`bx
//! lr`). There are **three direct plain `bl` call sites**, at `0x081c7e78`,
//! `0x081c8048`, and `0x081d8354`, and no predicated `bl` call sites.
//!
//! The MOV/MP4 parser stores its atom-table root in word zero of a table
//! handle. This accessor loads and returns that 32-bit ARM word. Deliberate
//! deviation: its argument and result remain `u32`, rather than host pointer
//! types, because the firmware field is exactly four bytes while host pointers
//! can be eight bytes.

/// Returns the atom-table root stored in word zero of `table_handle`.
///
/// # Safety
///
/// `table_handle` must be readable as one aligned `u32`. The original has no
/// NULL, bounds, or alignment check.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_atom_table_root(table_handle: *const u32) -> u32 {
    *table_handle
}

#[cfg(test)]
mod tests {
    use super::mov_atom_table_root;

    #[test]
    fn returns_the_first_32_bit_handle_word_verbatim() {
        for root in [0, 1, 0x0800_0000, 0x2200_0000, u32::MAX] {
            let handle = [root, !root, 0xfeed_face];
            assert_eq!(unsafe { mov_atom_table_root(handle.as_ptr()) }, root);
        }
    }
}
