//! Copies the shared cell stored in an object's +0x894 field.
//!
//! ## Original: `FUN_0822b054` @ 0x0822b054 (12 bytes)
//!
//! The three-word body is a thunk: it adds 0x894 to `source` and tail-branches
//! to `FUN_083b50c8`. The next real function begins at 0x0822b060. Whole-image
//! A32 decoding finds three inbound unconditional plain `bl` calls (0x081b70ec,
//! 0x081cbe58, and 0x08220434), zero inbound predicated `bl` calls, and no
//! outbound `bl` calls. It copies the target-width shared-cell pointer from
//! `source + 0x894` to `dst`, then increments the non-NULL cell's +4 signed
//! reference count with wrapping arithmetic.
//!
//! Deliberate deviation: the tail branch to the already ported
//! `shared_cell_copy_construct_primary` is expressed inline so this 12-byte
//! veneer remains an independently hookable Rust entry. Host tests use a
//! low-address raw-u32 slab because the firmware object and shared-cell fields
//! are target-width pointers.

const SHARED_CELL_FIELD_WORD: usize = 0x894 / core::mem::size_of::<u32>();
const SHARED_CELL_REFCOUNT_WORD: usize = 1;

/// `shared_cell_field_copy` — retailOS `FUN_0822b054` @ `0x0822b054`.
///
/// # Safety
/// `dst` must be a valid aligned writable target-pointer word; `source` must
/// be a valid aligned object with a readable word at +0x894. A non-NULL cell
/// pointer stored there must be writable through its +4 reference-count word.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.shared_cell_field_copy")]
#[inline(never)]
pub unsafe extern "C" fn shared_cell_field_copy(dst: *mut u32, source: *const u32) -> *mut u32 {
    let cell = source.add(SHARED_CELL_FIELD_WORD).read();
    dst.write(cell);
    if cell != 0 {
        let refcount = (cell as usize as *mut u32)
            .add(SHARED_CELL_REFCOUNT_WORD)
            .read_volatile();
        (cell as usize as *mut u32)
            .add(SHARED_CELL_REFCOUNT_WORD)
            .write_volatile(refcount.wrapping_add(1));
    }
    dst
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn copies_field_and_retains_non_null_cell() {
        let Some(slab) = try_map_u32_slab(hints::SHARED_CELL_FIELD_COPY, 0x1000) else {
            return;
        };
        let source = slab.cast::<u32>();
        let cell = unsafe { slab.add(0x900).cast::<u32>() };
        let dst = unsafe { slab.add(0x800).cast::<u32>() };
        unsafe {
            cell.write(0x1234_5678);
            cell.add(SHARED_CELL_REFCOUNT_WORD).write(0xffff_ffff);
            source.add(SHARED_CELL_FIELD_WORD).write(cell as usize as u32);

            assert_eq!(shared_cell_field_copy(dst, source), dst);
            assert_eq!(dst.read(), cell as usize as u32);
            assert_eq!(cell.add(SHARED_CELL_REFCOUNT_WORD).read(), 0);
        }
    }

    #[test]
    fn copies_null_field_without_touching_adjacent_memory() {
        let Some(slab) = try_map_u32_slab(hints::SHARED_CELL_FIELD_COPY_NULL, 0x1000) else {
            return;
        };
        let source = slab.cast::<u32>();
        let dst = unsafe { slab.add(0x800).cast::<u32>() };
        unsafe {
            dst.write(0xfeed_face);
            source.add(SHARED_CELL_FIELD_WORD).write(0);

            assert_eq!(shared_cell_field_copy(dst, source), dst);
            assert_eq!(dst.read(), 0);
            assert_eq!(source.add(SHARED_CELL_FIELD_WORD + 1).read(), 0);
        }
    }
}
