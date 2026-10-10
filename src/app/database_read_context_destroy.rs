//! Database read-context destruction, retail `FUN_080bd694` @ 0x080bd694.
//!
//! True extent: 56 bytes (52 instruction bytes and the +0x8018 literal at
//! 0x080bd6c8); the next function begins at 0x080bd6cc. Raw A32 has zero
//! plain BLs, two BLNEs to free_tag4, and one tail B to the same callee.
//! Whole-image decoding finds two incoming plain BLs and no predicated BLs.
//!
//! NULL is ignored. Otherwise release the optional primary buffer at +4,
//! then the optional auxiliary buffer at +0x8018, then the context itself,
//! all with heap tag 4. Fields are not cleared. The constructor at 0x0809ea58
//! and database-opening caller at 0x08063e9c establish this owner role.
//! Deliberate deviation: Rust does not guarantee the final tail transfer;
//! deallocation uses the existing free_tag4 seam. Target pointer words stay
//! four bytes wide even on hosts with wider native pointers.

use crate::heap::veneers::free_tag4;

const PRIMARY_BUFFER: usize = 4 / 4;
const AUXILIARY_BUFFER: usize = 0x8018 / 4;

/// # Safety
/// A non-NULL context must be a word-aligned tag-4 allocation readable through
/// +0x801b. Its nonzero buffer words must name distinct live tag-4 allocations,
/// neither of which overlaps the context. All three allocations are consumed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn database_read_context_destroy(context: *mut u32) {
    if context.is_null() {
        return;
    }
    let primary = context.add(PRIMARY_BUFFER).read();
    if primary != 0 {
        free_tag4(primary as usize as *mut u8);
    }
    let auxiliary = context.add(AUXILIARY_BUFFER).read();
    if auxiliary != 0 {
        free_tag4(auxiliary as usize as *mut u8);
    }
    free_tag4(context.cast());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};

    #[test]
    fn null_context_does_not_free() {
        let _lock = mock_heap();
        unsafe { database_read_context_destroy(core::ptr::null_mut()) };
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn optional_buffers_and_owner_are_consumed_without_field_writes() {
        for (primary, auxiliary) in [(0, 0), (0x1234_5000, 0), (0, 0x2345_6000), (0x1234_5000, 0x2345_6000)] {
            let _lock = mock_heap();
            let mut context = [0xa5a5_a5a5u32; AUXILIARY_BUFFER + 2];
            context[PRIMARY_BUFFER] = primary;
            context[AUXILIARY_BUFFER] = auxiliary;
            let before = context;
            unsafe { database_read_context_destroy(context.as_mut_ptr()) };
            assert_eq!(free_log(), (1 + usize::from(primary != 0) + usize::from(auxiliary != 0), context.as_mut_ptr().cast(), 4));
            assert_eq!(context, before);
        }
    }
}
