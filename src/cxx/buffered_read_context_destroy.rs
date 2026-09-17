//! Buffered read context destructor — retailOS `FUN_082677a0` at load address
//! `0x082677a0` (40 bytes, `0x082677a0..0x082677c8`). Raw `osos.dec` words
//! establish the next independent `push {r4,lr}` function at `0x082677c8`.
//!
//! Raw ARM has one plain direct `bl` (`operator_delete_tag3` at `0x082aad14`)
//! and no predicated calls. A whole-image branch decode finds four plain direct
//! callers and no predicated callers. It deletes the target-width allocation
//! word at +0x0c, clears that word and the length at +0x10, clears the state
//! byte at +0x14, then returns the context.
//!
//! Deliberate deviation: the ARM call is the existing Rust
//! `operator_delete_tag3` call. The target pointer remains a `u32` word on
//! host builds; all accesses are volatile to preserve the firmware ordering.

use crate::heap::veneers::operator_delete_tag3;

/// Target-width allocation word (`+0x0c / sizeof(u32)`).
pub const BUFFERED_READ_CONTEXT_ALLOCATION_WORD: usize = 3;
/// Target-width length word (`+0x10 / sizeof(u32)`).
pub const BUFFERED_READ_CONTEXT_LENGTH_WORD: usize = 4;
/// State byte offset.
pub const BUFFERED_READ_CONTEXT_STATE_OFFSET: usize = 0x14;

/// Releases the buffered-read allocation and resets its result fields.
///
/// `context` must point to at least 0x15 bytes. The allocation is passed to
/// the tag-3 delete even when zero, exactly as the original does.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffered_read_context_destroy(context: *mut u8) -> *mut u8 {
    let allocation = (context as *const u32)
        .add(BUFFERED_READ_CONTEXT_ALLOCATION_WORD)
        .read_volatile();
    operator_delete_tag3(allocation as usize as *mut u8);
    (context as *mut u32)
        .add(BUFFERED_READ_CONTEXT_ALLOCATION_WORD)
        .write_volatile(0);
    (context as *mut u32)
        .add(BUFFERED_READ_CONTEXT_LENGTH_WORD)
        .write_volatile(0);
    context
        .add(BUFFERED_READ_CONTEXT_STATE_OFFSET)
        .write_volatile(0);
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_allocation_then_clears_only_the_owned_result_fields() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let allocation = 0x1234_5678u32;
        let mut context = [0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc, allocation, 0xfeed_beef, 0x1122_3344];
        unsafe {
            (context.as_mut_ptr() as *mut u8)
                .add(BUFFERED_READ_CONTEXT_STATE_OFFSET)
                .write_volatile(0x9a);
            let returned = buffered_read_context_destroy(context.as_mut_ptr().cast());
            assert_eq!(returned, context.as_mut_ptr().cast());
        }
        assert_eq!(
            crate::heap::veneers::tests::free_log(),
            (1, allocation as usize as *mut u8, 3)
        );
        assert_eq!(context[BUFFERED_READ_CONTEXT_ALLOCATION_WORD], 0);
        assert_eq!(context[BUFFERED_READ_CONTEXT_LENGTH_WORD], 0);
        assert_eq!(unsafe { (context.as_ptr() as *const u8).add(BUFFERED_READ_CONTEXT_STATE_OFFSET).read_volatile() }, 0);
        assert_eq!(context[0..3], [0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc]);
    }

    #[test]
    fn null_allocation_still_resets_the_context_without_freeing() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let mut context = [0u32, 0, 0, 0, 0xfeed_beef, 0xffffffff];
        unsafe { buffered_read_context_destroy(context.as_mut_ptr().cast()) };
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
        assert_eq!(context[BUFFERED_READ_CONTEXT_ALLOCATION_WORD], 0);
        assert_eq!(context[BUFFERED_READ_CONTEXT_LENGTH_WORD], 0);
        assert_eq!(unsafe { (context.as_ptr() as *const u8).add(BUFFERED_READ_CONTEXT_STATE_OFFSET).read_volatile() }, 0);
    }
}
