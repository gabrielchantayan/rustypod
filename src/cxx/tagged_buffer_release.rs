//! Tagged buffer release — retailOS `FUN_0827c158` at load address
//! `0x0827c158` (52 bytes, `0x0827c158..0x0827c18c`). Raw `osos.dec` confirms
//! the following `push {r4,lr}` at `0x0827c18c` starts the next function.
//!
//! Raw ARM has one direct call (`bl 0x082aad14`) and the function has four
//! direct callers: four plain `bl`, zero predicated. It releases the target
//! width allocation word at +8 only when the state byte at +0 is 3 or 4,
//! clears that word, then sets the state to the -1 sentinel.
//!
//! Deliberate deviation: the direct ARM call becomes the existing Rust
//! `operator_delete_tag3` call; its target tag-3 allocator contract is shared
//! unchanged. Target pointer fields remain `u32` words even on host builds.

use crate::heap::veneers::operator_delete_tag3;

/// State byte that owns the allocation word at +8.
pub const TAGGED_BUFFER_OWNS_TAG3: u8 = 3;
/// Second state byte that owns the same allocation word at +8.
pub const TAGGED_BUFFER_OWNS_TAG4: u8 = 4;
/// Empty sentinel installed after every release attempt.
pub const TAGGED_BUFFER_EMPTY: u8 = 0xff;
/// Target-width allocation word index (`+0x08 / sizeof(u32)`).
pub const TAGGED_BUFFER_ALLOCATION_WORD: usize = 2;

/// Releases a tagged buffer's tag-3 allocation and marks the buffer empty.
///
/// `buffer` must point to at least three target words. The state byte at +0
/// decides whether word +8 is an owned allocation; all state values are then
/// replaced with the empty sentinel.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_buffer_release(buffer: *mut u8) {
    let state = buffer.read_volatile();
    if state == TAGGED_BUFFER_OWNS_TAG3 || state == TAGGED_BUFFER_OWNS_TAG4 {
        let allocation = (buffer as *const u32)
            .add(TAGGED_BUFFER_ALLOCATION_WORD)
            .read_volatile();
        operator_delete_tag3(allocation as usize as *mut u8);
        (buffer as *mut u32)
            .add(TAGGED_BUFFER_ALLOCATION_WORD)
            .write_volatile(0);
    }
    buffer.write_volatile(TAGGED_BUFFER_EMPTY);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_states_release_through_tag3_and_clear_the_target_width_allocation() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let allocation = 0x1234_5678u32;
        for (calls, state) in [TAGGED_BUFFER_OWNS_TAG3, TAGGED_BUFFER_OWNS_TAG4]
            .into_iter()
            .enumerate()
        {
            let mut buffer = [0u32, 0, allocation];
            unsafe {
                (buffer.as_mut_ptr() as *mut u8).write_volatile(state);
                tagged_buffer_release(buffer.as_mut_ptr().cast());
            }
            assert_eq!(unsafe { (buffer.as_ptr() as *const u8).read_volatile() }, TAGGED_BUFFER_EMPTY);
            assert_eq!(buffer[TAGGED_BUFFER_ALLOCATION_WORD], 0);
            assert_eq!(
                crate::heap::veneers::tests::free_log(),
                (calls + 1, allocation as usize as *mut u8, 3)
            );
        }
    }

    #[test]
    fn non_owner_state_preserves_the_allocation_word() {
        for state in [0, 1, 2, 5, TAGGED_BUFFER_EMPTY] {
            let mut buffer = [0u32, 0, 0xfeed_beef];
            unsafe {
                (buffer.as_mut_ptr() as *mut u8).write_volatile(state);
                tagged_buffer_release(buffer.as_mut_ptr().cast());
            }
            assert_eq!(unsafe { (buffer.as_ptr() as *const u8).read_volatile() }, TAGGED_BUFFER_EMPTY);
            assert_eq!(buffer[TAGGED_BUFFER_ALLOCATION_WORD], 0xfeed_beef);
        }
    }
}
