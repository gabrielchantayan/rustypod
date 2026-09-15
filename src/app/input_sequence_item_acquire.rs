//! Input-sequence item acquisition — `FUN_08129a78` @ **0x08129a78**.
//!
//! # Raw extent and call sites
//!
//! The 15 ARM instructions at `0x08129a78..0x08129ab4` are the complete
//! **60-byte** body; `FUN_08129ab4` starts at `0x08129ab4`. The body contains
//! two unconditional `bl` instructions and no predicated calls. Its five
//! inbound calls are plain `bl` instructions (from `0x081299c0`, `0x08129b30`,
//! `0x08129c80`, `0x08129f04`, and `0x08129f48`); none is predicated.
//!
//! # Algorithm
//!
//! Look up the item with `action_index` in the collection selected by `mode`.
//! Store that result at state `+0xb0`. Only when it is NULL, construct and
//! insert a replacement item, store its result at the same word, then reload
//! and return that word.
//!
//! # Deliberate deviations
//!
//! The lookup (`FUN_0812b018`) and construction (`FUN_081294c4`) callees are
//! not ported. Their behavior and three-register ABI are verified from their
//! raw callers/decompilation, so host tests use explicit seams; target builds
//! retain unresolved retail entry points for the linker/hook configuration.

#[cfg(not(target_os = "none"))]
use core::ptr;

/// ABI of the unported lookup and construction helpers.
pub type InputSequenceItemOp = unsafe extern "C" fn(*mut u8, u32, u32) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_input_sequence_item_op(_state: *mut u8, _index: u32, _mode: u32) -> *mut u8 {
    ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
static mut INPUT_SEQUENCE_FIND_ITEM: InputSequenceItemOp = missing_input_sequence_item_op;
#[cfg(not(target_os = "none"))]
static mut INPUT_SEQUENCE_BUILD_ITEM: InputSequenceItemOp = missing_input_sequence_item_op;

#[cfg(target_os = "none")]
extern "C" {
    fn retail_input_sequence_find_item(state: *mut u8, index: u32, mode: u32) -> *mut u8;
    fn retail_input_sequence_build_item(state: *mut u8, index: u32, mode: u32) -> *mut u8;
}

#[inline(always)]
unsafe fn find_item(state: *mut u8, index: u32, mode: u32) -> *mut u8 {
    #[cfg(target_os = "none")]
    { retail_input_sequence_find_item(state, index, mode) }
    #[cfg(not(target_os = "none"))]
    { INPUT_SEQUENCE_FIND_ITEM(state, index, mode) }
}

#[inline(always)]
unsafe fn build_item(state: *mut u8, index: u32, mode: u32) -> *mut u8 {
    #[cfg(target_os = "none")]
    { retail_input_sequence_build_item(state, index, mode) }
    #[cfg(not(target_os = "none"))]
    { INPUT_SEQUENCE_BUILD_ITEM(state, index, mode) }
}

/// Finds or creates the input-sequence item selected by `action_index`.
///
/// # Safety
///
/// `state` must be writable through offset `0xb3`; the selected retail helper
/// must accept `state`, `action_index`, and `mode`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn input_sequence_item_acquire(
    state: *mut u8,
    action_index: u32,
    mode: u32,
) -> *mut u8 {
    let item_slot = state.add(0xb0).cast::<u32>();
    let item = find_item(state, action_index, mode);
    item_slot.write_volatile(item as u32);
    if item.is_null() {
        item_slot.write_volatile(build_item(state, action_index, mode) as u32);
    }
    item_slot.read_volatile() as usize as *mut u8
}

#[cfg(test)]
pub(crate) unsafe fn replace_input_sequence_item_ops(
    find: InputSequenceItemOp,
    build: InputSequenceItemOp,
) -> (InputSequenceItemOp, InputSequenceItemOp) {
    let previous = (INPUT_SEQUENCE_FIND_ITEM, INPUT_SEQUENCE_BUILD_ITEM);
    INPUT_SEQUENCE_FIND_ITEM = find;
    INPUT_SEQUENCE_BUILD_ITEM = build;
    previous
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, INPUT_SEQUENCE_ITEM_OPS_TEST_LOCK};

    static mut FIND_RESULT: *mut u8 = ptr::null_mut();
    static mut BUILD_RESULT: *mut u8 = ptr::null_mut();
    static mut FIND_ARGS: (usize, u32, u32) = (0, 0, 0);
    static mut BUILD_ARGS: (usize, u32, u32) = (0, 0, 0);
    static mut BUILD_CALLS: u32 = 0;

    unsafe extern "C" fn find(state: *mut u8, index: u32, mode: u32) -> *mut u8 {
        FIND_ARGS = (state as usize, index, mode);
        FIND_RESULT
    }
    unsafe extern "C" fn build(state: *mut u8, index: u32, mode: u32) -> *mut u8 {
        BUILD_ARGS = (state as usize, index, mode);
        BUILD_CALLS += 1;
        BUILD_RESULT
    }

    struct Restore(InputSequenceItemOp, InputSequenceItemOp);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { replace_input_sequence_item_ops(self.0, self.1); }
        }
    }

    #[test]
    fn preserves_a_found_item_without_constructing() {
        let _lock = INPUT_SEQUENCE_ITEM_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = try_map_u32_slab(hints::INPUT_SEQUENCE_ITEM_FOUND, 0x1000) else {
            assert!(note_missing_u32_fixture("input_sequence_item_acquire"));
            return;
        };
        let previous = unsafe { replace_input_sequence_item_ops(find, build) };
        let _restore = Restore(previous.0, previous.1);
        unsafe {
            FIND_RESULT = state.add(0x200);
            BUILD_RESULT = ptr::null_mut(); BUILD_CALLS = 0;
            let result = input_sequence_item_acquire(state, 0x1f, 1);
            assert_eq!(result, FIND_RESULT);
            assert_eq!(state.add(0xb0).cast::<u32>().read() as usize, FIND_RESULT as usize);
            assert_eq!(BUILD_CALLS, 0);
            assert_eq!(FIND_ARGS, (state as usize, 0x1f, 1));
        }
    }

    #[test]
    fn constructs_only_after_a_null_lookup_and_returns_the_stored_result() {
        let _lock = INPUT_SEQUENCE_ITEM_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = try_map_u32_slab(hints::INPUT_SEQUENCE_ITEM_BUILD, 0x1000) else {
            assert!(note_missing_u32_fixture("input_sequence_item_acquire"));
            return;
        };
        let previous = unsafe { replace_input_sequence_item_ops(find, build) };
        let _restore = Restore(previous.0, previous.1);
        unsafe {
            FIND_RESULT = ptr::null_mut(); BUILD_RESULT = state.add(0x200); BUILD_CALLS = 0;
            assert_eq!(input_sequence_item_acquire(state, 3, 0), BUILD_RESULT);
            assert_eq!(state.add(0xb0).cast::<u32>().read() as usize, BUILD_RESULT as usize);
            assert_eq!(BUILD_CALLS, 1);
            assert_eq!(BUILD_ARGS, (state as usize, 3, 0));
        }
    }
}
