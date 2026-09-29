//! Parent-directory path-component predicate.
//!
//! `path_component_is_parent_reference` is retailOS `FUN_082e2ad0` at
//! `0x082e2ad0`. Raw ARM establishes an 80-byte extent
//! (`0x082e2ad0..0x082e2b1f`): its literal pool starts at `0x082e2b20`, and
//! the next separately entered function starts at `0x082e2b28`. Decoding all
//! ARM B/BL words in `osos.dec` finds two inbound direct call sites, both
//! plain unconditional `bl` at `0x082e16bc` and `0x082e4184`, with no
//! predicated calls or tail branches. Its one outbound call is a plain `bl`
//! through veneer `0x082e0138` to `0x082e014c`.
//!
//! It adds the numeric address of `accumulator_contribution` to resident word
//! `0x08a0a748`, then accepts `..` only when it ends immediately or the next
//! nine bytes are all ASCII spaces. The bounded whitespace helper at
//! `0x082e014c` is not yet ported; target builds call its verified retailOS
//! address and host builds use a replacement seam. Deliberate deviation: none.

use super::path_component_split::add_accumulator_contribution;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn remaining_path_bytes_are_spaces(bytes: *const u8, limit: u32) -> u32 {
    let helper: unsafe extern "C" fn(*const u8, u32) -> u32 =
        core::mem::transmute(0x082e_014cusize);
    helper(bytes, limit)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_remaining_path_bytes_are_spaces(_bytes: *const u8, _limit: u32) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
static mut REMAINING_PATH_BYTES_ARE_SPACES: unsafe extern "C" fn(*const u8, u32) -> u32 =
    host_remaining_path_bytes_are_spaces;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn remaining_path_bytes_are_spaces(bytes: *const u8, limit: u32) -> u32 {
    let helper = core::ptr::read_volatile(core::ptr::addr_of!(REMAINING_PATH_BYTES_ARE_SPACES));
    helper(bytes, limit)
}

/// Answers whether `component` is the retailOS parent-directory reference.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_component_is_parent_reference(
    component: *const u8,
    accumulator_contribution: *mut u8,
) -> u32 {
    add_accumulator_contribution(accumulator_contribution);

    if component.read() != b'.' || component.add(1).read() != b'.' {
        return 0;
    }
    if component.add(2).read() == 0 {
        return 1;
    }
    remaining_path_bytes_are_spaces(component.add(2), 9)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::fs::path_component_split::{
        path_component_accumulator, reset_path_component_accumulator,
        PATH_COMPONENT_ACCUMULATOR_TEST_LOCK,
    };

    static mut HELPER_RESULT: u32 = 0;
    static mut HELPER_CALL: Option<(usize, u32)> = None;

    unsafe extern "C" fn recording_space_helper(bytes: *const u8, limit: u32) -> u32 {
        HELPER_CALL = Some((bytes as usize, limit));
        HELPER_RESULT
    }

    unsafe fn reset_helper(result: u32) {
        HELPER_RESULT = result;
        HELPER_CALL = None;
        REMAINING_PATH_BYTES_ARE_SPACES = recording_space_helper;
    }

    #[test]
    fn immediate_parent_reference_skips_the_bounded_space_helper() {
        let _guard = PATH_COMPONENT_ACCUMULATOR_TEST_LOCK.lock();
        unsafe {
            reset_path_component_accumulator();
            reset_helper(0);
            let mut contribution = 0u8;
            assert_eq!(
                path_component_is_parent_reference(b"..\0".as_ptr(), &mut contribution),
                1
            );
            assert_eq!(HELPER_CALL, None);
        }
    }

    #[test]
    fn trailing_bytes_use_the_exact_nine_byte_helper_contract() {
        let _guard = PATH_COMPONENT_ACCUMULATOR_TEST_LOCK.lock();
        unsafe {
            reset_path_component_accumulator();
            reset_helper(1);
            let mut contribution = 0u8;
            let component = b"..         x\0";
            assert_eq!(
                path_component_is_parent_reference(component.as_ptr(), &mut contribution),
                1
            );
            assert_eq!(HELPER_CALL, Some((component.as_ptr().add(2) as usize, 9)));

            reset_helper(0);
            assert_eq!(
                path_component_is_parent_reference(component.as_ptr(), &mut contribution),
                0
            );
        }
    }

    #[test]
    fn non_parent_components_do_not_call_the_helper_and_still_update_the_accumulator() {
        let _guard = PATH_COMPONENT_ACCUMULATOR_TEST_LOCK.lock();
        unsafe {
            reset_path_component_accumulator();
            reset_helper(1);
            let before = path_component_accumulator();
            let mut contribution = 0u8;
            assert_eq!(
                path_component_is_parent_reference(b".x\0".as_ptr(), &mut contribution),
                0
            );
            assert_eq!(HELPER_CALL, None);
            assert_eq!(
                path_component_accumulator(),
                before.wrapping_add(&mut contribution as *mut u8 as usize as u32)
            );
        }
    }
}
