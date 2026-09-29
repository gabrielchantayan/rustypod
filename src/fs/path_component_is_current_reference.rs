//! Current-directory path-component predicate.
//!
//! `path_component_is_current_reference` is retailOS `FUN_082e2a7c` at
//! `0x082e2a7c`. Raw ARM establishes its exact 80-byte code extent
//! (`0x082e2a7c..0x082e2acb`): the following word at `0x082e2acc` is its
//! accumulator-address literal and the next separately entered function begins
//! at `0x082e2ad0`. Decoding every ARM B/BL word in `osos.dec` finds two
//! inbound direct call sites, both plain unconditional `bl` at `0x082e1684`
//! and `0x082e4170`, with no predicated calls or tail branches. Its one
//! outbound call is a plain `bl` through veneer `0x082e0138` to `0x082e014c`.
//!
//! It adds the numeric address of `accumulator_contribution` to resident word
//! `0x08a0a748`, then accepts `.` only when it ends immediately or the next
//! ten bytes are all ASCII spaces. The bounded whitespace helper at
//! `0x082e0138` is ported locally. Deliberate deviation: none.

use super::path_component_split::add_accumulator_contribution;
use super::remaining_path_bytes_are_spaces::remaining_path_bytes_are_spaces;

/// Answers whether `component` is the retailOS current-directory reference.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_component_is_current_reference(
    component: *const u8,
    accumulator_contribution: *mut u8,
) -> u32 {
    add_accumulator_contribution(accumulator_contribution);

    if component.read() != b'.' {
        return 0;
    }
    if component.add(1).read() == 0 {
        return 1;
    }
    if remaining_path_bytes_are_spaces(component.add(1), 10) != 0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::fs::path_component_split::{
        path_component_accumulator, reset_path_component_accumulator,
        PATH_COMPONENT_ACCUMULATOR_TEST_LOCK,
    };

    #[test]
    fn accepts_immediate_and_space_padded_current_references() {
        let _guard = PATH_COMPONENT_ACCUMULATOR_TEST_LOCK.lock();
        unsafe {
            reset_path_component_accumulator();
            let mut contribution = 0u8;
            assert_eq!(
                path_component_is_current_reference(b".\0".as_ptr(), &mut contribution),
                1
            );
            assert_eq!(
                path_component_is_current_reference(b".          x\0".as_ptr(), &mut contribution),
                1
            );
        }
    }

    #[test]
    fn rejects_non_current_components_and_updates_the_accumulator() {
        let _guard = PATH_COMPONENT_ACCUMULATOR_TEST_LOCK.lock();
        unsafe {
            reset_path_component_accumulator();
            let before = path_component_accumulator();
            let mut contribution = 0u8;
            assert_eq!(
                path_component_is_current_reference(b"x\0".as_ptr(), &mut contribution),
                0
            );
            assert_eq!(
                path_component_accumulator(),
                before.wrapping_add(&mut contribution as *mut u8 as usize as u32)
            );
        }
    }
}
