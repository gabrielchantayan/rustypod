//! Signed position-window rejection for items removed from a linked list.
//!
//! Original `FUN_08152ff8` at 0x08152ff8: 80 bytes through 0x08153048,
//! including the literal at 0x08153044 (76 instruction bytes). Raw words
//! verify two incoming plain BLs, zero predicated BLs, and no outgoing calls.
//! Read the global window coordinate at 0x08a79844, add 0x2d0000 with
//! 32-bit wrapping, then compare the item's signed word at +0x140 twice:
//! return 1 if the first read is <= the negated limit OR the second is >=
//! the limit. Both boundaries are inclusive, even for zero/negative limits.
//!
//! Deliberate deviations: omit dead stack writes; host builds substitute
//! local storage for the firmware global. Volatile reads preserve both
//! position observations and their order; no absolute-value simplification.
//!
//! Verification: 14591 host tests passed; ARM release build passed.
//! Executable host smoke confirmed both inclusive boundaries and interior.
//! match.py returned structural diff exit 1: LLVM retains two position
//! loads, signed comparisons and OR, but drops dead stack writes, loads
//! the global directly and computes the lower limit by subtraction.
//! Both listings have 19 lines (LLVM's listing includes its address literal).

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut POSITION_WINDOW_COORDINATE: i32 = 0;

#[inline(always)]
unsafe fn position_window_coordinate() -> *const i32 {
    #[cfg(target_os = "none")]
    { 0x08a79844 as *const i32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of!(POSITION_WINDOW_COORDINATE) }
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn item_outside_position_window(item: *const u32) -> u32 {
    let coordinate = ptr::read_volatile(position_window_coordinate());
    let first_position = ptr::read_volatile(item.add(0x140 / 4).cast::<i32>());
    let limit = coordinate.wrapping_add(0x2d0000);
    let lower_limit = limit.wrapping_neg();
    let second_position = ptr::read_volatile(item.add(0x140 / 4).cast::<i32>());
    u32::from(first_position <= lower_limit) | u32::from(second_position >= limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusive_signed_boundaries_and_wrapping_limits() {
        let mut item = [0xa5a5a5a5u32; 0x140 / 4 + 1];
        for coordinate in [0, 0x10000, -0x2d0000, -0x2d0001,
                           i32::MAX, i32::MIN, i32::MIN.wrapping_sub(0x2d0000)] {
            unsafe { POSITION_WINDOW_COORDINATE = coordinate; }
            let limit = coordinate.wrapping_add(0x2d0000);
            for position in [i32::MIN, i32::MAX, -1, 0, 1,
                             limit.wrapping_sub(1), limit, limit.wrapping_add(1),
                             limit.wrapping_neg().wrapping_sub(1), limit.wrapping_neg(),
                             limit.wrapping_neg().wrapping_add(1)] {
                item[0x140 / 4] = position as u32;
                // Independent widened arithmetic models the two ARM wrap points.
                let upper = ((coordinate as i64 + 0x2d0000) as u32) as i32;
                let lower = (-(upper as i64) as u32) as i32;
                let expected = if position <= lower || position >= upper { 1 } else { 0 };
                assert_eq!(unsafe { item_outside_position_window(item.as_ptr()) }, expected,
                           "coordinate={coordinate:#x}, position={position:#x}");
            }
        }
    }
}
