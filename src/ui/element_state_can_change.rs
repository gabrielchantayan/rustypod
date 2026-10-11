//! Queries an element's state bits and whether they may change.
//!
//! Original `FUN_080545c4` @ 0x080545c4: 160 bytes through the next
//! prologue at 0x08054664 (152 instruction bytes and eight literal bytes).
//! Raw ARM words verify two outbound plain BLs, zero predicated BLs, and
//! two inbound plain BLs at 0x0806737c and 0x081790b4, zero predicated.
//! NULL, 'dev ', and 'tune' elements clear optional outputs and return zero.
//! Other kinds report +0x18c bits 0 and 1, then reject +0x18d bit 6 or
//! either playlist predicate (0x08059bc0, 0x08059d04), short-circuiting in
//! that order. Ghidra's indirect jumps are actually conditional pop {pc}.
//! Deviations: unported predicates remain fixed-address firmware boundaries;
//! host execution requiring them must install explicit predicate seams.

use core::ptr;

type ElementPredicate = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_predicate(_element: *mut u8) -> u32 {
    panic!("install element-state playlist predicate seams")
}

#[cfg(not(target_os = "none"))]
pub static mut ELEMENT_STATE_PLST_FLAG_10: ElementPredicate = missing_predicate;
#[cfg(not(target_os = "none"))]
pub static mut ELEMENT_STATE_PLST_FLAG_20: ElementPredicate = missing_predicate;

#[inline(always)]
unsafe fn plst_flag_10(element: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    let query: ElementPredicate = core::mem::transmute(0x0805_9bc0usize);
    #[cfg(not(target_os = "none"))]
    let query = ptr::read_volatile(ptr::addr_of!(ELEMENT_STATE_PLST_FLAG_10));
    query(element)
}

#[inline(always)]
unsafe fn plst_flag_20(element: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    let query: ElementPredicate = core::mem::transmute(0x0805_9d04usize);
    #[cfg(not(target_os = "none"))]
    let query = ptr::read_volatile(ptr::addr_of!(ELEMENT_STATE_PLST_FLAG_20));
    query(element)
}

/// # Safety
/// A non-NULL element must be aligned and readable through +0x19b, and
/// satisfy the firmware predicates' contracts. Non-NULL outputs must be
/// writable bytes; aliasing element bytes or each other is permitted.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_state_can_change(
    element: *mut u8, first_state: *mut u8, second_state: *mut u8,
) -> u32 {
    state_can_change(element, first_state, second_state, plst_flag_10, plst_flag_20)
}

#[inline(always)]
unsafe fn state_can_change(
    element: *mut u8, first_state: *mut u8, second_state: *mut u8,
    flag_10: unsafe fn(*mut u8) -> u32, flag_20: unsafe fn(*mut u8) -> u32,
) -> u32 {
    if element.is_null() || matches!(element.add(0x198).cast::<u32>().read(), 0x6465_7620 | 0x7475_6e65) {
        if !first_state.is_null() { first_state.write(0); }
        if !second_state.is_null() { second_state.write(0); }
        return 0;
    }
    if !first_state.is_null() { first_state.write(element.add(0x18c).read() & 1); }
    if !second_state.is_null() { second_state.write((element.add(0x18c).read() >> 1) & 1); }
    if element.add(0x18d).read() & 0x40 != 0 { return 0; }
    (flag_10(element) == 0 && flag_20(element) == 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn flag_10(element: *mut u8) -> u32 {
        element.add(0x1a0).write(element.add(0x1a0).read() + 1);
        element.add(0x1a2).read() as u32
    }
    unsafe fn flag_20(element: *mut u8) -> u32 {
        element.add(0x1a1).write(element.add(0x1a1).read() + 1);
        element.add(0x1a3).read() as u32
    }

    #[test]
    fn excluded_kinds_and_null_clear_optional_outputs() {
        unsafe {
            let mut outputs = [7, 9];
            assert_eq!(element_state_can_change(ptr::null_mut(), outputs.as_mut_ptr(), outputs.as_mut_ptr().add(1)), 0);
            assert_eq!(outputs, [0, 0]);
            for kind in [0x6465_7620u32, 0x7475_6e65] {
                let mut words = [0xffffffffu32; 0x1a4 / 4];
                words[0x198 / 4] = kind;
                outputs = [7, 9];
                assert_eq!(element_state_can_change(words.as_mut_ptr().cast(), outputs.as_mut_ptr(), ptr::null_mut()), 0);
                assert_eq!(outputs, [0, 9]);
            }
        }
    }

    #[test]
    fn reports_bits_before_inhibit_and_short_circuits_predicates() {
        unsafe {
            for bits in 0..=255u8 {
                for (inhibit, first, second, expected, calls) in [
                    (0x40, 0, 0, 0, [0, 0]), (0, 1, 0, 0, [1, 0]),
                    (0, 0, 1, 0, [1, 1]), (0x80, 0, 0, 1, [1, 1]),
                ] {
                    let mut words = [0u32; 0x1a4 / 4];
                    let element = words.as_mut_ptr().cast::<u8>();
                    element.add(0x18c).write(bits);
                    element.add(0x18d).write(inhibit);
                    element.add(0x1a2).write(first);
                    element.add(0x1a3).write(second);
                    let mut out = [9, 9];
                    assert_eq!(state_can_change(element, out.as_mut_ptr(), out.as_mut_ptr().add(1), flag_10, flag_20), expected);
                    assert_eq!(out, [bits & 1, (bits >> 1) & 1]);
                    assert_eq!([element.add(0x1a0).read(), element.add(0x1a1).read()], calls);
                }
            }
        }
    }

    #[test]
    fn output_aliases_preserve_sequential_reads_and_inhibit() {
        unsafe {
            let mut words = [0u32; 0x1a4 / 4];
            let element = words.as_mut_ptr().cast::<u8>();
            element.add(0x18c).write(3);
            let mut second = 9;
            assert_eq!(state_can_change(element, element.add(0x18c), &mut second, flag_10, flag_20), 1);
            assert_eq!(second, 0); // first write changes the second read
            element.add(0x18d).write(0x40);
            assert_eq!(state_can_change(element, element.add(0x18d), element.add(0x18d), flag_10, flag_20), 1);
            assert_eq!(element.add(0x18d).read(), 0); // outputs clear inhibit before testing it
            let mut out = 9;
            element.add(0x18c).write(1);
            assert_eq!(state_can_change(element, &mut out, &mut out, flag_10, flag_20), 1);
            assert_eq!(out, 0); // second output wins
        }
    }
}
