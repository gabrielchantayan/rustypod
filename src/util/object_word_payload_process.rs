//! In-place selected-value adjustment of an object's four-word payload.

/// Verified ABI of selected_value_pair_adjust at 0x0829b764 (identified).
pub type SelectedValuePairAdjust = unsafe extern "C" fn(*mut u32, u32, *const u32, *mut u32, i32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_selected_value_pair_adjust(object: *mut u32, selection: u32, input: *const u32, output: *mut u32, multiplier: i32) {
    let adjust: SelectedValuePairAdjust = unsafe { core::mem::transmute(0x0829_b764usize) };
    unsafe { adjust(object, selection, input, output, multiplier) };
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selected_value_pair_adjust(_: *mut u32, _: u32, _: *const u32, _: *mut u32, _: i32) {
    panic!("object_word_payload_process requires selected_value_pair_adjust at 0x0829b764")
}
#[cfg(target_os = "none")]
const DEFAULT_ADJUST: SelectedValuePairAdjust = firmware_selected_value_pair_adjust;
#[cfg(not(target_os = "none"))]
const DEFAULT_ADJUST: SelectedValuePairAdjust = missing_selected_value_pair_adjust;

/// Unported pair adjustment; ARM calls the verified retail entry.
pub static mut SELECTED_VALUE_PAIR_ADJUST: SelectedValuePairAdjust = DEFAULT_ADJUST;

/// object_word_payload_process — FUN_0829b804 @ 0x0829b804, exactly 80 bytes
/// through 0x0829b850; the next real function starts at 0x0829b854.
/// Raw A32 words verify two outbound plain BLs to selected_value_pair_adjust,
/// zero predicated BLs, and two inbound plain BLs (0x0829b454, 0x0829b4b0).
/// If object word 11 is zero, leaves the payload untouched. Otherwise adjusts
/// each two-word pair in place with multiplier -1, reloading word 11 after
/// the first call even if it becomes zero. No second selection guard is added.
/// Deliberate deviations: the identified but unported pair adjuster is an
/// explicit firmware seam; its unresolved tail behavior is not reimplemented.
/// Target word indices preserve the layout on 64-bit hosts.
///
/// # Safety
/// `object` permits an aligned read of word 11 and is valid for the adjuster.
/// When that word is nonzero, `words` contains four aligned writable words;
/// both pointers and the selection must satisfy the firmware callee contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_word_payload_process(object: *mut u32, words: *mut u32) {
    let selection = unsafe { object.add(11).read() };
    if selection == 0 { return; }
    let adjust = unsafe { core::ptr::addr_of_mut!(SELECTED_VALUE_PAIR_ADJUST).read_volatile() };
    unsafe { process_selected_pairs(object, words, selection, adjust) };
}

unsafe fn process_selected_pairs(object: *mut u32, words: *mut u32, selection: u32, adjust: SelectedValuePairAdjust) {
    unsafe { adjust(object, selection, words, words, -1) };
    let selection = unsafe { object.add(11).read() };
    let second = unsafe { words.add(2) };
    unsafe { adjust(object, selection, second, second, -1) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_selection_does_not_touch_even_a_null_payload() {
        let mut object = [u32::MAX; 12];
        object[11] = 0;
        unsafe { object_word_payload_process(object.as_mut_ptr(), core::ptr::null_mut()) };
        assert_eq!(object[11], 0);
        assert!(object[..11].iter().all(|&word| word == u32::MAX));
    }

    // A deterministic pair transform exercises sequencing, aliasing, and
    // mutation of the selection by the first call, not its unknown algorithm.
    unsafe extern "C" fn adjust_model(object: *mut u32, selection: u32, input: *const u32, output: *mut u32, multiplier: i32) {
        assert_eq!(input, output as *const u32);
        assert_eq!(multiplier, -1);
        unsafe {
            output.write(input.read().wrapping_sub(selection));
            output.add(1).write(input.add(1).read().wrapping_add(selection));
            object.add(11).write(object.read());
        }
    }

    #[test]
    fn reloads_selection_including_zero_and_adjusts_both_pairs() {
        for next_selection in [0, 7, u32::MAX] {
            let mut object = [0u32; 12];
            object[0] = next_selection;
            object[11] = 5;
            let mut words = [2u32, u32::MAX, 11, 13];
            unsafe { process_selected_pairs(object.as_mut_ptr(), words.as_mut_ptr(), 5, adjust_model) };
            assert_eq!(words, [2u32.wrapping_sub(5), 4, 11u32.wrapping_sub(next_selection), 13u32.wrapping_add(next_selection)]);
            assert_eq!(object[11], next_selection);
        }
    }
}
