//! `ui_element_word_pair_set` — `FUN_08067bb8` @ 0x08067bb8.
//! True extent: [0x08067bb8, 0x08067bc4), 12 bytes. Raw A32 words are
//! e580104c e5802050 e12fff1e; the next function begins with e92d4070.
//! Whole-image decoding verifies two incoming plain BLs (0x08058994 and
//! 0x08068f48), zero predicated incoming BLs, and no outgoing BLs.
//!
//! Store the two supplied words at UI element +0x4c and +0x50, in that
//! order, without inspecting their values or the previous fields. The callers
//! initialize a newly obtained element, preserving +0x4c across recreation
//! in one caller. Stronger field meanings are not established.
//! Deliberate deviations: none; u32 word indices retain the target layout
//! on hosts. The incidental unchanged r0 is not a C return value; callers
//! reload their element pointer after the call.

/// # Safety
/// `element` must point to aligned writable storage through byte +0x53.
/// No NULL check, ownership transfer, or referenced-object access is performed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_word_pair_set(element: *mut u32, first: u32, second: u32) {
    unsafe {
        element.add(0x4c / 4).write(first);
        element.add(0x50 / 4).write(second);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_both_fields_without_touching_neighbors() {
        for (first, second) in [(0, 0), (u32::MAX, 0), (0, u32::MAX),
                                (0x8000_0000, 0x7fff_ffff), (0x1234_5678, 0x8765_4321)] {
            let mut element = [0xa5a5_5a5a; 24];
            let mut expected = element;
            expected[19] = first;
            expected[20] = second;
            unsafe { ui_element_word_pair_set(element.as_mut_ptr(), first, second) };
            assert_eq!(element, expected);
            unsafe { ui_element_word_pair_set(element.as_mut_ptr(), second, first) };
            expected[19] = second;
            expected[20] = first;
            assert_eq!(element, expected);
        }
    }
}
