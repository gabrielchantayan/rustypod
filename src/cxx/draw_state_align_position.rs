//! `draw_state_align_position` — original `FUN_08262d38` @ `0x08262d38`.
//! True extent: 56 bytes, `0x08262d38..0x08262d70`; the next entry stores
//! the style byte at +0x10 and returns. Raw ARM decoding verifies two inbound
//! plain BL sites (`0x082639f0`, `0x08263a5c`), zero predicated BL sites,
//! and zero outgoing calls.
//!
//! Adjusts the draw-state's first word (text write position) by the available
//! width minus text width. Mode 1 adds half the signed, wrapping difference,
//! rounded toward zero; mode 2 adds the whole difference. Other modes leave
//! memory untouched. Both additions wrap like ARM ADD. The text-layout caller
//! applies this adjustment before drawing the selected text range.
//!
//! Deliberate deviations: none in memory effects or arithmetic. Rust expresses
//! the predicated ARM center path as a match and signed division by two.

/// # Safety
/// For alignment 1 or 2, `write_position` must point to one aligned, readable
/// and writable u32. Other alignment values do not access the pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_align_position(
    write_position: *mut u32,
    available_width: i32,
    text_width: i32,
    alignment: u32,
) {
    let adjustment = match alignment {
        1 => available_width.wrapping_sub(text_width) / 2,
        2 => available_width.wrapping_sub(text_width),
        _ => return,
    };
    let position = write_position.read();
    write_position.write(position.wrapping_add(adjustment as u32));
}

#[cfg(test)]
mod tests {
    use super::draw_state_align_position;

    #[test]
    fn centered_signed_difference_rounds_toward_zero_and_wraps() {
        // Independent model: perform ARM-width subtraction in u32, interpret
        // its sign, then use wider signed arithmetic for truncation/addition.
        for available in [i32::MIN, -9, -1, 0, 1, 9, i32::MAX] {
            for text in [i32::MIN, -4, -1, 0, 1, 4, i32::MAX] {
                for initial in [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                    let difference = (available as u32).wrapping_sub(text as u32) as i32;
                    let expected = (initial as i64 + i64::from(difference) / 2) as u32;
                    let mut words = [initial, 0x1234_5678];
                    unsafe { draw_state_align_position(words.as_mut_ptr(), available, text, 1) };
                    assert_eq!(words, [expected, 0x1234_5678]);
                }
            }
        }
    }

    #[test]
    fn right_alignment_uses_full_difference_and_only_first_word() {
        for (initial, available, text, expected) in [
            (10, 9, 4, 15),
            (10, 4, 9, 5),
            (0, 4, 9, u32::MAX - 4),
            (u32::MAX, 1, 0, 0),
            (0, i32::MAX, -1, 0x8000_0000),
            (0, i32::MIN, 1, 0x7fff_ffff),
        ] {
            let mut words = [initial, 0x89ab_cdef];
            unsafe { draw_state_align_position(words.as_mut_ptr(), available, text, 2) };
            assert_eq!(words, [expected, 0x89ab_cdef]);
        }
    }

    #[test]
    fn other_modes_do_not_access_memory_even_with_overflowing_widths() {
        for mode in [0, 3, 4, 0x8000_0000, u32::MAX] {
            unsafe {
                draw_state_align_position(core::ptr::null_mut(), i32::MIN, 1, mode);
            }
            let mut position = 123;
            unsafe { draw_state_align_position(&mut position, i32::MAX, -1, mode) };
            assert_eq!(position, 123);
        }
    }
}
