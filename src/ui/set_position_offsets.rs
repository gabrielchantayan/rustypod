//! `view_base_set_position_offsets` — `FUN_0826dd8c` @ 0x0826dd8c.
//! True size: 72 bytes, ending with the tail B at 0x0826ddd0; the next
//! function starts at 0x0826ddd4. Two inbound plain BL calls, zero predicated
//! BL calls, one inbound BNE; no outbound BL, one tail B to 0x0826db38.
//!
//! Select the first geometry pair whose two tags equal 0x80000002 after
//! clearing bit 0x20, otherwise try the second pair. Store x then y in the
//! selected pair, and always propagate geometry-changed redraw, even if
//! neither pair qualifies. Callers use these words as position offsets.
//! Deliberate deviations: the tail branch becomes a Rust call to the existing
//! port; target geometry remains six aligned u32 words per pair, not host
//! pointer-sized fields. Ghidra's inlined redraw body is not duplicated.

use crate::ui::geometry_changed::view_base_geometry_changed;
use crate::ui::view_base::ViewBase;

unsafe fn replace_position_offsets(geometry: *mut u32, x: u32, y: u32) {
    for base in [0usize, 6] {
        if geometry.add(base + 1).read() & !0x20 == 0x8000_0002
            && geometry.add(base + 4).read() & !0x20 == 0x8000_0002
        {
            geometry.add(base + 5).write(x);
            geometry.add(base + 2).write(y);
            break;
        }
    }
}

/// Replace eligible position offsets, then invalidate and notify geometry owners.
///
/// # Safety
/// `view` must be a writable, aligned ViewBase with valid bounds, parent and
/// virtual dispatch targets as required by `view_base_geometry_changed`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_base_set_position_offsets(view: *mut ViewBase, x: u32, y: u32) {
    replace_position_offsets(core::ptr::addr_of_mut!((*view).geometry).cast(), x, y);
    view_base_geometry_changed(view);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_selection_masks_only_bit_five_and_preserves_other_words() {
        let tags = [0x8000_0002, 0x8000_0022, 0x8000_0003, 2, 0x8000_0042];
        for first in tags {
            for second in tags {
                for third in tags {
                    for fourth in tags {
                        let mut words = [0x1234_5678; 12];
                        words[1] = first;
                        words[4] = second;
                        words[7] = third;
                        words[10] = fourth;
                        let mut expected = words;
                        let eligible = |a: u32, b: u32| {
                            (a == 0x8000_0002 || a == 0x8000_0022)
                                && (b == 0x8000_0002 || b == 0x8000_0022)
                        };
                        let selected = if eligible(first, second) { Some(0) }
                            else if eligible(third, fourth) { Some(6) } else { None };
                        if let Some(base) = selected {
                            expected[base + 5] = u32::MAX;
                            expected[base + 2] = 0x8000_0000;
                        }
                        unsafe { replace_position_offsets(words.as_mut_ptr(), u32::MAX, 0x8000_0000); }
                        assert_eq!(words, expected);
                    }
                }
            }
        }
    }
}

