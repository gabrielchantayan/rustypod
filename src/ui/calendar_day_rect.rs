//! Calendar day-cell geometry: FUN_0829b904 at 0x0829b904, 196 bytes.
//! Raw A32 extent ends at the next function's push at 0x0829b9c8.
//! Verified calls: six plain body BLs, one predicated BLNE; two plain
//! inbound BLs (0x08140c7c, 0x08141478), no predicated inbound BLs.
//!
//! Divide the view rectangle into seven columns, center its leftover width,
//! normalize the month's first weekday relative to the configured week start,
//! and place the one-based day in rows spaced 34 pixels apart. Output cells
//! have height 35 and width column_width + 1. The special difference of seven
//! retains the accessor's weekday rather than reducing it to zero.
//!
//! Deviations: constant divisions are expressed in Rust rather than invoking
//! ADS quotient/remainder ABIs. All ARM arithmetic wraps. The month's first
//! weekday is computed by the canonical Rust port.

use super::rect::{Rect, rect_width, rect_offset};

use crate::time::month_first_weekday::month_first_weekday;

type MonthFirstWeekday = unsafe extern "C" fn(u32) -> u32;

/// Write the calendar cell for a one-based day.
///
/// # Safety
/// `view` is word-aligned and readable through +0x103, with a valid target-width
/// pointer at +0xec to an owner readable through +0xeb. `out` is a writable
/// Rect; the month's date word at owner+0xe8 must be valid for retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn calendar_day_rect(view: *const u32, day: i32, out: *mut Rect) {
    day_rect_with(view, day, out, month_first_weekday);
}

unsafe fn day_rect_with(view: *const u32, day: i32, out: *mut Rect, weekday: MonthFirstWeekday) {
    let bounds = view.add(0x80 / 4).cast::<Rect>();
    let column_width = rect_width(bounds) / 7;
    let leftover = rect_width(bounds).wrapping_sub(column_width.wrapping_mul(7));
    let owner = view.add(0xec / 4).read() as usize as *const u32;
    let first = weekday(owner.add(0xe8 / 4).read());
    let difference = first.wrapping_sub(view.add(0x100 / 4).read());
    let offset = if difference == 7 { first } else { difference % 7 };
    let index = day.wrapping_add(offset as i32).wrapping_sub(1);
    let row = index / 7;
    let column = index.wrapping_sub(row.wrapping_mul(7));
    out.write(bounds.read());
    let dx = column_width.wrapping_mul(column).wrapping_add(leftover / 2).wrapping_add(2);
    let dy = row.wrapping_mul(34).wrapping_add(view.add(0xf8 / 4).read() as i32);
    rect_offset(out, dx, dy);
    (*out).right = (*out).left.wrapping_add(column_width).wrapping_add(1);
    (*out).bottom = (*out).top.wrapping_add(35);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn first_weekday(date: u32) -> u32 { date }

    #[test]
    fn day_cells_cover_week_start_rows_negative_width_and_wrapping() {
        unsafe {
            let Some(slab) = crate::testing::try_map_u32_slab(
                crate::testing::hints::CALENDAR_DAY_RECT, 0x1000,
            ) else { return };
            let view = slab.cast::<u32>();
            let owner = slab.add(0x400).cast::<u32>();
            view.add(0xec / 4).write(owner as usize as u32);
            for &(width, first, start, day, top, left, y) in &[
                (100i32, 1u32, 1u32, 1i32, 10i32, 20i32, 5i32),
                (100, 7, 0, 1, 10, 20, 5),
                (101, 7, 1, 2, 10, 20, 5),
                (-101, 1, 1, 0, -10, -20, -5),
                (100, 1, 7, 31, 0, 0, 0),
                (100, 1, 1, i32::MAX, i32::MAX, i32::MAX, i32::MAX),
            ] {
                let bounds = Rect { top, left, bottom: top.wrapping_add(200), right: left.wrapping_add(width) };
                view.add(0x80 / 4).cast::<Rect>().write(bounds);
                view.add(0x100 / 4).write(start);
                view.add(0xf8 / 4).write(y as u32);
                owner.add(0xe8 / 4).write(first);
                let mut actual = Rect::default();
                day_rect_with(view, day, &mut actual, first_weekday);
                // Independent widened arithmetic with explicit ARM word reduction.
                let delta = first.wrapping_sub(start);
                let offset = if delta == 7 { first } else { delta % 7 };
                let index = (day as i64 + offset as i64 - 1) as i32 as i64;
                let row = index / 7;
                let col = index % 7;
                let cell_width = width as i64 / 7;
                let expected_left = (left as i64 + cell_width * col + (width as i64 % 7) / 2 + 2) as i32;
                let expected_top = (top as i64 + row * 34 + y as i64) as i32;
                assert_eq!(actual, Rect {
                    top: expected_top, left: expected_left,
                    bottom: expected_top.wrapping_add(35),
                    right: expected_left.wrapping_add(cell_width as i32).wrapping_add(1),
                });
                assert_eq!(view.add(0x80 / 4).cast::<Rect>().read(), bounds);
            }
        }
    }
}
