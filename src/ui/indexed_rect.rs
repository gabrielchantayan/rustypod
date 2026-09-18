//! Indexed rectangle lookup from a UI object's geometry table.
//!
//! Original: `FUN_0816b52c` @ 0x0816b52c (52 bytes, including its tail
//! branch to `rect_offset`). Raw decoding establishes one tail `b`, no
//! internal `bl`, and four inbound plain `bl` calls with no predicated calls.
//! The function selects a four-word QuickDraw rectangle from the table at
//! `object+0xec`, indexed relative to `object+0xe8`, copies it to `out_rect`,
//! then translates it by the x/y offsets at `object+0xf0/+0xf4`.
//!
//! Deliberate deviation: the retail tail branch becomes a Rust call to the
//! already-ported [`super::rect::rect_offset`]; it preserves the same
//! target-width wrapping coordinate arithmetic.

use super::rect::{rect_offset, Rect};

/// indexed_rect_copy_offset — original: `FUN_0816b52c` @ 0x0816b52c (52 bytes).
///
/// `object` is an opaque target-layout object: all four fields used here are
/// 32-bit words, so their offsets remain correct on 64-bit host tests.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_rect_copy_offset(
    object: *const u32,
    index: i32,
    out_rect: *mut Rect,
) {
    let first_index = *object.add(0x3a) as i32;
    let table = *object.add(0x3b) as usize as *const Rect;
    let source = table.offset(index.wrapping_sub(first_index) as isize);

    core::ptr::write(out_rect, core::ptr::read(source));
    rect_offset(
        out_rect,
        *object.add(0x3c) as i32,
        *object.add(0x3d) as i32,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn selects_relative_rect_and_applies_wrapping_origin() {
        let Some(table_memory) = try_map_u32_slab(hints::INDEXED_RECT_COPY_OFFSET, 4096) else {
            return;
        };
        let table = table_memory as *mut Rect;
        unsafe {
            core::ptr::write(table.add(0), Rect { top: 1, left: 2, bottom: 3, right: 4 });
            core::ptr::write(table.add(1), Rect { top: -20, left: 30, bottom: 40, right: -50 });
            core::ptr::write(table.add(2), Rect {
                top: i32::MAX,
                left: i32::MIN,
                bottom: -1,
                right: 0,
            });

            let mut object = [0u32; 62];
            object[0x3a] = 17;
            object[0x3b] = table as u32;
            object[0x3c] = 0xffff_ffff;
            object[0x3d] = 2;

            let mut out = Rect::default();
            indexed_rect_copy_offset(object.as_ptr(), 18, &mut out);
            assert_eq!(out, Rect { top: -18, left: 29, bottom: 42, right: -51 });

            object[0x3c] = 1;
            object[0x3d] = 1;
            indexed_rect_copy_offset(object.as_ptr(), 19, &mut out);
            assert_eq!(out, Rect {
                top: i32::MIN,
                left: i32::MIN.wrapping_add(1),
                bottom: 0,
                right: 1,
            });
        }
    }
}
