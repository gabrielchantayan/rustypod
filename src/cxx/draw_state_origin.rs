//! `draw_state_set_origin` — original: `FUN_08264564` @ 0x08264564.
//! True extent: 12 bytes, 0x08264564..0x08264570; next function starts
//! with `push {r4,r5,r6,lr}`. Raw-image scan: 2 plain BL callers
//! (0x0826e2d4, 0x0826ebc0), 0 predicated BL callers; no outgoing calls.
//!
//! Raw words e580102c, e5802030, e12fff1e decode to
//! `str r1,[r0,#0x2c]; str r2,[r0,#0x30]; bx lr`. Stores the render-space
//! left/top origin without clipping, arithmetic, or validation. Both
//! callers supply transformed rectangle coordinates before intersection.
//! Deliberate deviations: none in memory behavior; the unused preserved
//! r0 is not exposed as a return value (the retail callers ignore it).
//! ARM codegen retains both stores at the exact offsets; LLVM adds a
//! frame-pointer prologue/epilogue instead of the retail leaf `bx lr`.

/// Stores the signed x/y origin verbatim, preserving every other field.
///
/// # Safety
/// `record` must be word-aligned and writable through byte offset 0x33.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_set_origin(record: *mut u8, left: i32, top: i32) {
    record.cast::<i32>().add(11).write(left);
    record.cast::<i32>().add(12).write(top);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_origin_without_clamping_or_touching_neighbors() {
        for (left, top) in [(0, 0), (-1, 17), (i32::MIN, i32::MAX), (i32::MAX, i32::MIN)] {
            let mut record = [0x5a5a_5a5au32; 18];
            let mut expected = record;
            expected[11] = left as u32;
            expected[12] = top as u32;
            unsafe { draw_state_set_origin(record.as_mut_ptr().cast(), left, top) };
            assert_eq!(record, expected);
            unsafe { draw_state_set_origin(record.as_mut_ptr().cast(), top, left) };
            expected[11] = top as u32;
            expected[12] = left as u32;
            assert_eq!(record, expected);
        }
    }
}
