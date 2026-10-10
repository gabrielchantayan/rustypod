//! Reflected curve scan: `FUN_08075e04` at **0x08075e04**.
//! True extent: 140 bytes, [0x08075e04, 0x08075e90), next function PUSH.
//! Raw A32: two incoming plain BLs (0x080ec3f8, 0x080ecf84), zero
//! predicated BLs; one outgoing plain BL (0x08075e5c -> 0x080f0424).
//!
//! Negate the first three control-point Y words, and the fourth for signed
//! degree > 2. Scan with reflected, exchanged bounds. If the pending-start
//! byte changes from nonzero to zero, negate the current span record's word 5.
//! Finally negate the original first Y again, preserving the scan result.
//!
//! Deliberate deviations: the ascending scan remains in retailOS at its raw
//! verified address; host execution supplies it through the internal seam.
//! No algorithm/ABI deviation: Ghidra's void result is corrected to u32 (raw
//! epilogue preserves r0), pointer fields remain target-width u32 on hosts,
//! and negation wraps, including INT_MIN. Other Y words are not restored.

type CurveScan = unsafe extern "C" fn(*mut u32, i32, usize, i32, i32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn ascending_scan(state: *mut u32, degree: i32, subdivide: usize,
    lower: i32, upper: i32) -> u32 {
    core::mem::transmute::<usize, CurveScan>(0x080f_0424)(state, degree, subdivide, lower, upper)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn ascending_scan(_: *mut u32, _: i32, _: usize, _: i32, _: i32) -> u32 {
    panic!("reflected curve scan requires retailOS ascending scan 0x080f0424")
}

/// # Safety
/// `state` has at least 24 writable aligned words. Word 14 points to writable
/// control-point pairs (at least 3, or 4 for degree > 2). Word 23 points to a
/// writable span record with at least 6 words when byte 0x5a is consumed.
/// The state, degree and subdivision code address must be valid for the scan.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn curve_scan_reflected(state: *mut u32, degree: i32,
    subdivide: usize, lower: i32, upper: i32) -> u32 {
    scan_with(state, degree, subdivide, lower, upper, ascending_scan)
}

#[inline]
pub(super) unsafe fn scan_with(state: *mut u32, degree: i32, subdivide: usize,
    lower: i32, upper: i32, scan: CurveScan) -> u32 {
    let points = state.add(14).read() as usize as *mut i32;
    for index in [1, 3, 5] {
        points.add(index).write(points.add(index).read().wrapping_neg());
    }
    if degree > 2 {
        points.add(7).write(points.add(7).read().wrapping_neg());
    }
    let pending = state.cast::<u8>().add(0x5a).read();
    let result = scan(state, degree, subdivide, upper.wrapping_neg(), lower.wrapping_neg());
    if pending != 0 && state.cast::<u8>().add(0x5a).read() == 0 {
        let span = state.add(23).read() as usize as *mut i32;
        span.add(5).write(span.add(5).read().wrapping_neg());
    }
    points.add(1).write(points.add(1).read().wrapping_neg());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn advance(state: *mut u32, _: i32, _: usize, _: i32, _: i32) -> u32 {
        let points = state.add(14).read() as usize as *mut i32;
        // The real scan can advance the point link and consume the pending
        // start. Restoration must use the saved link but the current value.
        points.add(1).write(points.add(1).read().wrapping_add(7));
        state.add(14).write(points.add(8) as usize as u32);
        let replacement = state.add(21).read();
        state.add(23).write(replacement);
        let flags = state.cast::<u8>().add(0x5a);
        flags.write(state.cast::<u8>().add(0x59).read());
        0x8000_0062
    }

    #[test]
    fn signed_degree_wrapping_and_pending_start_transition() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::CURVE_SCAN_REFLECTED, 4096).expect("curve scan fixture");
        unsafe {
            let points = slab.cast::<i32>();
            let old_span = points.add(32);
            let new_span = points.add(48);
            for degree in [i32::MIN, -1, 0, 2, 3, i32::MAX] {
                for value in [i32::MIN, -19, 0, 23, i32::MAX] {
                    for (before, after) in [(0, 0), (0, 1), (1, 0), (2, 0), (1, 1)] {
                        let original = [11, value, 13, -5, 17, i32::MIN, 19, 29];
                        core::ptr::copy_nonoverlapping(original.as_ptr(), points, 8);
                        old_span.add(5).write(31);
                        new_span.add(5).write(value);
                        let mut state = [0u32; 24];
                        state[14] = points as usize as u32;
                        state[21] = new_span as usize as u32;
                        state[23] = old_span as usize as u32;
                        let bytes = state.as_mut_ptr().cast::<u8>();
                        bytes.add(0x59).write(after);
                        bytes.add(0x5a).write(before);
                        let result = scan_with(state.as_mut_ptr(), degree, 0, 0, 0, advance);
                        assert_eq!(result, 0x8000_0062);
                        let expected_first = (value as i64 - 7) as i32;
                        assert_eq!(core::slice::from_raw_parts(points, 8), &[
                            11, expected_first, 13, 5, 17, i32::MIN, 19,
                            if degree > 2 { -29 } else { 29 }]);
                        assert_eq!(old_span.add(5).read(), 31);
                        assert_eq!(new_span.add(5).read(), if before != 0 && after == 0 {
                            (-(value as i64)) as i32
                        } else { value });
                        assert_eq!(state[14], points.add(8) as usize as u32);
                    }
                }
            }
        }
    }
}
