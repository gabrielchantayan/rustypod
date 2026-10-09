//! Auto-hinter feature detection, retailOS 0x080dcb70, 192 bytes.
//! Raw A32: two plain BLs (0x080e2f5c, 0x080d93a4), zero predicated
//! BLs, then a tail B to 0x080d908c; next function starts at 0x080dcc30.
//! Capture the axis segment range before computing segments, propagate errors,
//! mark segments round unless a consecutive pair of on-curve points occurs,
//! link segments, then compute edges. Ghidra incorrectly inlines the tail target.
//! No algorithmic deviations; native pointer fields permit host classifier tests.

#[repr(C)]
struct Point {
    flags: u16,
    before_next: [u8; 30],
    next: *mut Point,
}

#[repr(C)]
struct Segment {
    flags: u8,
    before_first: [u8; 35],
    first: *mut Point,
    last: *mut Point,
    trailing: u32,
}

unsafe fn classify_segment(segment: *mut Segment) {
    let mut point = (*segment).first;
    let last = (*segment).last;
    let mut previous = (*point).flags & 3;
    (*segment).flags &= !1;
    while point != last {
        point = (*point).next;
        let current = (*point).flags & 3;
        if previous | current == 0 {
            break;
        }
        if point == last {
            (*segment).flags |= 1;
        }
        previous = current;
    }
}

type ComputeSegments = unsafe extern "C" fn(*mut u32, i32) -> i32;
type LinkSegments = unsafe extern "C" fn(*mut u32, i32);

/// Detect auto-hinter features for an axis.
///
/// # Safety
/// `hints` has the retailOS layout, `dimension` selects a valid axis, and all
/// segment/point ranges and firmware dependencies must be valid. The captured
/// segment allocation must survive compute-segments, as required by stock code.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn af_detect_features(hints: *mut u32, dimension: i32) -> i32 {
    #[cfg(target_os = "none")]
    {
        let axis = hints.add(12 + dimension as usize * 7);
        let mut segment = (*axis.add(2) as usize) as *mut Segment;
        let end = (segment as usize).wrapping_add((*axis).wrapping_mul(48) as usize);
        let compute_segments: ComputeSegments = core::mem::transmute(0x080e2f5cusize);
        let error = compute_segments(hints, dimension);
        if error != 0 {
            return error;
        }
        while (segment as usize) < end {
            classify_segment(segment);
            segment = segment.add(1);
        }
        let link_segments: LinkSegments = core::mem::transmute(0x080d93a4usize);
        link_segments(hints, dimension);
        let compute_edges: ComputeSegments = core::mem::transmute(0x080d908cusize);
        compute_edges(hints, dimension)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (hints, dimension);
        panic!("af_detect_features requires retailOS auto-hinter callees")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn classify(flags: &[u16], initial: u8) -> u8 {
        let mut points: std::vec::Vec<Point> = flags.iter().map(|&flags| Point {
            flags, before_next: [0; 30], next: core::ptr::null_mut(),
        }).collect();
        for index in 0..points.len() - 1 {
            points[index].next = unsafe { points.as_mut_ptr().add(index + 1) };
        }
        let mut segment = Segment {
            flags: initial, before_first: [0; 35], first: points.as_mut_ptr(),
            last: unsafe { points.as_mut_ptr().add(points.len() - 1) }, trailing: 0,
        };
        unsafe { classify_segment(&mut segment); }
        segment.flags
    }

    #[test]
    fn round_requires_reaching_last_without_adjacent_on_curve_points() {
        assert_eq!(classify(&[0, 1, 0, 2, 0], 0xa4), 0xa5);
        assert_eq!(classify(&[1, 0, 0, 2], 0xa5), 0xa4);
        assert_eq!(classify(&[1, 0, 0], 0xa5), 0xa4);
        assert_eq!(classify(&[0, 0], 0xa5), 0xa4);
    }

    #[test]
    fn singleton_clears_round_and_only_low_two_point_bits_matter() {
        for flags in [0, 1, 2, 3, 0xffff] {
            assert_eq!(classify(&[flags], 0xff), 0xfe);
        }
        assert_eq!(classify(&[4, 8], 0xff), 0xfe);
        assert_eq!(classify(&[4, 9], 0xfe), 0xff);
    }
}
