//! FreeType Type 1 glyph-outline builder point recorder.
//!
//! Type 1 charstring decoding keeps coordinates as either raw `FT_Pos`
//! values or 16.16 fixed-point values, selected by [`T1Builder::shift`].

use core::ffi::c_void;

use crate::ft::types::{FtBBox, FtOutline, FtVector};

/// `T1_BuilderRec` (psaux.h), sliced through `metrics_only` at +0x54.
///
/// The first six members are target pointers: each occupies four bytes on
/// ARM and naturally widens on the host.  Accesses use field names rather
/// than byte offsets, preserving the firmware layout without host overlap.
#[repr(C)]
pub struct T1Builder {
    pub memory: *mut c_void,
    pub face: *mut c_void,
    pub glyph: *mut c_void,
    pub loader: *mut c_void,
    pub base: *mut FtOutline,
    pub current: *mut FtOutline,
    pub last: FtVector,
    pub scale_x: i32,
    pub scale_y: i32,
    pub pos_x: i32,
    pub pos_y: i32,
    pub left_bearing: FtVector,
    pub advance: FtVector,
    pub bbox: FtBBox,
    pub parse_state: u8,
    pub load_points: u8,
    pub no_recurse: u8,
    pub shift: u8,
    pub metrics_only: u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(T1Builder, current)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(T1Builder, last)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x51] = [0; core::mem::offset_of!(T1Builder, load_points)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x53] = [0; core::mem::offset_of!(T1Builder, shift)];

/// Type 1 `t1_builder_add_point` (psaux.c) — original: `FUN_080bb65c` @
/// 0x080bb65c (104 bytes, 0x080bb65c..0x080bb65c0; the separate two-word
/// `ldr r0,[r0,#0x168] / bx lr` function starts at 0x080bb6c4). Eight `bl`
/// call sites verified by decoding every B/BL word in `osos.dec`: seven
/// unconditional `bl` in `t1_decoder_parse_charstrings` at 0x080de384,
/// 0x080de920, 0x080de944, 0x080dead4, 0x080deaf8, 0x080deb68, and
/// 0x080deb8c, plus one gated `bleq` at 0x080c4d0c.  The predicated caller
/// invokes this only after its preceding decoder operation returns zero;
/// it is not a NULL guard in this callee.
///
/// If `load_points` is set, records the signed `n_points` slot of `current`:
/// `shift` selects arithmetic `>> 16` conversion from 16.16 fixed point;
/// otherwise x and y are stored unchanged.  A nonzero `on_curve` selects tag
/// 1, while zero selects cubic-control tag 2, and the stored point becomes
/// `last`.  The unsigned-halfword increment of `n_points` is outside that
/// guard, so a counting-only pass advances it with i16 wrap even when it
/// stores nothing.  No pointer is NULL-checked, matching the raw ARM.
///
/// No deliberate deviations.
///
/// # Safety
/// `builder` and `builder->current` must be valid.  When `load_points != 0`,
/// the outline's points and tags arrays must contain the signed `n_points`
/// element.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn t1_builder_add_point(
    builder: *mut T1Builder,
    x: i32,
    y: i32,
    on_curve: i32,
) {
    let outline = (*builder).current;
    if (*builder).load_points != 0 {
        let index = (*outline).n_points as isize;
        let point = (*outline).points.offset(index);
        let mut x = x;
        let mut y = y;
        if (*builder).shift != 0 {
            x >>= 16;
            y >>= 16;
        }
        (*point).x = x;
        (*point).y = y;
        *(*outline).tags.offset(index) = if on_curve != 0 { 1 } else { 2 };
        (*builder).last = *point;
    }
    (*outline).n_points = (*outline).n_points.wrapping_add(1);
}

/// Firmware load address of the unported Type 1 contour finalizer
/// `t1_builder_add_contour` @ 0x080c9a6c.
pub const T1_BUILDER_ADD_CONTOUR_ADDRESS: usize = 0x080c_9a6c;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_t1_builder_add_contour(builder: *mut T1Builder) -> i32 {
    let add_contour: unsafe extern "C" fn(*mut T1Builder) -> i32 =
        core::mem::transmute(T1_BUILDER_ADD_CONTOUR_ADDRESS);
    add_contour(builder)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_t1_builder_add_contour(_builder: *mut T1Builder) -> i32 {
    panic!("t1_builder_start_point requires t1_builder_add_contour 0x080c9a6c")
}

/// Direct-call boundary for the unported `t1_builder_add_contour` @
/// 0x080c9a6c. It finalizes the preceding outline contour and grows
/// storage if required.
#[cfg(target_os = "none")]
pub static mut T1_BUILDER_ADD_CONTOUR: unsafe extern "C" fn(*mut T1Builder) -> i32 =
    firmware_t1_builder_add_contour;

#[cfg(not(target_os = "none"))]
pub static mut T1_BUILDER_ADD_CONTOUR: unsafe extern "C" fn(*mut T1Builder) -> i32 =
    missing_t1_builder_add_contour;

/// Firmware load address of the unported capacity-checking on-curve point
/// wrapper at 0x080c4ce0.
pub const T1_BUILDER_CHECK_AND_ADD_ON_CURVE_POINT_ADDRESS: usize = 0x080c_4ce0;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_t1_builder_check_and_add_on_curve_point(
    builder: *mut T1Builder,
    x: i32,
    y: i32,
) -> i32 {
    let add_point: unsafe extern "C" fn(*mut T1Builder, i32, i32) -> i32 =
        core::mem::transmute(T1_BUILDER_CHECK_AND_ADD_ON_CURVE_POINT_ADDRESS);
    add_point(builder, x, y)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_t1_builder_check_and_add_on_curve_point(
    _builder: *mut T1Builder,
    _x: i32,
    _y: i32,
) -> i32 {
    panic!("t1_builder_start_point requires point wrapper 0x080c4ce0")
}

/// Direct-call boundary for the unported 0x080c4ce0 wrapper. It checks
/// capacity for one point, then invokes [`t1_builder_add_point`] with
/// `on_curve = 1` when that check succeeds.
#[cfg(target_os = "none")]
pub static mut T1_BUILDER_CHECK_AND_ADD_ON_CURVE_POINT:
    unsafe extern "C" fn(*mut T1Builder, i32, i32) -> i32 =
    firmware_t1_builder_check_and_add_on_curve_point;

#[cfg(not(target_os = "none"))]
pub static mut T1_BUILDER_CHECK_AND_ADD_ON_CURVE_POINT:
    unsafe extern "C" fn(*mut T1Builder, i32, i32) -> i32 =
    missing_t1_builder_check_and_add_on_curve_point;

/// Type 1 `t1_builder_start_point` (t1gload.c) — original:
/// `FUN_080c9af4` @ 0x080c9af4 (88 bytes,
/// 0x080c9af4..0x080c9b48; the following `mov r3,r0 / mov r0,r1` starts
/// a separate function at 0x080c9b4c). Seven unconditional `bl` call
/// sites are verified by decoding every ARM B/BL word in `osos.dec`:
/// 0x080de328, 0x080de898, 0x080de8e8, 0x080de96c, 0x080dea94,
/// 0x080deb30, and 0x080debb8. There are no predicated call forms and
/// no raw DATA word references to this entry.
///
/// A builder with `parse_state == 3` already has a path and succeeds without
/// touching it. Only state 2 (a preceding `moveto`) may begin a path; every
/// other state returns syntax error 3. The accepted path becomes state 3,
/// finalizes its preceding contour, then checks capacity and records `(x,y)`
/// as an on-curve point. Errors from either callee propagate, and the state
/// remains 3 after a contour or capacity failure.
///
/// Deliberate deviation: after the contour call, the ARM restores its
/// arguments and tail-branches to the unported 0x080c4ce0 wrapper. Rust
/// returns the direct seam call's value; this preserves the wrapper's
/// observable error and point-recording behavior without reifying the tail
/// branch.
///
/// # Safety
/// `builder` and the structures required by the selected seam must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn t1_builder_start_point(
    builder: *mut T1Builder,
    x: i32,
    y: i32,
) -> i32 {
    if (*builder).parse_state == 3 {
        return 0;
    }
    if (*builder).parse_state != 2 {
        return 3;
    }
    (*builder).parse_state = 3;
    let add_contour = core::ptr::addr_of!(T1_BUILDER_ADD_CONTOUR).read_volatile();
    let error = add_contour(builder);
    if error != 0 {
        return error;
    }
    let add_point =
        core::ptr::addr_of!(T1_BUILDER_CHECK_AND_ADD_ON_CURVE_POINT).read_volatile();
    add_point(builder, x, y)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static START_POINT_LOCK: Mutex<()> = Mutex::new(());
    static ADD_CONTOUR_CALLS: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());
    static ADD_POINT_CALLS: Mutex<std::vec::Vec<(usize, i32, i32)>> =
        Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn record_add_contour(builder: *mut T1Builder) -> i32 {
        ADD_CONTOUR_CALLS.lock().push(builder as usize);
        0
    }

    unsafe extern "C" fn fail_add_contour(builder: *mut T1Builder) -> i32 {
        ADD_CONTOUR_CALLS.lock().push(builder as usize);
        0x23
    }

    unsafe extern "C" fn record_add_point(builder: *mut T1Builder, x: i32, y: i32) -> i32 {
        ADD_POINT_CALLS.lock().push((builder as usize, x, y));
        0
    }

    unsafe extern "C" fn fail_add_point(builder: *mut T1Builder, x: i32, y: i32) -> i32 {
        ADD_POINT_CALLS.lock().push((builder as usize, x, y));
        0x2a
    }

    fn with_start_point_seams(
        add_contour: unsafe extern "C" fn(*mut T1Builder) -> i32,
        add_point: unsafe extern "C" fn(*mut T1Builder, i32, i32) -> i32,
        body: impl FnOnce(),
    ) {
        let _lock = START_POINT_LOCK.lock();
        ADD_CONTOUR_CALLS.lock().clear();
        ADD_POINT_CALLS.lock().clear();
        let saved_contour =
            unsafe { core::ptr::addr_of!(T1_BUILDER_ADD_CONTOUR).read_volatile() };
        let saved_point = unsafe {
            core::ptr::addr_of!(T1_BUILDER_CHECK_AND_ADD_ON_CURVE_POINT).read_volatile()
        };
        unsafe {
            core::ptr::addr_of_mut!(T1_BUILDER_ADD_CONTOUR).write_volatile(add_contour);
            core::ptr::addr_of_mut!(T1_BUILDER_CHECK_AND_ADD_ON_CURVE_POINT)
                .write_volatile(add_point);
        }
        body();
        unsafe {
            core::ptr::addr_of_mut!(T1_BUILDER_ADD_CONTOUR).write_volatile(saved_contour);
            core::ptr::addr_of_mut!(T1_BUILDER_CHECK_AND_ADD_ON_CURVE_POINT)
                .write_volatile(saved_point);
        }
    }

    struct Fixture {
        points: [FtVector; 8],
        tags: [u8; 8],
        outline: FtOutline,
        builder: T1Builder,
    }

    impl Fixture {
        fn new(n_points: i16, load_points: u8, shift: u8) -> std::boxed::Box<Self> {
            let mut fixture = std::boxed::Box::new(Self {
                points: [FtVector { x: -777, y: 888 }; 8],
                tags: [0xaa; 8],
                outline: FtOutline {
                    n_contours: 0,
                    n_points,
                    points: core::ptr::null_mut(),
                    tags: core::ptr::null_mut(),
                    contours: core::ptr::null_mut(),
                    flags: 0,
                },
                builder: T1Builder {
                    memory: core::ptr::null_mut(),
                    face: core::ptr::null_mut(),
                    glyph: core::ptr::null_mut(),
                    loader: core::ptr::null_mut(),
                    base: core::ptr::null_mut(),
                    current: core::ptr::null_mut(),
                    last: FtVector { x: -1, y: -1 },
                    scale_x: 0xdeadbeef_u32 as i32,
                    scale_y: 0xdeadbeef_u32 as i32,
                    pos_x: 0xdeadbeef_u32 as i32,
                    pos_y: 0xdeadbeef_u32 as i32,
                    left_bearing: FtVector { x: -777, y: 888 },
                    advance: FtVector { x: -777, y: 888 },
                    bbox: FtBBox { x_min: -1, y_min: -2, x_max: 3, y_max: 4 },
                    parse_state: 0xbe,
                    load_points,
                    no_recurse: 0xde,
                    shift,
                    metrics_only: 0xad,
                },
            });
            fixture.outline.points = fixture.points.as_mut_ptr();
            fixture.outline.tags = fixture.tags.as_mut_ptr();
            fixture.builder.current = &mut fixture.outline;
            fixture
        }
    }

    #[test]
    fn shifted_point_floors_fixed_coordinates_and_sets_on_curve_tag() {
        let mut fixture = Fixture::new(0, 1, 1);
        unsafe { t1_builder_add_point(&mut fixture.builder, 0x0002_8000, -0x0001_8000, -7) };
        assert_eq!(fixture.points[0], FtVector { x: 2, y: -2 });
        assert_eq!(fixture.tags[0], 1);
        assert_eq!(fixture.builder.last, FtVector { x: 2, y: -2 });
        assert_eq!(fixture.outline.n_points, 1);
    }

    #[test]
    fn unshifted_point_preserves_raw_coordinates_and_cubic_tag() {
        let mut fixture = Fixture::new(0, 1, 0);
        unsafe { t1_builder_add_point(&mut fixture.builder, -31, 0x1234_5678, 0) };
        assert_eq!(fixture.points[0], FtVector { x: -31, y: 0x1234_5678 });
        assert_eq!(fixture.tags[0], 2);
        assert_eq!(fixture.builder.last, FtVector { x: -31, y: 0x1234_5678 });
    }

    #[test]
    fn counting_pass_does_not_store_but_advances_count() {
        let mut fixture = Fixture::new(3, 0, 1);
        unsafe { t1_builder_add_point(&mut fixture.builder, 0x0005_0000, 0x0006_0000, 1) };
        assert_eq!(fixture.outline.n_points, 4);
        assert!(fixture.points.iter().all(|point| *point == FtVector { x: -777, y: 888 }));
        assert!(fixture.tags.iter().all(|tag| *tag == 0xaa));
        assert_eq!(fixture.builder.last, FtVector { x: -1, y: -1 });
    }

    #[test]
    fn negative_count_indexes_backwards() {
        let mut fixture = Fixture::new(-1, 1, 0);
        fixture.outline.points = unsafe { fixture.points.as_mut_ptr().add(1) };
        fixture.outline.tags = unsafe { fixture.tags.as_mut_ptr().add(1) };
        unsafe { t1_builder_add_point(&mut fixture.builder, 3, 4, 1) };
        assert_eq!(fixture.points[0], FtVector { x: 3, y: 4 });
        assert_eq!(fixture.tags[0], 1);
        assert_eq!(fixture.outline.n_points, 0);
    }

    #[test]
    fn point_count_wraps_as_a_signed_halfword() {
        let mut fixture = Fixture::new(i16::MAX, 0, 0);
        unsafe { t1_builder_add_point(&mut fixture.builder, 0, 0, 1) };
        assert_eq!(fixture.outline.n_points, i16::MIN);
    }

    #[test]
    fn existing_path_returns_success_without_calling_seams() {
        let mut fixture = Fixture::new(0, 1, 0);
        fixture.builder.parse_state = 3;
        with_start_point_seams(record_add_contour, record_add_point, || {
            let rc = unsafe { t1_builder_start_point(&mut fixture.builder, 9, -4) };
            assert_eq!(rc, 0);
            assert!(ADD_CONTOUR_CALLS.lock().is_empty());
            assert!(ADD_POINT_CALLS.lock().is_empty());
        });
        assert_eq!(fixture.builder.parse_state, 3);
    }

    #[test]
    fn state_without_moveto_returns_syntax_error_without_calling_seams() {
        let mut fixture = Fixture::new(0, 1, 0);
        fixture.builder.parse_state = 1;
        with_start_point_seams(record_add_contour, record_add_point, || {
            let rc = unsafe { t1_builder_start_point(&mut fixture.builder, 9, -4) };
            assert_eq!(rc, 3);
            assert!(ADD_CONTOUR_CALLS.lock().is_empty());
            assert!(ADD_POINT_CALLS.lock().is_empty());
        });
        assert_eq!(fixture.builder.parse_state, 1);
    }

    #[test]
    fn contour_failure_starts_path_and_propagates_without_point_call() {
        let mut fixture = Fixture::new(0, 1, 0);
        fixture.builder.parse_state = 2;
        let builder = &mut fixture.builder as *mut T1Builder as usize;
        with_start_point_seams(fail_add_contour, record_add_point, || {
            let rc = unsafe { t1_builder_start_point(&mut fixture.builder, 0x1234, -0x5678) };
            assert_eq!(rc, 0x23);
            assert_eq!(ADD_CONTOUR_CALLS.lock().as_slice(), [builder]);
            assert!(ADD_POINT_CALLS.lock().is_empty());
        });
        assert_eq!(fixture.builder.parse_state, 3);
    }

    #[test]
    fn starts_path_then_forwards_coordinates_and_point_error() {
        let mut fixture = Fixture::new(0, 1, 0);
        fixture.builder.parse_state = 2;
        let builder = &mut fixture.builder as *mut T1Builder as usize;
        with_start_point_seams(record_add_contour, fail_add_point, || {
            let rc = unsafe {
                t1_builder_start_point(&mut fixture.builder, 0x1234_5678, -0x1234_567)
            };
            assert_eq!(rc, 0x2a);
            assert_eq!(ADD_CONTOUR_CALLS.lock().as_slice(), [builder]);
            assert_eq!(
                ADD_POINT_CALLS.lock().as_slice(),
                [(builder, 0x1234_5678, -0x1234_567)]
            );
        });
        assert_eq!(fixture.builder.parse_state, 3);
    }
}
