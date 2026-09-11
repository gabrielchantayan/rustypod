//! Builds a render request from a compact descriptor.
//!
//! `render_request_from_descriptor` — original: `FUN_0826b2a8` @
//! **0x0826b2a8**, 112 bytes (`0x0826b2a8..0x0826b318`). The next separately
//! linked function begins with `push {r4,r5,r6,lr}` at 0x0826b318, so the
//! supplied Ghidra extent is exact. Decoding every ARM B/BL-immediate word in
//! `osos.dec` finds nine direct inbound call sites, all unconditional `bl`:
//! 0x08101378, 0x08175200, 0x081b7380, 0x081cbfac, 0x081cc240, 0x081ccc3c,
//! 0x081f8104, 0x081f81d0, and 0x08211378. There are no predicated `bl` forms
//! or tail `b` references.
//!
//! # Algorithm
//!
//! Copy the descriptor's top and left coordinates, then add its height and
//! width with ARM's wrapping arithmetic to form a QuickDraw [`Rect`]. Forward
//! that rectangle, descriptor words +0x00/+0x10/+0x20, the low halfword at
//! +0x24, and two literal zero arguments to the opaque retail initializer at
//! 0x0810e7d0. The initializer's identity is not inferred: raw decoding
//! establishes only this recovered ABI.
//!
//! # Deliberate deviations
//!
//! `FUN_0810e7d0` is not ported. Target builds call its retailOS entry
//! directly; host tests install a recording initializer through a seam. This
//! preserves the device dependency without inventing the callee's behavior.

#[cfg(not(target_os = "none"))]
use core::ptr;

use crate::ui::rect::Rect;

/// Compact source record consumed by [`render_request_from_descriptor`].
///
/// The port observes words +0x00, +0x08, +0x0c, +0x10, +0x18, +0x1c, +0x20,
/// and the low halfword at +0x24. The two remaining fields retain their
/// offsets without attributing an unverified meaning to them.
#[repr(C)]
pub struct RenderRequestDescriptor {
    pub source: u32,
    pub reserved_04: u32,
    pub height: i32,
    pub width: i32,
    pub source_parameter: u32,
    pub reserved_14: u32,
    pub left: i32,
    pub top: i32,
    pub options: u32,
    pub mode: u16,
    pub reserved_26: u16,
}

const _: () = assert!(core::mem::size_of::<RenderRequestDescriptor>() == 0x28);

/// ABI recovered from the direct call to unported `FUN_0810e7d0`.
pub type RenderRequestInitializer = unsafe extern "C" fn(
    request: *mut u8,
    bounds: *const Rect,
    source: u32,
    source_parameter: u32,
    options: u32,
    mode: u32,
    zero_0: u32,
    zero_1: u32,
);

#[cfg(target_os = "none")]
const RETAIL_RENDER_REQUEST_INITIALIZER: usize = 0x0810_e7d0;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn initialize_retail_render_request(
    request: *mut u8,
    bounds: *const Rect,
    source: u32,
    source_parameter: u32,
    options: u32,
    mode: u32,
) {
    let initializer: RenderRequestInitializer = core::mem::transmute(RETAIL_RENDER_REQUEST_INITIALIZER);
    initializer(request, bounds, source, source_parameter, options, mode, 0, 0);
}

/// Host seam for the unported retail initializer.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RenderRequestFromDescriptorOps {
    pub initialize: RenderRequestInitializer,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_render_request_initializer(
    _request: *mut u8,
    _bounds: *const Rect,
    _source: u32,
    _source_parameter: u32,
    _options: u32,
    _mode: u32,
    _zero_0: u32,
    _zero_1: u32,
) {
    panic!("FUN_0810e7d0 is unported; install RENDER_REQUEST_FROM_DESCRIPTOR_OPS");
}

/// Host default deliberately fails loudly rather than fabricating behavior for
/// the unresolved retail initializer.
#[cfg(not(target_os = "none"))]
pub static mut RENDER_REQUEST_FROM_DESCRIPTOR_OPS: RenderRequestFromDescriptorOps =
    RenderRequestFromDescriptorOps { initialize: missing_render_request_initializer };

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn render_request_initializer() -> RenderRequestInitializer {
    ptr::read_volatile(ptr::addr_of!(RENDER_REQUEST_FROM_DESCRIPTOR_OPS.initialize))
}

/// render_request_from_descriptor — original: `FUN_0826b2a8` @ 0x0826b2a8
/// (112 bytes; 9 direct unconditional `bl` call sites).
///
/// Form the request bounds from `descriptor`, then forward the observed fields
/// in the original register/stack argument order. The original has no NULL
/// guards and directly dereferences `descriptor`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.render_request_from_descriptor"
)]
#[inline(never)]
pub unsafe extern "C" fn render_request_from_descriptor(
    descriptor: *const RenderRequestDescriptor,
    request: *mut u8,
) {
    let descriptor = &*descriptor;
    let bounds = Rect {
        top: descriptor.top,
        left: descriptor.left,
        bottom: descriptor.top.wrapping_add(descriptor.height),
        right: descriptor.left.wrapping_add(descriptor.width),
    };

    #[cfg(target_os = "none")]
    initialize_retail_render_request(
        request,
        &bounds,
        descriptor.source,
        descriptor.source_parameter,
        descriptor.options,
        descriptor.mode as u32,
    );

    #[cfg(not(target_os = "none"))]
    render_request_initializer()(
        request,
        &bounds,
        descriptor.source,
        descriptor.source_parameter,
        descriptor.options,
        descriptor.mode as u32,
        0,
        0,
    );
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;
    use parking_lot::Mutex;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RecordedCall {
        request: *mut u8,
        bounds: Rect,
        source: u32,
        source_parameter: u32,
        options: u32,
        mode: u32,
        zero_0: u32,
        zero_1: u32,
    }

    static mut RECORDED_CALL: Option<RecordedCall> = None;

    unsafe extern "C" fn record_initializer(
        request: *mut u8,
        bounds: *const Rect,
        source: u32,
        source_parameter: u32,
        options: u32,
        mode: u32,
        zero_0: u32,
        zero_1: u32,
    ) {
        RECORDED_CALL = Some(RecordedCall {
            request,
            bounds: *bounds,
            source,
            source_parameter,
            options,
            mode,
            zero_0,
            zero_1,
        });
    }

    unsafe fn install_recording_initializer() -> RenderRequestInitializer {
        let previous = RENDER_REQUEST_FROM_DESCRIPTOR_OPS.initialize;
        RENDER_REQUEST_FROM_DESCRIPTOR_OPS.initialize = record_initializer;
        RECORDED_CALL = None;
        previous
    }

    unsafe fn restore_initializer(previous: RenderRequestInitializer) {
        RENDER_REQUEST_FROM_DESCRIPTOR_OPS.initialize = previous;
    }

    #[test]
    fn forwards_descriptor_fields_and_quickdraw_bounds() {
        let _guard = TEST_LOCK.lock();
        let previous = unsafe { install_recording_initializer() };
        let descriptor = RenderRequestDescriptor {
            source: 0x0123_4567,
            reserved_04: 0,
            height: 18,
            width: 32,
            source_parameter: 0x89ab_cdef,
            reserved_14: 0,
            left: -7,
            top: 11,
            options: 0x0bad_f00d,
            mode: 0x1234,
            reserved_26: 0xffff,
        };
        let request = 0x1234_5000usize as *mut u8;

        unsafe { render_request_from_descriptor(&descriptor, request) };

        assert_eq!(
            unsafe { RECORDED_CALL },
            Some(RecordedCall {
                request,
                bounds: Rect { top: 11, left: -7, bottom: 29, right: 25 },
                source: 0x0123_4567,
                source_parameter: 0x89ab_cdef,
                options: 0x0bad_f00d,
                mode: 0x1234,
                zero_0: 0,
                zero_1: 0,
            })
        );
        unsafe { restore_initializer(previous) };
    }

    #[test]
    fn wraps_extent_additions_and_reads_only_mode_low_halfword() {
        let _guard = TEST_LOCK.lock();
        let previous = unsafe { install_recording_initializer() };
        let descriptor = RenderRequestDescriptor {
            source: 1,
            reserved_04: 0,
            height: 5,
            width: 0x30,
            source_parameter: 2,
            reserved_14: 0,
            left: i32::MAX - 15,
            top: i32::MAX - 2,
            options: 3,
            mode: 0xabcd,
            reserved_26: 0x5678,
        };

        unsafe { render_request_from_descriptor(&descriptor, ptr::null_mut()) };

        let call = unsafe { RECORDED_CALL }.unwrap();
        assert_eq!(call.bounds, Rect {
            top: i32::MAX - 2,
            left: i32::MAX - 15,
            bottom: i32::MIN + 2,
            right: i32::MIN + 32,
        });
        assert_eq!(call.mode, 0xabcd);
        assert_eq!((call.zero_0, call.zero_1), (0, 0));
        unsafe { restore_initializer(previous) };
    }
}
