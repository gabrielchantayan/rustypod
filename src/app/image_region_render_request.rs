//! Builds a render request for an image region.
//!
//! Original `FUN_08211310` @ **0x08211310**, 120 bytes, ending at
//! 0x08211388 (the next function's push). Whole-image ARM decoding verifies
//! two inbound plain BLs (0x081141f4, 0x0811421c), zero predicated BLs;
//! the body has three plain outbound BLs and zero predicated BLs.
//!
//! Return zero when the source handle at +4 is zero. Otherwise resolve that
//! handle through retail 0x081b5414, build the signed-halfword format's
//! descriptor, replace height/width with wrapping region differences and
//! top/left with the region origin, then construct the request and return one.
//!
//! Deliberate deviations: reuse the descriptor port's documented zero filling
//! of originally unstored bytes. The unobserved reserved word +4 is zeroed.
//! The source resolver remains a retail call, not an invented implementation;
//! host callers install its recovered ABI through the seam below.

use super::image_format::image_format_descriptor;
use crate::ui::render_request_from_descriptor::{RenderRequestDescriptor, render_request_from_descriptor};

pub type ImageSourceResolve = unsafe extern "C" fn(u32) -> u32;
type Submit = unsafe extern "C" fn(*const RenderRequestDescriptor, *mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_source_resolver(_: u32) -> u32 {
    panic!("install IMAGE_REGION_SOURCE_RESOLVE for retail 0x081b5414")
}

#[cfg(not(target_os = "none"))]
pub static mut IMAGE_REGION_SOURCE_RESOLVE: ImageSourceResolve = missing_source_resolver;

unsafe fn build_region_request(record: *const u32, request: *mut u8,
    resolve: ImageSourceResolve, submit: Submit) -> u32 {
    let handle = record.add(1).read();
    if handle == 0 { return 0; }
    let source = resolve(handle);
    let format = record.add(2).cast::<i16>().read() as i32 as u32;
    let mut storage = core::mem::MaybeUninit::<RenderRequestDescriptor>::uninit();
    let descriptor = storage.as_mut_ptr();
    core::ptr::addr_of_mut!((*descriptor).source).write(source);
    core::ptr::addr_of_mut!((*descriptor).reserved_04).write(0);
    image_format_descriptor(core::ptr::addr_of_mut!((*descriptor).height).cast(), format);
    let mut descriptor = storage.assume_init();
    descriptor.height = (record.add(5).read() as i32).wrapping_sub(record.add(3).read() as i32);
    descriptor.width = (record.add(6).read() as i32).wrapping_sub(record.add(4).read() as i32);
    descriptor.top = record.add(3).read() as i32;
    descriptor.left = record.add(4).read() as i32;
    submit(&descriptor, request);
    1
}

/// Build the request from the seven-word target record; +8 is a signed i16.
/// The nonzero handle must be valid for retail 0x081b5414. No NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_region_render_request(record: *const u32, request: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    let resolve: ImageSourceResolve = core::mem::transmute(0x081b_5414usize);
    #[cfg(not(target_os = "none"))]
    let resolve = core::ptr::addr_of!(IMAGE_REGION_SOURCE_RESOLVE).read();
    build_region_request(record, request, resolve, render_request_from_descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn unreachable_resolve(_: u32) -> u32 { panic!("zero handle resolved") }
    unsafe extern "C" fn unreachable_submit(_: *const RenderRequestDescriptor, _: *mut u8) {
        panic!("zero handle submitted")
    }
    unsafe extern "C" fn resolve(handle: u32) -> u32 { handle.wrapping_add(7) }
    // Consume the constructed descriptor into observable geometry and format.
    unsafe extern "C" fn consume(d: *const RenderRequestDescriptor, out: *mut u8) {
        let d = &*d;
        let out = out.cast::<u32>();
        for (i, value) in [d.source, d.top as u32, d.left as u32,
            d.top.wrapping_add(d.height) as u32, d.left.wrapping_add(d.width) as u32,
            d.source_parameter, d.options, d.mode as u32].into_iter().enumerate() {
            out.add(i).write(value);
        }
    }

    #[test]
    fn absent_source_does_not_read_format_or_touch_request() {
        let record = [0xdeadbeef, 0];
        let mut out = [0xa5a5a5a5u32; 8];
        assert_eq!(unsafe { build_region_request(record.as_ptr(), out.as_mut_ptr().cast(),
            unreachable_resolve, unreachable_submit) }, 0);
        assert_eq!(out, [0xa5a5a5a5; 8]);
        assert_eq!(unsafe { image_region_render_request(record.as_ptr(), out.as_mut_ptr().cast()) }, 0);
    }

    #[test]
    fn region_bounds_wrap_and_preserve_descriptor_format() {
        for bounds in [[10, 20, 10, 20], [30, 40, 5, 7],
            [i32::MIN, i32::MAX, i32::MAX, i32::MIN]] {
            let record = [0, 123, 0x3f1, bounds[0] as u32, bounds[1] as u32,
                bounds[2] as u32, bounds[3] as u32];
            let mut out = [0u32; 8];
            assert_eq!(unsafe { build_region_request(record.as_ptr(), out.as_mut_ptr().cast(), resolve, consume) }, 1);
            assert_eq!(&out[..5], &[130, bounds[0] as u32, bounds[1] as u32, bounds[2] as u32, bounds[3] as u32]);
            let mut format = [0u32; 8];
            unsafe { image_format_descriptor(format.as_mut_ptr().cast(), 0x3f1) };
            assert_eq!(&out[5..], &[format[2], format[6], format[7] & 0xffff]);
        }
    }

    #[test]
    fn format_is_signed_low_halfword_and_nonzero_source_is_boolean() {
        for format in [0xffff, 0x1234ffff, 0x123403f1] {
            let record = [0, u32::MAX, format, 1, 2, 3, 4];
            let mut out = [0u32; 8];
            assert_eq!(unsafe { build_region_request(record.as_ptr(), out.as_mut_ptr().cast(), resolve, consume) }, 1);
            assert_eq!(out[0], 6);
            let mut expected = [0u32; 8];
            unsafe { image_format_descriptor(expected.as_mut_ptr().cast(), format as i16 as i32 as u32) };
            assert_eq!(&out[5..], &[expected[2], expected[6], expected[7] & 0xffff]);
        }
    }
}
