//! Descriptor-backed object factory, retailOS `0x0826b318`.
//!
//! Raw A32 extent: 76 bytes, ending before the next function at `0x0826b364`.
//! Two plain BL sites (both operator_new), zero predicated BL sites, and two
//! constructor tail branches. Kind 6 allocates 0xa4 bytes and passes the eager
//! flag to the constructor at 0x082903c4. Other kinds allocate 0x6c bytes and
//! pass the context word to the constructor at 0x0811dd2c. Constructor results
//! are returned unchanged, and allocation failure is not intercepted.
//!
//! Deliberate deviations: Rust expresses tail branches as calls; the existing
//! operator_new port is called directly. Unported constructors remain resident
//! firmware calls with host-only seams; no constructor behavior is guessed.

#[cfg(target_os = "none")]
use crate::heap::veneers::operator_new;

pub type DescriptorObjectConstruct = unsafe extern "C" fn(*mut u8, *const u16, u32) -> *mut u8;
pub type DescriptorObjectAllocate = unsafe extern "C" fn(usize) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_allocate(size: usize) -> *mut u8 {
    crate::heap::veneers::operator_new(size)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_construct(_: *mut u8, _: *const u16, _: u32) -> *mut u8 {
    panic!("resident descriptor constructor requires a host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut DESCRIPTOR_OBJECT_ALLOCATE: DescriptorObjectAllocate = host_allocate;
#[cfg(not(target_os = "none"))]
pub static mut KIND_SIX_DESCRIPTOR_CONSTRUCT: DescriptorObjectConstruct = unavailable_construct;
#[cfg(not(target_os = "none"))]
pub static mut BORROWED_DESCRIPTOR_CONSTRUCT: DescriptorObjectConstruct = unavailable_construct;

// Only the exact unsigned halfword 6 selects the larger object. The two third
// arguments belong to different constructors and must not be booleanized.
#[inline(always)]
fn descriptor_layout(kind: u16, context: u32, eager: u32) -> (usize, u32) {
    if kind == 6 { (0xa4, eager) } else { (0x6c, context) }
}

/// Allocates and constructs an object selected by the descriptor's kind.
///
/// # Safety
/// `descriptor` must be halfword-aligned and valid for the selected resident
/// constructor. `context` must satisfy the non-kind-6 constructor's contract.
/// Host callers must install valid constructor seams before calling.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn descriptor_object_create(descriptor: *const u16, context: u32, eager: u32) -> *mut u8 {
    let kind = unsafe { descriptor.read() };
    let (size, argument) = descriptor_layout(kind, context, eager);
    #[cfg(target_os = "none")]
    let object = unsafe { operator_new(size) };
    #[cfg(not(target_os = "none"))]
    let object = unsafe { DESCRIPTOR_OBJECT_ALLOCATE(size) };
    #[cfg(target_os = "none")]
    let construct: DescriptorObjectConstruct = unsafe {
        core::mem::transmute(if kind == 6 { 0x0829_03c4usize } else { 0x0811_dd2cusize })
    };
    #[cfg(not(target_os = "none"))]
    let construct = unsafe {
        if kind == 6 { KIND_SIX_DESCRIPTOR_CONSTRUCT } else { BORROWED_DESCRIPTOR_CONSTRUCT }
    };
    unsafe { construct(object, descriptor, argument) }
}

#[cfg(test)]
mod tests {
    use super::descriptor_layout;

    #[test]
    fn only_exact_kind_six_uses_extended_layout() {
        for kind in 0..=u16::MAX {
            let expected = if kind == 6 { (164, 0xfedc_ba98) } else { (108, 0x8765_4321) };
            assert_eq!(descriptor_layout(kind, 0x8765_4321, 0xfedc_ba98), expected);
        }
    }

    #[test]
    fn constructor_argument_is_not_a_boolean() {
        for argument in [0, 1, 2, 0x8000_0000, u32::MAX] {
            assert_eq!(descriptor_layout(6, !argument, argument), (164, argument));
            assert_eq!(descriptor_layout(7, argument, !argument), (108, argument));
        }
    }
}
