//! X.509 attribute constructor — FUN_0806f0a4 @ 0x0806f0a4.
//! True extent: 164 bytes through 0x0806f148 (160 code bytes plus descriptor
//! literal). Raw A32 scan: two inbound plain BLs, zero predicated; seven
//! outgoing plain BLs and one BLNE. Allocate an attribute, resolve its NID,
//! clear the single-value flag, create a stack, allocate an ASN.1 value and
//! append it before setting its type/payload. On failure release the attribute
//! first, then any unattached value. A NULL OID does not abort construction.
//!
//! Deviations: existing ports supply allocation, OID, stack and release edges.
//! The unported value setter uses its exact firmware address on device and a
//! host seam. Pointer-sized word slots preserve +0/+4/+8 on ARM. The otherwise
//! dead descriptor-resolver context is zero: descriptor types 1 and 0 do not
//! consult it (image addresses are runtime addresses +0xaed8). No rollback or
//! extra validation is added. Static backend dispatch adds no target allocation.

use super::obj_dat::obj_nid2obj;
use crate::runtime::parameter_descriptor_value::parameter_descriptor_value;
use crate::runtime::global_parameter_descriptor_value::global_parameter_descriptor_value;
use crate::cxx::typed_allocation_release::typed_allocation_release_helper;
use crate::cxx::opaque_allocation_release_089062ec::release_opaque_allocation_089062ec;
use crate::cxx::object_flags::namespace_provider_push;
use crate::drivers::ata_cmd::ata_call_with_zero;

const ATTRIBUTE_DESCRIPTOR: usize = 0x0891_f6ac;
pub type AttributeValueSet = unsafe extern "C" fn(*mut usize, i32, usize);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_value_set(_: *mut usize, _: i32, _: usize) {
    panic!("install ASN.1 value setter 0x0803a55c for host execution")
}
#[cfg(not(target_os = "none"))]
pub static mut ATTRIBUTE_VALUE_SET: AttributeValueSet = missing_value_set;

trait Backend {
    unsafe fn attribute(&mut self) -> *mut usize;
    unsafe fn object(&mut self, nid: i32) -> usize;
    unsafe fn stack(&mut self) -> *mut usize;
    unsafe fn value(&mut self) -> *mut usize;
    unsafe fn push(&mut self, stack: *mut usize, value: *mut usize) -> u32;
    unsafe fn set(&mut self, value: *mut usize, kind: i32, payload: usize);
    unsafe fn release_attribute(&mut self, attribute: *mut usize);
    unsafe fn release_value(&mut self, value: *mut usize);
}
struct Retail;
impl Backend for Retail {
    #[inline(always)]
    unsafe fn attribute(&mut self) -> *mut usize {
        parameter_descriptor_value(ATTRIBUTE_DESCRIPTOR as *const u8, 0, 0, 0) as usize as *mut usize
    }
    #[inline(always)]
    unsafe fn object(&mut self, nid: i32) -> usize { obj_nid2obj(nid) as usize }
    #[inline(always)]
    unsafe fn stack(&mut self) -> *mut usize { ata_call_with_zero().cast() }
    #[inline(always)]
    unsafe fn value(&mut self) -> *mut usize {
        global_parameter_descriptor_value(core::ptr::null(), 0, 0, 0) as usize as *mut usize
    }
    #[inline(always)]
    unsafe fn push(&mut self, stack: *mut usize, value: *mut usize) -> u32 {
        namespace_provider_push(stack, value as usize)
    }
    #[inline(always)]
    unsafe fn set(&mut self, value: *mut usize, kind: i32, payload: usize) {
        #[cfg(target_os = "none")]
        let call: AttributeValueSet = core::mem::transmute(0x0803_a55cusize);
        #[cfg(not(target_os = "none"))]
        let call = core::ptr::addr_of!(ATTRIBUTE_VALUE_SET).read_volatile();
        call(value, kind, payload);
    }
    #[inline(always)]
    unsafe fn release_attribute(&mut self, attribute: *mut usize) {
        typed_allocation_release_helper(attribute.cast(), ATTRIBUTE_DESCRIPTOR as *const u8);
    }
    #[inline(always)]
    unsafe fn release_value(&mut self, value: *mut usize) {
        release_opaque_allocation_089062ec(value.cast());
    }
}

#[inline(always)]
unsafe fn construct(backend: &mut impl Backend, nid: i32, kind: i32, payload: usize) -> *mut usize {
    let attribute = backend.attribute();
    if attribute.is_null() { return core::ptr::null_mut(); }
    attribute.write(backend.object(nid));
    attribute.add(1).write(0);
    let stack = backend.stack();
    attribute.add(2).write(stack as usize);
    let mut value = core::ptr::null_mut();
    if !stack.is_null() {
        value = backend.value();
        if !value.is_null() && backend.push(stack, value) != 0 {
            backend.set(value, kind, payload);
            return attribute;
        }
    }
    backend.release_attribute(attribute);
    if !value.is_null() { backend.release_value(value); }
    core::ptr::null_mut()
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn x509_attribute_create(nid: i32, kind: i32, payload: usize) -> *mut usize {
    construct(&mut Retail, nid, kind, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        attribute: [usize; 3], stack: [usize; 5], value: [usize; 2],
        fail: u8, oid: usize, released: u8, initialized: bool,
    }
    impl Backend for Fixture {
        unsafe fn attribute(&mut self) -> *mut usize {
            if self.fail == 1 { core::ptr::null_mut() } else { self.attribute.as_mut_ptr() }
        }
        unsafe fn object(&mut self, nid: i32) -> usize { assert_eq!(nid, 42); self.oid }
        unsafe fn stack(&mut self) -> *mut usize {
            if self.fail == 2 { core::ptr::null_mut() } else { self.stack.as_mut_ptr() }
        }
        unsafe fn value(&mut self) -> *mut usize {
            if self.fail == 3 { core::ptr::null_mut() } else { self.value.as_mut_ptr() }
        }
        unsafe fn push(&mut self, stack: *mut usize, value: *mut usize) -> u32 {
            assert_eq!(stack, self.stack.as_mut_ptr());
            if self.fail == 4 { return 0; }
            self.stack[0] = 1; self.stack[1] = value as usize; 1
        }
        unsafe fn set(&mut self, value: *mut usize, kind: i32, payload: usize) {
            assert_eq!(self.stack[1], value as usize, "append precedes initialization");
            value.write(kind as usize); value.add(1).write(payload); self.initialized = true;
        }
        unsafe fn release_attribute(&mut self, attribute: *mut usize) {
            assert_eq!(attribute, self.attribute.as_mut_ptr());
            assert_eq!(self.released, 0); self.released = 1;
            // Attribute destruction owns its stack, but not an unappended value.
            self.stack[0] = 0;
        }
        unsafe fn release_value(&mut self, value: *mut usize) {
            assert_eq!(self.released, 1, "attribute destruction must happen first");
            assert_eq!(value, self.value.as_mut_ptr()); self.released = 3;
        }
    }
    #[test]
    fn allocation_and_append_failures_preserve_cleanup_ownership() {
        for fail in 1..=4 {
            let mut f = Fixture { attribute: [99; 3], stack: [0; 5], value: [77; 2],
                fail, oid: 123, released: 0, initialized: false };
            assert!(unsafe { construct(&mut f, 42, 4, 456) }.is_null());
            assert_eq!(f.released, match fail { 1 => 0, 4 => 3, _ => 1 });
            assert!(!f.initialized);
            assert_eq!(f.value, [77; 2]);
            if fail != 1 { assert_eq!(&f.attribute[..2], &[123, 0]); }
        }
    }
    #[test]
    fn success_keeps_stack_and_value_even_when_oid_resolution_returns_null() {
        for oid in [0, 123] {
            let mut f = Fixture { attribute: [99; 3], stack: [0; 5], value: [77; 2],
                fail: 0, oid, released: 0, initialized: false };
            let result = unsafe { construct(&mut f, 42, -4, 0) };
            assert_eq!(result, f.attribute.as_mut_ptr());
            assert_eq!(f.attribute, [oid, 0, f.stack.as_mut_ptr() as usize]);
            assert_eq!(f.stack[0], 1);
            assert_eq!(f.stack[1], f.value.as_mut_ptr() as usize);
            assert_eq!(f.value, [(-4i32) as usize, 0]);
            assert!(f.initialized); assert_eq!(f.released, 0);
        }
    }
}
