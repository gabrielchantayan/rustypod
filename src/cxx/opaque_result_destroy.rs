//! Destructor for an otherwise unidentified 80-byte result object.
//!
//! The paired constructor `FUN_08267958` leaves a `StringObject` at +0 and
//! owns three target-width vector headers at +0x2c, +0x38, and +0x44. The
//! intervening members are not destroyed by this body and remain opaque.
use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::heap::veneers::cxx_array_dealloc;

/// A three-word ARM vector header. Pointers deliberately stay target-width.
#[repr(C)]
pub struct TargetVector {
    pub begin: u32,
    pub end: u32,
    pub capacity: u32,
}

/// An element of the +0x44 vector (28 bytes on ARM).
#[repr(C)]
pub struct OpaqueVector28Element {
    pub opaque: [u32; 3],
    pub first: StringObject,
    pub second: StringObject,
}

/// An element of the +0x38 vector (16 bytes on ARM).
#[repr(C)]
pub struct OpaqueVector16Element {
    pub first: StringObject,
    pub second: StringObject,
}

/// An element of the +0x2c vector (32 bytes on ARM).
#[repr(C)]
pub struct OpaqueVector32Element {
    pub string: StringObject,
    pub nested: TargetVector,
    pub opaque: [u32; 3],
}

/// The identified layout of the object at `FUN_082679f8`'s `this` pointer.
///
/// `repr(C)` gives the raw firmware layout on ARM. Native host pointers widen
/// the embedded StringObjects, so host tests access fields rather than target
/// byte offsets.
#[repr(C)]
pub struct OpaqueResult {
    pub primary: StringObject,
    pub secondary: StringObject,
    pub opaque_word: u32,
    pub third: StringObject,
    pub fourth: StringObject,
    pub fifth: StringObject,
    pub vector32: TargetVector,
    pub vector16: TargetVector,
    pub vector28: TargetVector,
}

#[inline(always)]
fn vector_len(vector: &TargetVector, stride: u32) -> usize {
    vector.capacity.wrapping_sub(vector.begin).wrapping_div(stride) as usize
}

unsafe fn destroy_vector28(vector: &TargetVector) {
    let mut element = vector.begin as usize as *mut OpaqueVector28Element;
    let end = vector.end as usize as *mut OpaqueVector28Element;
    while element != end {
        string_object_destroy(core::ptr::addr_of_mut!((*element).second));
        string_object_destroy(core::ptr::addr_of_mut!((*element).first));
        element = element.add(1);
    }
    cxx_array_dealloc(vector.begin as usize as *mut u8, vector_len(vector, 0x1c), 0);
}

unsafe fn destroy_vector16(vector: &TargetVector) {
    let mut element = vector.begin as usize as *mut OpaqueVector16Element;
    let end = vector.end as usize as *mut OpaqueVector16Element;
    while element != end {
        string_object_destroy(core::ptr::addr_of_mut!((*element).second));
        string_object_destroy(core::ptr::addr_of_mut!((*element).first));
        element = element.add(1);
    }
    cxx_array_dealloc(vector.begin as usize as *mut u8, vector_len(vector, 0x10), 0);
}

unsafe fn destroy_vector32(vector: &TargetVector) {
    let mut element = vector.begin as usize as *mut OpaqueVector32Element;
    let end = vector.end as usize as *mut OpaqueVector32Element;
    while element != end {
        let nested = &(*element).nested;
        cxx_array_dealloc(nested.begin as usize as *mut u8, vector_len(nested, 1), 0);
        string_object_destroy(core::ptr::addr_of_mut!((*element).string));
        element = element.add(1);
    }
    cxx_array_dealloc(vector.begin as usize as *mut u8, vector_len(vector, 0x20), 0);
}

/// `opaque_result_destroy` — original: `FUN_082679f8` @ `0x082679f8`
/// (164 bytes; seven direct `bl` call sites, all unconditional, zero predicated).
///
/// Raw `osos.dec` establishes the extent: `push {r4,r5,r6,lr}` at
/// `0x082679f8` through `b 0x08277484` at `0x08267a98`; the next function
/// starts with `push {r4,r5,lr}` at `0x08267a9c`. Ghidra's 212-byte body
/// incorrectly follows that final tail branch into `string_object_destroy`.
///
/// Destroys the three vectors in reverse field order. Their elements have
/// target strides 28, 16, and 32; each allocation is then released through
/// `cxx_array_dealloc`. Finally tail-destroys the primary StringObject and
/// returns `this`. The other four embedded StringObjects are deliberately not
/// touched: the verified ARM body never addresses them.
///
/// Deliberate deviation: target vector pointers are `u32`, and native host
/// tests use the field layout rather than target byte offsets. On ARM this is
/// the exact three-word vector representation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_result_destroy(this: *mut OpaqueResult) -> *mut OpaqueResult {
    destroy_vector28(&(*this).vector28);
    destroy_vector16(&(*this).vector16);
    destroy_vector32(&(*this).vector32);
    string_object_destroy(core::ptr::addr_of_mut!((*this).primary));
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_lengths_use_target_strides_and_wrap() {
        assert_eq!(vector_len(&TargetVector { begin: 0x1000, end: 0, capacity: 0x1038 }, 0x1c), 2);
        assert_eq!(vector_len(&TargetVector { begin: 0xffff_fff0, end: 0, capacity: 0x10 }, 0x10), 2);
    }

    #[test]
    fn destroy_empty_result_only_reinitializes_primary() {
        let mut result: OpaqueResult = unsafe { core::mem::zeroed() };
        result.secondary.payload = 0x1234usize as *mut u8;
        unsafe { opaque_result_destroy(&mut result) };
        assert!(result.primary.payload.is_null());
        assert_eq!(result.secondary.payload, 0x1234usize as *mut u8);
        assert_eq!(result.vector32.begin, 0);
        assert_eq!(result.vector16.begin, 0);
        assert_eq!(result.vector28.begin, 0);
    }

}
