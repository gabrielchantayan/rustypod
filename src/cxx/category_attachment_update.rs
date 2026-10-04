//! Lazy category attachment update — `FUN_081fa6c4` at `0x081fa6c4`.
//!
//! True extent: 112 bytes, ending before the independent push at 0x081fa734.
//! Raw whole-image A32 scan: two incoming plain BLs, zero predicated BLs;
//! four outgoing plain BLs, zero predicated BLs, two predicated tail branches.
//! Lazily allocate and construct a 32-byte attachment. Reload the owner slot
//! after construction: dispose a different non-null attachment before storing
//! the constructor result. Zero values set a category bit; nonzero values append
//! a category/value pair via 0x080fe7e8 (r1=value, r2=category).
//! Deliberate deviations: semantic class identity remains unknown. Unported
//! constructor and pair insertion retain verified address-specific target seams;
//! host callers must install those boundaries. The flag operation is inlined,
//! with ARM register-shift semantics (low eight shift bits, >=32 yields zero).

use core::ptr;
use crate::heap::veneers::{operator_new, operator_delete};
use super::vtable_08980110_construct::vtable_08980110_construct;

#[repr(C)]
pub struct CategoryAttachmentOwner {
    pub prefix: [u32; 10],
    pub attachment: *mut u8,
}

type Construct = unsafe extern "C" fn(*mut u8) -> *mut u8;
type Append = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct(_: *mut u8) -> *mut u8 {
    panic!("install CATEGORY_ATTACHMENT_CONSTRUCT before host use")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_append(_: *mut u8, _: u32, _: u32) {
    panic!("install CATEGORY_ATTACHMENT_APPEND before host use")
}
#[cfg(not(target_os = "none"))]
pub static mut CATEGORY_ATTACHMENT_CONSTRUCT: Construct = missing_construct;
#[cfg(not(target_os = "none"))]
pub static mut CATEGORY_ATTACHMENT_APPEND: Append = missing_append;

#[inline(always)]
unsafe fn ensure_attachment(
    owner: *mut CategoryAttachmentOwner,
    allocate: impl FnOnce() -> *mut u8,
    construct: impl FnOnce(*mut u8) -> *mut u8,
    dispose: impl FnOnce(*mut u8),
) -> *mut u8 {
    let slot = unsafe { ptr::addr_of_mut!((*owner).attachment) };
    if unsafe { slot.read_volatile() }.is_null() {
        let replacement = construct(allocate());
        let current = unsafe { slot.read_volatile() };
        if current != replacement {
            if !current.is_null() {
                dispose(current);
            }
            unsafe { slot.write_volatile(replacement) };
        }
    }
    unsafe { slot.read_volatile() }
}

#[inline(always)]
unsafe fn set_category(attachment: *mut u8, category: u32) {
    let shift = category & 255;
    let mask = if shift < 32 { 1u32 << shift } else { 0 };
    let flags = unsafe { attachment.add(4) };
    unsafe { flags.write_volatile(flags.read_volatile() | mask as u8) };
}

/// # Safety
/// Owner must be writable, with its attachment pointer at target offset 0x28.
/// Existing attachments and constructor results must satisfy the stock callees;
/// allocation failure is not checked by the original. Host seams must be installed
/// before paths using the unported constructor or pair insertion are exercised.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn category_attachment_update(
    owner: *mut CategoryAttachmentOwner, category: u32, value: u32,
) {
    #[cfg(target_os = "none")]
    let construct: Construct = unsafe { core::mem::transmute(0x080f_e824usize) };
    #[cfg(not(target_os = "none"))]
    let construct = unsafe { ptr::read_volatile(ptr::addr_of!(CATEGORY_ATTACHMENT_CONSTRUCT)) };
    let attachment = unsafe { ensure_attachment(owner,
        || operator_new(32).cast(),
        |storage| construct(storage),
        |old| { operator_delete(vtable_08980110_construct(old).cast()); },
    ) };
    if value == 0 {
        unsafe { set_category(attachment, category) };
    } else {
        #[cfg(target_os = "none")]
        let append: Append = unsafe { core::mem::transmute(0x080f_e7e8usize) };
        #[cfg(not(target_os = "none"))]
        let append = unsafe { ptr::read_volatile(ptr::addr_of!(CATEGORY_ATTACHMENT_APPEND)) };
        unsafe { append(attachment, value, category) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_bits_match_arm_register_shift_boundaries() {
        let mut storage = [0xa5u8; 32];
        let mut owner = CategoryAttachmentOwner { prefix: [0xdeadbeef; 10], attachment: storage.as_mut_ptr() };
        for category in [0, 1, 7, 8, 31, 32, 255, 256, 263, 264, u32::MAX] {
            storage[4] = 0x42;
            unsafe { category_attachment_update(&mut owner, category, 0) };
            let shift = category & 255;
            let expected = if shift < 8 { 0x42 | (1u8 << shift) } else { 0x42 };
            assert_eq!(storage[4], expected, "category {category}");
            assert_eq!(&storage[..4], &[0xa5; 4]);
            assert_eq!(&storage[5..], &[0xa5; 27]);
            assert_eq!(owner.prefix, [0xdeadbeef; 10]);
        }
    }

    #[test]
    fn constructor_reentrancy_replaces_only_a_distinct_current_attachment() {
        let mut allocated = [0u8; 32];
        let mut old = [0u8; 32];
        let replacement = allocated.as_mut_ptr();
        let previous = old.as_mut_ptr();
        for current in [ptr::null_mut(), replacement, previous] {
            let mut owner = CategoryAttachmentOwner { prefix: [0; 10], attachment: ptr::null_mut() };
            let owner_ptr = &mut owner as *mut CategoryAttachmentOwner;
            let mut disposed = ptr::null_mut();
            let result = unsafe { ensure_attachment(owner_ptr, || replacement,
                |storage| { assert_eq!(storage, replacement); (*owner_ptr).attachment = current; replacement },
                |attachment| { assert_eq!((*owner_ptr).attachment, previous); disposed = attachment; },
            ) };
            assert_eq!(result, replacement);
            assert_eq!(owner.attachment, replacement);
            assert_eq!(disposed, if current == previous { previous } else { ptr::null_mut() });
        }
        let mut owner = CategoryAttachmentOwner { prefix: [0; 10], attachment: replacement };
        let result = unsafe { ensure_attachment(&mut owner,
            || panic!("existing attachment must not allocate"),
            |_| panic!("existing attachment must not construct"),
            |_| panic!("existing attachment must not dispose"),
        ) };
        assert_eq!(result, replacement);
    }
}
