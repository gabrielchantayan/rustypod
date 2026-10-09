//! Kinded interface base initializer — retailOS 0x080dae7c.
//! True extent: 108 bytes, [0x080dae7c, 0x080daee8): 100 code bytes
//! and literals 0xefc and 0x08a12084. Two plain inbound BLs (0x080585b8,
//! 0x080586e0), zero predicated inbound BLs; one plain outgoing BL to
//! bzero at 0x0805cfb4, zero predicated outgoing BLs.
//!
//! NULL returns -109. Otherwise clear the 0xefc-byte base, store the low
//! kind byte, clear flags +0xef8..+0xefa, find the first empty registry
//! slot among indices 0..3, store that index at +1, and publish the object.
//! A full registry deliberately writes slot 4 without checking it.
//! Callers construct kind-1 and kind-2 interfaces; subtype data begins +0xefc.
//! Deviations: reuse the registered Rust bzero; hosts use an isolated registry
//! with native-width pointer cells, while target cells remain four bytes.

use core::ptr;
use crate::libc::bzero::bzero;

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTRY: [*mut u8; 5] = [ptr::null_mut(); 5];

#[inline(always)]
unsafe fn registry() -> *mut *mut u8 {
    #[cfg(target_os = "none")]
    { 0x08a1_2084 as *mut *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_REGISTRY).cast() }
}

/// Initialize and publish an interface base.
///
/// # Safety
/// A non-NULL object must provide 0xefc writable bytes. Registry access must
/// be externally serialized, and slot 4 must be writable even when full.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn kinded_interface_initialize(object: *mut u8, kind: u32) -> i32 {
    if object.is_null() {
        return -109;
    }
    bzero(object, 0xefc);
    object.write(kind as u8);
    object.add(0xef8).write(0);
    object.add(0xef9).write(0);
    object.add(0xefa).write(0);
    let slots = registry();
    let mut index = 0;
    while index < 4 && !slots.add(index).read_volatile().is_null() {
        index += 1;
    }
    object.add(1).write(index as u8);
    slots.add(index).write_volatile(object);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn null_preserves_registry() {
        let _guard = LOCK.lock();
        unsafe {
            let before = [ptr::dangling_mut::<u8>(); 5];
            ptr::addr_of_mut!(HOST_REGISTRY).write(before);
            assert_eq!(kinded_interface_initialize(ptr::null_mut(), u32::MAX), -109);
            assert_eq!(ptr::addr_of!(HOST_REGISTRY).read(), before);
            ptr::addr_of_mut!(HOST_REGISTRY).write([ptr::null_mut(); 5]);
        }
    }

    #[test]
    fn first_hole_full_registry_and_exact_clear_extent() {
        let _guard = LOCK.lock();
        for occupied in 0..=4 {
            for kind in [0, 1, 2, 0xff, 0x100, u32::MAX] {
                for alignment in 0..4 {
                    let mut bytes = [0xa5u8; 0xf04];
                    let mut before = [ptr::null_mut(); 5];
                    for slot in &mut before[..occupied] {
                        *slot = ptr::dangling_mut::<u8>();
                    }
                    // The unchecked fifth cell must be overwritten when full.
                    before[4] = ptr::dangling_mut::<u8>();
                    unsafe {
                        ptr::addr_of_mut!(HOST_REGISTRY).write(before);
                        let object = bytes.as_mut_ptr().add(alignment);
                        assert_eq!(kinded_interface_initialize(object, kind), 0);
                        let after = ptr::addr_of!(HOST_REGISTRY).read();
                        for index in 0..5 {
                            assert_eq!(after[index], if index == occupied { object } else { before[index] });
                        }
                    }
                    for (offset, byte) in bytes.iter().enumerate() {
                        let expected = if offset == alignment { kind as u8 }
                            else if offset == alignment + 1 { occupied as u8 }
                            else if offset >= alignment && offset < alignment + 0xefc { 0 }
                            else { 0xa5 };
                        assert_eq!(*byte, expected, "offset {offset}, occupied {occupied}, kind {kind}");
                    }
                }
            }
        }
        unsafe { ptr::addr_of_mut!(HOST_REGISTRY).write([ptr::null_mut(); 5]); }
    }
}
